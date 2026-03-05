//! Leader election via k8s `coordination.k8s.io/v1` Lease.
//!
//! Uses the same mechanism as `client-go` leader election:
//! create-or-acquire a Lease, renew periodically, release on shutdown.

use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, ObjectMeta, PostParams};
use kube::Client;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{LeaderElector, LeaderWorkFn};

// ────────────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────────────

/// Configuration for k8s Lease-based leader election.
#[derive(Debug, Clone)]
pub struct K8sLeaseConfig {
    /// Kubernetes namespace where the Lease object lives.
    pub namespace: String,
    /// Unique identity of this pod (typically `POD_NAME` from downward API).
    pub identity: String,
    /// Prefix for Lease object names: `"{lease_prefix}-{role}"`.
    pub lease_prefix: String,
    /// How long before a Lease is considered expired.
    pub lease_duration: Duration,
    /// How often the holder renews the Lease.
    pub renew_period: Duration,
}

impl K8sLeaseConfig {
    /// Build config from environment variables with sensible defaults.
    ///
    /// - `POD_NAMESPACE` -> namespace (default: `"default"`)
    /// - `POD_NAME` -> identity (default: `"local"`)
    #[must_use]
    pub fn from_env(lease_prefix: impl Into<String>) -> Self {
        Self {
            namespace: std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "default".into()),
            identity: std::env::var("POD_NAME").unwrap_or_else(|_| "local".into()),
            lease_prefix: lease_prefix.into(),
            lease_duration: Duration::from_secs(15),
            renew_period: Duration::from_secs(2),
        }
    }

    /// Override timing parameters.
    #[must_use]
    pub fn with_timing(mut self, lease_duration: Duration, renew_period: Duration) -> Self {
        self.lease_duration = lease_duration;
        self.renew_period = renew_period;
        self
    }

    /// Validate config for safe operation.
    ///
    /// # Errors
    /// Returns an error when required invariants are violated.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.namespace.trim().is_empty() {
            return Err(anyhow!("k8s leader: namespace must be non-empty"));
        }
        if self.identity.trim().is_empty() {
            return Err(anyhow!("k8s leader: identity must be non-empty"));
        }
        if self.lease_prefix.trim().is_empty() {
            return Err(anyhow!("k8s leader: lease_prefix must be non-empty"));
        }
        if self.renew_period.is_zero() {
            return Err(anyhow!("k8s leader: renew_period must be > 0"));
        }
        if self.lease_duration <= self.renew_period {
            return Err(anyhow!(
                "k8s leader: lease_duration ({:?}) must be > renew_period ({:?})",
                self.lease_duration,
                self.renew_period
            ));
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Elector
// ────────────────────────────────────────────────────────────────────────────

/// Leader elector backed by a k8s `coordination.k8s.io/v1` Lease.
pub struct K8sLeaseElector {
    client: Client,
    config: K8sLeaseConfig,
}

impl K8sLeaseElector {
    /// Create an elector with an existing kube [`Client`].
    #[must_use]
    pub fn with_client(client: Client, config: K8sLeaseConfig) -> Self {
        Self { client, config }
    }

    /// Create an elector using the default in-cluster / kubeconfig client.
    ///
    /// # Errors
    ///
    /// Fails if kube client cannot be initialised (no kubeconfig, no
    /// in-cluster service account).
    pub async fn from_default(config: K8sLeaseConfig) -> anyhow::Result<Self> {
        let client = Client::try_default().await.context("kube client init")?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl LeaderElector for K8sLeaseElector {
    async fn run_role(
        &self,
        role: &str,
        cancel: CancellationToken,
        work: LeaderWorkFn,
    ) -> anyhow::Result<()> {
        let lease_name = format!("{}-{role}", self.config.lease_prefix);
        let api: Api<Lease> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let mut backoff = Backoff::new();

        loop {
            let acquired = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = self.try_acquire(&api, &lease_name) => result,
            };

            match acquired {
                Ok(true) => {
                    backoff.reset();
                    info!(role, identity = %self.config.identity, %lease_name, "acquired leadership");
                    if let Err(e) = self.run_while_leader(role, &api, &lease_name, cancel.clone(), &work).await {
                        warn!(role, error = %e, "leader loop ended (leadership lost or error)");
                    }
                }
                Ok(false) => {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Ok(()),
                        () = sleep(self.config.renew_period) => {}
                    }
                }
                Err(e) => {
                    let delay = backoff.next_delay();
                    #[allow(clippy::cast_possible_truncation)]
                    let delay_ms = delay.as_millis() as u64;
                    warn!(role, error = %e, delay_ms, "leader acquire failed");
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Ok(()),
                        () = sleep(delay) => {}
                    }
                }
            }
        }
    }
}

impl K8sLeaseElector {
    async fn try_acquire(
        &self,
        api: &Api<Lease>,
        lease_name: &str,
    ) -> anyhow::Result<bool> {
        ensure_lease_exists(api, lease_name).await?;

        let lease = api.get(lease_name).await.with_context(|| format!("get Lease {lease_name}"))?;

        let now = Timestamp::now();
        let (holder, renew_time, duration_s) = read_lease_state(&lease);

        #[allow(clippy::cast_possible_truncation)]
        let lease_duration_s = duration_s.unwrap_or(self.config.lease_duration.as_secs() as i32);
        let lease_span = SignedDuration::from_secs(i64::from(lease_duration_s));

        let expired = renew_time.is_none_or(|rt| {
            rt.checked_add(lease_span)
                .map_or(true, |expiry| expiry < now)
        });
        let i_am_holder = holder.as_deref() == Some(self.config.identity.as_str());

        if !(expired || i_am_holder || holder.is_none()) {
            return Ok(false);
        }

        // Acquire leadership using resourceVersion-guarded replace to avoid split-brain.
        let mut new_lease = lease.clone();
        new_lease.spec.get_or_insert_default().holder_identity = Some(self.config.identity.clone());
        new_lease.spec.get_or_insert_default().lease_duration_seconds = Some(lease_duration_s);
        new_lease.spec.get_or_insert_default().renew_time =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(now));

        match api
            .replace(lease_name, &PostParams::default(), &new_lease)
            .await
        {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(resp)) if resp.code == 409 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn run_while_leader(
        &self,
        role: &str,
        api: &Api<Lease>,
        lease_name: &str,
        cancel: CancellationToken,
        work: &LeaderWorkFn,
    ) -> anyhow::Result<()> {
        let mut active: Option<ActiveRole> = None;

        loop {
            // Ensure work is running while we hold leadership.
            if active.as_ref().is_none_or(|a| a.handle.is_finished()) {
                if let Some(r) = active.take() {
                    r.await_and_log(role).await;
                }
                let child = CancellationToken::new();
                let handle = tokio::spawn(work(child.clone()));
                active = Some(ActiveRole { child, handle });
            }

            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    stop_and_release(&mut active, role, api, lease_name, &self.config.identity).await;
                    return Ok(());
                }
                () = sleep(self.config.renew_period) => {
                    if let Err(e) = self.renew_once(api, lease_name).await {
                        if let Some(r) = active.take() {
                            r.stop(role).await;
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    async fn renew_once(&self, api: &Api<Lease>, lease_name: &str) -> anyhow::Result<()> {
        let lease = api.get(lease_name).await.with_context(|| format!("get Lease {lease_name}"))?;
        let (holder, renew_time, duration_s) = read_lease_state(&lease);

        if holder.as_deref() != Some(self.config.identity.as_str()) {
            return Err(anyhow!("lease holder changed to {holder:?}"));
        }

        let now = Timestamp::now();
        #[allow(clippy::cast_possible_truncation)]
        let lease_duration_s = duration_s.unwrap_or(self.config.lease_duration.as_secs() as i32);
        let lease_span = SignedDuration::from_secs(i64::from(lease_duration_s));

        if let Some(rt) = renew_time {
            let is_expired = rt
                .checked_add(lease_span)
                .map_or(true, |expiry| expiry < now);
            if is_expired {
                return Err(anyhow!("lease expired before renew"));
            }
        }

        let mut new_lease = lease.clone();
        new_lease.spec.get_or_insert_default().renew_time =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(now));

        match api
            .replace(lease_name, &PostParams::default(), &new_lease)
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(resp)) if resp.code == 409 => Err(anyhow!("renew conflict")),
            Err(e) => Err(e.into()),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

struct ActiveRole {
    child: CancellationToken,
    handle: JoinHandle<anyhow::Result<()>>,
}

impl ActiveRole {
    async fn stop(self, role: &str) {
        self.child.cancel();
        match self.handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(role, error = %e, "leader work exited with error"),
            Err(e) => warn!(role, error = %e, "leader work task panicked"),
        }
    }

    #[allow(clippy::cognitive_complexity)]
    async fn await_and_log(self, role: &str) {
        match self.handle.await {
            Ok(Ok(())) => warn!(role, "leader work exited unexpectedly (Ok)"),
            Ok(Err(e)) => warn!(role, error = %e, "leader work exited unexpectedly (Err)"),
            Err(e) => warn!(role, error = %e, "leader work panicked"),
        }
    }
}

async fn stop_and_release(
    active: &mut Option<ActiveRole>,
    role: &str,
    api: &Api<Lease>,
    lease_name: &str,
    identity: &str,
) {
    if let Some(r) = active.take() {
        r.stop(role).await;
    }
    if let Err(e) = release_lease(api, lease_name, identity).await {
        warn!(role, error = %e, "best-effort lease release failed");
    }
}

/// Best-effort release: clear `holderIdentity` to speed up re-election.
async fn release_lease(api: &Api<Lease>, lease_name: &str, identity: &str) -> anyhow::Result<()> {
    let lease = api.get(lease_name).await.context("get lease for release")?;
    let (holder, _, _) = read_lease_state(&lease);

    if holder.as_deref() != Some(identity) {
        return Ok(());
    }

    let mut new_lease = lease.clone();
    new_lease.spec.get_or_insert_default().holder_identity = None;

    // resourceVersion-guarded replace; conflict means someone else already updated.
    match api.replace(lease_name, &PostParams::default(), &new_lease).await {
        Ok(_) => {}
        Err(kube::Error::Api(resp)) if resp.code == 409 => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

async fn ensure_lease_exists(api: &Api<Lease>, lease_name: &str) -> anyhow::Result<()> {
    match api.get(lease_name).await {
        Ok(_) => return Ok(()),
        Err(kube::Error::Api(resp)) if resp.code == 404 => {}
        Err(e) => return Err(e.into()),
    }

    let lease = Lease {
        metadata: ObjectMeta {
            name: Some(lease_name.to_owned()),
            ..ObjectMeta::default()
        },
        ..Lease::default()
    };
    match api.create(&PostParams::default(), &lease).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(resp)) if resp.code == 409 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn read_lease_state(lease: &Lease) -> (Option<String>, Option<Timestamp>, Option<i32>) {
    let spec = lease.spec.as_ref();
    let holder = spec.and_then(|s| s.holder_identity.clone());
    let duration = spec.and_then(|s| s.lease_duration_seconds);
    let renew_time = spec.and_then(|s| s.renew_time.as_ref()).map(|t| t.0);
    (holder, renew_time, duration)
}

struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            next: Duration::from_millis(200),
        }
    }

    fn reset(&mut self) {
        self.next = Duration::from_millis(200);
    }

    fn next_delay(&mut self) -> Duration {
        let out = self.next;
        self.next = std::cmp::min(self.next * 2, Duration::from_secs(5));
        out
    }
}
