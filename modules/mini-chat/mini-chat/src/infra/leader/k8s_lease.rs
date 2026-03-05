//! Leader election via k8s `coordination.k8s.io/v1` Lease.
//!
//! Uses the same mechanism as `client-go` leader election:
//! create-or-acquire a Lease, renew periodically, release on shutdown.

use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::Client;
use serde::Serialize;
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
        let mut active: Option<ActiveRole> = None;

        loop {
            let acquired = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    stop_and_release(&mut active, role, &api, &lease_name).await;
                    return Ok(());
                }
                result = self.try_acquire_or_renew(&api, &lease_name) => result?,
            };

            if acquired {
                if active.is_none() {
                    let child = CancellationToken::new();
                    let handle = tokio::spawn(work(child.clone()));
                    active = Some(ActiveRole { child, handle });
                    info!(role, identity = %self.config.identity, "acquired leadership");
                }

                let renew_result = tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        stop_and_release(&mut active, role, &api, &lease_name).await;
                        return Ok(());
                    }
                    result = self.renew_loop(&api, &lease_name) => result,
                };

                if let Some(r) = active.take() {
                    r.stop(role).await;
                }

                if let Err(e) = renew_result {
                    warn!(role, error = %e, "lost leadership");
                }
            } else {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Ok(()),
                    () = sleep(self.config.renew_period) => {}
                }
            }
        }
    }
}

impl K8sLeaseElector {
    async fn try_acquire_or_renew(
        &self,
        api: &Api<Lease>,
        lease_name: &str,
    ) -> anyhow::Result<bool> {
        ensure_lease_exists(api, lease_name).await?;

        let lease = api
            .get(lease_name)
            .await
            .with_context(|| format!("get Lease {lease_name}"))?;

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

        if expired || i_am_holder || holder.is_none() {
            patch_lease(api, lease_name, &self.config.identity, lease_duration_s, now).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn renew_loop(&self, api: &Api<Lease>, lease_name: &str) -> anyhow::Result<()> {
        loop {
            sleep(self.config.renew_period).await;

            let lease = api.get(lease_name).await?;
            let (holder, renew_time, duration_s) = read_lease_state(&lease);

            if holder.as_deref() != Some(self.config.identity.as_str()) {
                return Err(anyhow!("lease holder changed to {holder:?}"));
            }

            let now = Timestamp::now();
            #[allow(clippy::cast_possible_truncation)]
            let lease_duration_s =
                duration_s.unwrap_or(self.config.lease_duration.as_secs() as i32);
            let lease_span = SignedDuration::from_secs(i64::from(lease_duration_s));

            if let Some(rt) = renew_time {
                let is_expired = rt
                    .checked_add(lease_span)
                    .map_or(true, |expiry| expiry < now);
                if is_expired {
                    return Err(anyhow!("lease expired before renew"));
                }
            }

            patch_lease(api, lease_name, &self.config.identity, lease_duration_s, now).await?;
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
}

async fn stop_and_release(
    active: &mut Option<ActiveRole>,
    role: &str,
    api: &Api<Lease>,
    lease_name: &str,
) {
    if let Some(r) = active.take() {
        r.stop(role).await;
    }
    if let Err(e) = release_lease(api, lease_name).await {
        warn!(role, error = %e, "best-effort lease release failed");
    }
}

/// Best-effort release: clear `holderIdentity` to speed up re-election.
async fn release_lease(api: &Api<Lease>, lease_name: &str) -> anyhow::Result<()> {
    #[derive(Debug, Serialize)]
    struct Spec {
        #[serde(rename = "holderIdentity")]
        holder_identity: Option<String>,
    }
    #[derive(Debug, Serialize)]
    struct LeasePatch {
        spec: Spec,
    }

    let pp = PatchParams::default();
    let patch = LeasePatch {
        spec: Spec {
            holder_identity: None,
        },
    };
    api.patch(lease_name, &pp, &Patch::Merge(&patch))
        .await
        .context("release lease")?;
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

async fn patch_lease(
    api: &Api<Lease>,
    lease_name: &str,
    identity: &str,
    lease_duration_s: i32,
    now: Timestamp,
) -> anyhow::Result<()> {
    #[derive(Debug, Serialize)]
    struct Spec<'a> {
        #[serde(rename = "holderIdentity")]
        holder_identity: &'a str,
        #[serde(rename = "leaseDurationSeconds")]
        lease_duration_seconds: i32,
        #[serde(rename = "renewTime")]
        renew_time: String,
    }
    #[derive(Debug, Serialize)]
    struct LeasePatch<'a> {
        spec: Spec<'a>,
    }

    let pp = PatchParams::default();
    let patch = LeasePatch {
        spec: Spec {
            holder_identity: identity,
            lease_duration_seconds: lease_duration_s,
            renew_time: now.to_string(),
        },
    };

    api.patch(lease_name, &pp, &Patch::Merge(&patch))
        .await
        .context("patch lease")?;
    Ok(())
}
