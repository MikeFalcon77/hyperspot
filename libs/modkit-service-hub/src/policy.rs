//! Per-call policy stack for cross-cutting concerns.
//!
//! Policies run hooks before and after the transport call. The
//! [`PolicyStack`] composes an ordered list of [`Policy`] implementations
//! and drives execution through them.

use async_trait::async_trait;
use std::future::Future;
use std::sync::Arc;

use crate::error::ServiceHubError;
use crate::ir::contract::{Idempotency, MethodKind};

/// Context passed to policy hooks for each service call.
pub struct PolicyContext {
    /// Service name being invoked.
    pub service: &'static str,
    /// Method name being invoked.
    pub method: &'static str,
    /// Idempotency classification (used for retry decisions).
    pub idempotency: Idempotency,
    /// Whether the method is unary or streaming.
    pub kind: MethodKind,
}

/// A policy that can intercept service calls before and after transport.
///
/// Implement this trait to add cross-cutting concerns such as tracing,
/// metrics, or authorization checks.
#[async_trait]
pub trait Policy: Send + Sync {
    /// Called before the transport call is made.
    ///
    /// # Errors
    ///
    /// Return an error to short-circuit the call (subsequent policies
    /// and the transport call will be skipped).
    async fn on_request(&self, ctx: &PolicyContext) -> Result<(), ServiceHubError>;

    /// Called after the transport call completes.
    ///
    /// # Errors
    ///
    /// Returning an error replaces the original transport result.
    async fn on_response(
        &self,
        ctx: &PolicyContext,
        success: bool,
    ) -> Result<(), ServiceHubError>;
}

/// Ordered list of policies applied to every service call.
///
/// Policies run `on_request` in insertion order and `on_response` in
/// reverse order (like middleware stacks).
pub struct PolicyStack {
    policies: Vec<Arc<dyn Policy>>,
}

impl PolicyStack {
    /// Create an empty policy stack.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Append a policy to the end of the stack.
    pub fn push(&mut self, policy: Arc<dyn Policy>) {
        self.policies.push(policy);
    }

    /// Execute a service call through the policy stack.
    ///
    /// 1. Runs `on_request` for each policy in order.
    /// 2. Invokes the transport closure `f`.
    /// 3. Runs `on_response` for each policy in reverse order.
    ///
    /// # Errors
    ///
    /// Returns the first error from any policy hook, or the transport
    /// error if the call itself fails.
    pub async fn execute<F, Fut, T>(
        &self,
        ctx: &PolicyContext,
        f: F,
    ) -> Result<T, ServiceHubError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ServiceHubError>>,
    {
        // Run on_request hooks in order.
        for policy in &self.policies {
            policy.on_request(ctx).await?;
        }

        // Execute the transport call.
        let result = f().await;
        let success = result.is_ok();

        // Run on_response hooks in reverse order.
        for policy in self.policies.iter().rev() {
            policy.on_response(ctx, success).await?;
        }

        result
    }
}

impl Default for PolicyStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy that emits `tracing` spans and log events for each service call.
pub struct TracingPolicy;

#[async_trait]
impl Policy for TracingPolicy {
    async fn on_request(&self, ctx: &PolicyContext) -> Result<(), ServiceHubError> {
        tracing::info!(
            service = ctx.service,
            method = ctx.method,
            idempotency = ?ctx.idempotency,
            kind = ?ctx.kind,
            "service call started"
        );
        Ok(())
    }

    async fn on_response(
        &self,
        ctx: &PolicyContext,
        success: bool,
    ) -> Result<(), ServiceHubError> {
        if success {
            tracing::info!(
                service = ctx.service,
                method = ctx.method,
                "service call succeeded"
            );
        } else {
            tracing::warn!(
                service = ctx.service,
                method = ctx.method,
                "service call failed"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test policy that records the order of `on_request` / `on_response` calls.
    struct OrderRecorder {
        id: usize,
        log: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Policy for OrderRecorder {
        async fn on_request(&self, _ctx: &PolicyContext) -> Result<(), ServiceHubError> {
            self.log
                .lock()
                .push(format!("on_request:{}", self.id));
            Ok(())
        }

        async fn on_response(
            &self,
            _ctx: &PolicyContext,
            success: bool,
        ) -> Result<(), ServiceHubError> {
            self.log
                .lock()
                .push(format!("on_response:{}:{success}", self.id));
            Ok(())
        }
    }

    fn test_ctx() -> PolicyContext {
        PolicyContext {
            service: "TestService",
            method: "test_method",
            idempotency: Idempotency::SafeRead,
            kind: MethodKind::Unary,
        }
    }

    #[tokio::test]
    async fn policy_stack_calls_in_order() {
        let log: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));

        let mut stack = PolicyStack::new();
        stack.push(Arc::new(OrderRecorder {
            id: 1,
            log: Arc::clone(&log),
        }));
        stack.push(Arc::new(OrderRecorder {
            id: 2,
            log: Arc::clone(&log),
        }));

        let ctx = test_ctx();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_inner = Arc::clone(&call_count);

        let result: Result<&str, ServiceHubError> = stack
            .execute(&ctx, || async move {
                call_count_inner.fetch_add(1, Ordering::Relaxed);
                Ok("done")
            })
            .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        let entries = log.lock().clone();
        assert_eq!(entries, vec![
            "on_request:1",
            "on_request:2",
            "on_response:2:true",
            "on_response:1:true",
        ]);
    }

    struct FailPolicy;

    #[async_trait]
    impl Policy for FailPolicy {
        async fn on_request(&self, _ctx: &PolicyContext) -> Result<(), ServiceHubError> {
            Err(ServiceHubError::Validation(
                "blocked by policy".to_owned(),
            ))
        }

        async fn on_response(
            &self,
            _ctx: &PolicyContext,
            _success: bool,
        ) -> Result<(), ServiceHubError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn policy_stack_short_circuits_on_request_error() {
        let log: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));

        let mut stack = PolicyStack::new();
        stack.push(Arc::new(FailPolicy));
        stack.push(Arc::new(OrderRecorder {
            id: 2,
            log: Arc::clone(&log),
        }));

        let ctx = test_ctx();
        let result: Result<&str, ServiceHubError> = stack
            .execute(&ctx, || async { Ok("should not run") })
            .await;

        assert!(result.is_err());
        // Second policy's on_request should never have been called.
        let entries = log.lock().clone();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn tracing_policy_does_not_error() {
        let policy = TracingPolicy;
        let ctx = test_ctx();

        policy.on_request(&ctx).await.unwrap();
        policy.on_response(&ctx, true).await.unwrap();
        policy.on_response(&ctx, false).await.unwrap();
    }
}
