use std::time::Duration;

/// Adaptive pacing configuration for the worker loop.
/// Framework-level — no outbox-specific knowledge.
#[derive(Debug, Clone)]
pub struct PacingConfig {
    /// Fastest pace — floor for sustained work.
    pub min_interval: Duration,
    /// Starting pace after waking from Idle. Ramps down to `min_interval`.
    pub active_interval: Duration,
    /// Safety-net poll interval while Idle (poker timer).
    pub idle_interval: Duration,
    /// Subtracted per consecutive Proceed (ramp-down step).
    pub ramp_step: Duration,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_millis(10),
            active_interval: Duration::from_millis(100),
            idle_interval: Duration::from_secs(600),
            ramp_step: Duration::from_millis(10),
        }
    }
}
