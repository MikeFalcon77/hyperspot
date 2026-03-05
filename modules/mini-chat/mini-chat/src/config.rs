use serde::{Deserialize, Serialize};

use crate::module::DEFAULT_URL_PREFIX;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiniChatConfig {
    #[serde(default = "default_url_prefix")]
    pub url_prefix: String,
    #[serde(default)]
    pub streaming: StreamingConfig,
    #[serde(default = "default_vendor")]
    pub vendor: String,
    #[serde(default)]
    pub workers: WorkersConfig,
}

// ────────────────────────────────────────────────────────────────────────────
// Workers configuration
// ────────────────────────────────────────────────────────────────────────────

/// Background workers configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkersConfig {
    /// Prefix for k8s Lease objects used by leader election.
    ///
    /// Lease names follow the pattern `"{lease_prefix}-{role}"`, where role is
    /// one of:
    /// - `orphan-watchdog-leader`
    /// - `thread-summary-leader`
    /// - `cleanup-leader`
    #[serde(default = "default_workers_lease_prefix")]
    pub lease_prefix: String,
    #[serde(default)]
    pub orphan_watchdog: OrphanWatchdogConfig,
    #[serde(default)]
    pub thread_summary: ThreadSummaryConfig,
    #[serde(default)]
    pub cleanup: CleanupConfig,
}

impl WorkersConfig {
    /// Validate all sub-configs. Returns an error describing the first
    /// invalid value found.
    pub fn validate(&self) -> Result<(), String> {
        if self.lease_prefix.trim().is_empty() {
            return Err("workers.lease_prefix must be non-empty".to_owned());
        }
        self.orphan_watchdog.validate()?;
        self.thread_summary.validate()?;
        self.cleanup.validate()?;
        Ok(())
    }
}

/// Orphan watchdog — detects running turns abandoned by crashed pods.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrphanWatchdogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Seconds between orphan scans (default: 60).
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u32,
    /// Seconds a turn can be `running` before considered orphaned (default: 300).
    /// Valid range: 60..=3600.
    #[serde(default = "default_orphan_timeout")]
    pub timeout_threshold_secs: u32,
}

impl Default for OrphanWatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_scan_interval(),
            timeout_threshold_secs: default_orphan_timeout(),
        }
    }
}

impl OrphanWatchdogConfig {
    /// Validate configuration values.
    pub fn validate(self) -> Result<(), String> {
        if !(60..=3600).contains(&self.timeout_threshold_secs) {
            return Err(format!(
                "orphan_watchdog.timeout_threshold_secs must be 60-3600, got {}",
                self.timeout_threshold_secs
            ));
        }
        if self.scan_interval_secs == 0 {
            return Err("orphan_watchdog.scan_interval_secs must be > 0".to_owned());
        }
        Ok(())
    }
}

/// Thread summary worker — compresses chat history via LLM summarization.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadSummaryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u32,
    /// Trigger summarization when message count exceeds this value (default: 20).
    #[serde(default = "default_msg_count_threshold")]
    pub msg_count_threshold: u32,
    /// Trigger summarization every N user turns (default: 15).
    #[serde(default = "default_turn_threshold")]
    pub turn_threshold: u32,
}

impl Default for ThreadSummaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_scan_interval(),
            msg_count_threshold: default_msg_count_threshold(),
            turn_threshold: default_turn_threshold(),
        }
    }
}

impl ThreadSummaryConfig {
    /// Validate configuration values.
    pub fn validate(self) -> Result<(), String> {
        if self.scan_interval_secs == 0 {
            return Err("thread_summary.scan_interval_secs must be > 0".to_owned());
        }
        if self.msg_count_threshold == 0 {
            return Err("thread_summary.msg_count_threshold must be > 0".to_owned());
        }
        if self.turn_threshold == 0 {
            return Err("thread_summary.turn_threshold must be > 0".to_owned());
        }
        Ok(())
    }
}

/// Cleanup worker — removes provider resources for soft-deleted chats.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u32,
    /// Max retry attempts per attachment (default: 10). Valid: 3..=100.
    #[serde(default = "default_cleanup_max_attempts")]
    pub max_attempts: u32,
    /// Base backoff delay in seconds (default: 2). Valid: 1..=60.
    #[serde(default = "default_cleanup_base_delay")]
    pub base_delay_secs: u32,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_scan_interval(),
            max_attempts: default_cleanup_max_attempts(),
            base_delay_secs: default_cleanup_base_delay(),
        }
    }
}

impl CleanupConfig {
    /// Validate configuration values.
    pub fn validate(self) -> Result<(), String> {
        if self.scan_interval_secs == 0 {
            return Err("cleanup.scan_interval_secs must be > 0".to_owned());
        }
        if !(3..=100).contains(&self.max_attempts) {
            return Err(format!(
                "cleanup.max_attempts must be 3-100, got {}",
                self.max_attempts
            ));
        }
        if !(1..=60).contains(&self.base_delay_secs) {
            return Err(format!(
                "cleanup.base_delay_secs must be 1-60, got {}",
                self.base_delay_secs
            ));
        }
        Ok(())
    }
}

/// SSE streaming tuning parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamingConfig {
    /// Bounded mpsc channel capacity between provider task and SSE writer.
    /// Valid range: 16–64 (default 32).
    #[serde(default = "default_channel_capacity")]
    pub sse_channel_capacity: u16,

    /// Ping keepalive interval in seconds.
    /// Valid range: 5–60 (default 15).
    #[serde(default = "default_ping_interval")]
    pub sse_ping_interval_seconds: u16,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            sse_channel_capacity: default_channel_capacity(),
            sse_ping_interval_seconds: default_ping_interval(),
        }
    }
}

impl StreamingConfig {
    /// Validate configuration values at startup. Returns an error message
    /// describing the first invalid value found.
    pub fn validate(self) -> Result<(), String> {
        if !(16..=64).contains(&self.sse_channel_capacity) {
            return Err(format!(
                "sse_channel_capacity must be 16-64, got {}",
                self.sse_channel_capacity
            ));
        }
        if !(5..=60).contains(&self.sse_ping_interval_seconds) {
            return Err(format!(
                "sse_ping_interval_seconds must be 5-60, got {}",
                self.sse_ping_interval_seconds
            ));
        }
        Ok(())
    }
}

fn default_channel_capacity() -> u16 {
    32
}

fn default_ping_interval() -> u16 {
    15
}

const fn default_true() -> bool {
    true
}

const fn default_scan_interval() -> u32 {
    60
}

const fn default_orphan_timeout() -> u32 {
    300
}

const fn default_msg_count_threshold() -> u32 {
    20
}

const fn default_turn_threshold() -> u32 {
    15
}

const fn default_cleanup_max_attempts() -> u32 {
    10
}

const fn default_cleanup_base_delay() -> u32 {
    2
}

fn default_workers_lease_prefix() -> String {
    "mini-chat".to_owned()
}

impl Default for MiniChatConfig {
    fn default() -> Self {
        Self {
            url_prefix: default_url_prefix(),
            streaming: StreamingConfig::default(),
            vendor: default_vendor(),
            workers: WorkersConfig::default(),
        }
    }
}

fn default_url_prefix() -> String {
    DEFAULT_URL_PREFIX.to_owned()
}

fn default_vendor() -> String {
    "hyperspot".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        StreamingConfig::default().validate().unwrap();
        WorkersConfig::default().validate().unwrap();
    }

    #[test]
    fn channel_capacity_boundaries() {
        let valid = StreamingConfig::default();

        assert!(
            (StreamingConfig {
                sse_channel_capacity: 15,
                ..valid
            })
            .validate()
            .is_err()
        );
        assert!(
            (StreamingConfig {
                sse_channel_capacity: 16,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (StreamingConfig {
                sse_channel_capacity: 64,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (StreamingConfig {
                sse_channel_capacity: 65,
                ..valid
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn ping_interval_boundaries() {
        let valid = StreamingConfig::default();

        assert!(
            (StreamingConfig {
                sse_ping_interval_seconds: 4,
                ..valid
            })
            .validate()
            .is_err()
        );
        assert!(
            (StreamingConfig {
                sse_ping_interval_seconds: 5,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (StreamingConfig {
                sse_ping_interval_seconds: 60,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (StreamingConfig {
                sse_ping_interval_seconds: 61,
                ..valid
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn orphan_watchdog_timeout_boundaries() {
        let valid = OrphanWatchdogConfig::default();

        assert!(
            (OrphanWatchdogConfig {
                timeout_threshold_secs: 59,
                ..valid
            })
            .validate()
            .is_err()
        );
        assert!(
            (OrphanWatchdogConfig {
                timeout_threshold_secs: 60,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (OrphanWatchdogConfig {
                timeout_threshold_secs: 3600,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (OrphanWatchdogConfig {
                timeout_threshold_secs: 3601,
                ..valid
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn cleanup_max_attempts_boundaries() {
        let valid = CleanupConfig::default();

        assert!(
            (CleanupConfig {
                max_attempts: 2,
                ..valid
            })
            .validate()
            .is_err()
        );
        assert!(
            (CleanupConfig {
                max_attempts: 3,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (CleanupConfig {
                max_attempts: 100,
                ..valid
            })
            .validate()
            .is_ok()
        );
        assert!(
            (CleanupConfig {
                max_attempts: 101,
                ..valid
            })
            .validate()
            .is_err()
        );
    }
}
