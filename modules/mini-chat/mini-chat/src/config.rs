use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::infra::llm::ProviderKind;
use crate::module::DEFAULT_URL_PREFIX;

#[derive(Debug, Clone, Serialize, Deserialize, modkit_macros::ExpandVars)]
#[serde(deny_unknown_fields)]
pub struct MiniChatConfig {
    #[serde(default = "default_url_prefix")]
    pub url_prefix: String,
    #[serde(default)]
    pub streaming: StreamingConfig,
    #[serde(default)]
    pub workers: WorkersConfig,
    #[serde(default = "default_vendor")]
    pub vendor: String,
    #[serde(default)]
    pub estimation_budgets: EstimationBudgets,
    #[serde(default)]
    pub quota: QuotaConfig,
    #[serde(default)]
    pub outbox: OutboxConfig,
    #[serde(default)]
    pub context: ContextConfig,
    /// Provider registry. Key = `provider_id` (matches [`ModelCatalogEntry::provider_id`]).
    #[expand_vars]
    #[serde(default = "default_providers")]
    pub providers: HashMap<String, ProviderEntry>,
}

/// Configuration for a single LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize, modkit_macros::ExpandVars)]
#[serde(deny_unknown_fields)]
pub struct ProviderEntry {
    /// Which adapter to use (e.g., `openai_responses`, `openai_chat_completions`).
    pub kind: ProviderKind,
    /// OAGW upstream alias (used in proxy URI: `/{alias}/...`).
    /// Defaults to [`host`](ProviderEntry::host) when omitted.
    #[serde(default)]
    pub upstream_alias: Option<String>,
    /// Upstream hostname (e.g., `api.openai.com`). Used for OAGW upstream
    /// registration during module init.
    pub host: String,
    /// API path template for the responses endpoint.
    /// Use `{model}` as placeholder for the deployment/model name.
    /// Defaults to `/v1/responses` (`OpenAI` native).
    /// Azure example: `/openai/deployments/{model}/responses?api-version=2025-03-01-preview`
    #[serde(default = "default_api_path")]
    pub api_path: String,
    /// OAGW auth plugin type for this upstream (optional).
    /// Example: `gts.x.core.oagw.auth_plugin.v1~x.core.oagw.apikey.v1`
    #[serde(default)]
    pub auth_plugin_type: Option<String>,
    /// Auth plugin config (e.g., `header`, `prefix`, `secret_ref`).
    /// Values support `${VAR}` env expansion via [`config_expanded()`].
    #[expand_vars]
    #[serde(default)]
    pub auth_config: Option<HashMap<String, String>>,
}

impl ProviderEntry {
    /// Effective OAGW upstream alias — falls back to [`host`](Self::host) when
    /// [`upstream_alias`](Self::upstream_alias) is not explicitly configured.
    #[must_use]
    pub fn effective_alias(&self) -> &str {
        self.upstream_alias.as_deref().unwrap_or(&self.host)
    }

    /// Validate provider entry at startup.
    pub fn validate(&self, provider_id: &str) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err(format!("provider '{provider_id}': host must not be empty"));
        }
        Ok(())
    }
}

fn default_api_path() -> String {
    "/v1/responses".to_owned()
}

fn default_providers() -> HashMap<String, ProviderEntry> {
    let mut m = HashMap::new();
    m.insert(
        "openai".to_owned(),
        ProviderEntry {
            kind: ProviderKind::OpenAiResponses,
            upstream_alias: None,
            host: "api.openai.com".to_owned(),
            api_path: default_api_path(),
            auth_plugin_type: Some(
                "gts.x.core.oagw.auth_plugin.v1~x.core.oagw.apikey.v1".to_owned(),
            ),
            auth_config: Some({
                let mut c = HashMap::new();
                c.insert("header".to_owned(), "Authorization".to_owned());
                c.insert("prefix".to_owned(), "Bearer ".to_owned());
                c.insert("secret_ref".to_owned(), "cred://openai-key".to_owned());
                c
            }),
        },
    );
    m
}

/// Background workers configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for WorkersConfig {
    fn default() -> Self {
        Self {
            lease_prefix: default_workers_lease_prefix(),
            orphan_watchdog: OrphanWatchdogConfig::default(),
            thread_summary: ThreadSummaryConfig::default(),
            cleanup: CleanupConfig::default(),
        }
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Model override for summarization. If empty, the chat's own model is used.
    #[serde(default)]
    pub summary_model: String,
    /// Provider ID used for summarization LLM calls (must match a key in
    /// `MiniChatConfig.providers`). Defaults to `"openai"`.
    #[serde(default = "default_summary_provider_id")]
    pub summary_provider_id: String,
    /// Hard cap on summary output tokens (default: 1024).
    #[serde(default = "default_max_summary_tokens")]
    pub max_summary_tokens: u64,
}

impl Default for ThreadSummaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_scan_interval(),
            msg_count_threshold: default_msg_count_threshold(),
            turn_threshold: default_turn_threshold(),
            summary_model: String::new(),
            summary_provider_id: default_summary_provider_id(),
            max_summary_tokens: default_max_summary_tokens(),
        }
    }
}

impl ThreadSummaryConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if self.scan_interval_secs == 0 {
            return Err("thread_summary.scan_interval_secs must be > 0".to_owned());
        }
        if self.msg_count_threshold == 0 {
            return Err("thread_summary.msg_count_threshold must be > 0".to_owned());
        }
        if self.turn_threshold == 0 {
            return Err("thread_summary.turn_threshold must be > 0".to_owned());
        }
        if self.max_summary_tokens == 0 {
            return Err("thread_summary.max_summary_tokens must be > 0".to_owned());
        }
        if self.summary_provider_id.trim().is_empty() {
            return Err("thread_summary.summary_provider_id must be non-empty".to_owned());
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

    /// Maximum output tokens sent to the preflight reserve.
    /// Default 32768 (matching common model limits).
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            sse_channel_capacity: default_channel_capacity(),
            sse_ping_interval_seconds: default_ping_interval(),
            max_output_tokens: default_max_output_tokens(),
        }
    }
}

fn default_max_output_tokens() -> u32 {
    32_768
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

const fn default_max_summary_tokens() -> u64 {
    1024
}

fn default_summary_provider_id() -> String {
    "openai".to_owned()
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
            workers: WorkersConfig::default(),
            vendor: default_vendor(),
            estimation_budgets: EstimationBudgets::default(),
            quota: QuotaConfig::default(),
            outbox: OutboxConfig::default(),
            context: ContextConfig::default(),
            providers: default_providers(),
        }
    }
}

/// Token estimation parameters sourced from `ConfigMap` (P1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstimationBudgets {
    #[serde(default = "default_bytes_per_token")]
    pub bytes_per_token_conservative: u32,
    #[serde(default = "default_fixed_overhead")]
    pub fixed_overhead_tokens: u32,
    #[serde(default = "default_safety_margin")]
    pub safety_margin_pct: u32,
    #[serde(default = "default_image_budget")]
    pub image_token_budget: u32,
    #[serde(default = "default_tool_surcharge")]
    pub tool_surcharge_tokens: u32,
    #[serde(default = "default_web_surcharge")]
    pub web_search_surcharge_tokens: u32,
    #[serde(default = "default_min_gen_floor")]
    pub minimal_generation_floor: u32,
}

impl Default for EstimationBudgets {
    fn default() -> Self {
        Self {
            bytes_per_token_conservative: default_bytes_per_token(),
            fixed_overhead_tokens: default_fixed_overhead(),
            safety_margin_pct: default_safety_margin(),
            image_token_budget: default_image_budget(),
            tool_surcharge_tokens: default_tool_surcharge(),
            web_search_surcharge_tokens: default_web_surcharge(),
            minimal_generation_floor: default_min_gen_floor(),
        }
    }
}

impl EstimationBudgets {
    pub fn validate(self) -> Result<(), String> {
        if self.bytes_per_token_conservative == 0 {
            return Err("bytes_per_token_conservative must be > 0".to_owned());
        }
        if self.minimal_generation_floor == 0 {
            return Err("minimal_generation_floor must be > 0".to_owned());
        }
        Ok(())
    }
}

fn default_bytes_per_token() -> u32 {
    4
}
fn default_fixed_overhead() -> u32 {
    100
}
fn default_safety_margin() -> u32 {
    10
}
fn default_image_budget() -> u32 {
    1000
}
fn default_tool_surcharge() -> u32 {
    500
}
fn default_web_surcharge() -> u32 {
    500
}
fn default_min_gen_floor() -> u32 {
    50
}

/// Quota enforcement configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    #[serde(default = "default_overshoot_tolerance")]
    pub overshoot_tolerance_factor: f64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            overshoot_tolerance_factor: default_overshoot_tolerance(),
        }
    }
}

impl QuotaConfig {
    pub fn validate(self) -> Result<(), String> {
        if !(1.0..=1.5).contains(&self.overshoot_tolerance_factor) {
            return Err(format!(
                "overshoot_tolerance_factor must be 1.0-1.5, got {}",
                self.overshoot_tolerance_factor
            ));
        }
        Ok(())
    }
}

/// Outbox configuration for usage event publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxConfig {
    /// Queue name for usage events.
    #[serde(default = "default_outbox_queue_name")]
    pub queue_name: String,

    /// Number of outbox partitions. Must be 1–64.
    #[serde(default = "default_outbox_num_partitions")]
    pub num_partitions: u32,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            queue_name: default_outbox_queue_name(),
            num_partitions: default_outbox_num_partitions(),
        }
    }
}

impl OutboxConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.queue_name.trim().is_empty() {
            return Err("outbox queue_name must not be empty".to_owned());
        }
        if !(1..=64).contains(&self.num_partitions) || !self.num_partitions.is_power_of_two() {
            return Err(format!(
                "outbox num_partitions must be a power of 2 in 1-64, got {}",
                self.num_partitions
            ));
        }
        Ok(())
    }
}

fn default_outbox_queue_name() -> String {
    "mini-chat.usage_snapshot".to_owned()
}

fn default_outbox_num_partitions() -> u32 {
    4
}

fn default_overshoot_tolerance() -> f64 {
    1.10
}

/// Context assembly configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfig {
    /// Soft-guideline instruction appended to system prompt when `web_search` is enabled.
    #[serde(default = "default_web_search_guard")]
    pub web_search_guard: String,

    /// Soft-guideline instruction appended to system prompt when `file_search` is enabled.
    #[serde(default = "default_file_search_guard")]
    pub file_search_guard: String,

    /// Maximum number of recent messages to include in context. Range: 0–100.
    #[serde(default = "default_recent_messages_limit")]
    pub recent_messages_limit: u32,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            web_search_guard: default_web_search_guard(),
            file_search_guard: default_file_search_guard(),
            recent_messages_limit: default_recent_messages_limit(),
        }
    }
}

impl ContextConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.recent_messages_limit > 100 {
            return Err(format!(
                "context recent_messages_limit must be 0-100, got {}",
                self.recent_messages_limit
            ));
        }
        Ok(())
    }
}

fn default_web_search_guard() -> String {
    "Use web_search only if the answer cannot be obtained from the provided context or your training data. Never use it for general knowledge questions. At most one web_search call per request.".to_owned()
}

fn default_file_search_guard() -> String {
    "Use file_search to find relevant information in the user's uploaded documents. Prefer file_search over general knowledge when documents are available.".to_owned()
}

fn default_recent_messages_limit() -> u32 {
    10
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
        EstimationBudgets::default().validate().unwrap();
        QuotaConfig::default().validate().unwrap();
        OutboxConfig::default().validate().unwrap();
        ContextConfig::default().validate().unwrap();
        WorkersConfig::default().validate().unwrap();
    }

    #[test]
    fn estimation_budgets_validation() {
        let valid = EstimationBudgets::default();

        assert!(
            (EstimationBudgets {
                bytes_per_token_conservative: 0,
                ..valid
            })
            .validate()
            .is_err()
        );
        assert!(
            (EstimationBudgets {
                minimal_generation_floor: 0,
                ..valid
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn quota_config_validation() {
        assert!(
            (QuotaConfig {
                overshoot_tolerance_factor: 0.99
            })
            .validate()
            .is_err()
        );
        assert!(
            (QuotaConfig {
                overshoot_tolerance_factor: 1.0
            })
            .validate()
            .is_ok()
        );
        assert!(
            (QuotaConfig {
                overshoot_tolerance_factor: 1.5
            })
            .validate()
            .is_ok()
        );
        assert!(
            (QuotaConfig {
                overshoot_tolerance_factor: 1.51
            })
            .validate()
            .is_err()
        );
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
