use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};

use crate::domain::ports::WorkersMetricsPort;

/// OpenTelemetry-backed metrics for mini-chat background workers.
pub struct WorkersMetricsMeter {
    orphan_turn_total: Counter<u64>,
    streams_aborted_total: Counter<u64>,
}

impl WorkersMetricsMeter {
    #[must_use]
    pub fn new(meter: &Meter) -> Self {
        Self {
            orphan_turn_total: meter
                .u64_counter("mini_chat_orphan_turn_total")
                .with_description("Number of orphan turns processed by watchdog")
                .build(),
            streams_aborted_total: meter
                .u64_counter("mini_chat_streams_aborted_total")
                .with_description("Number of streams aborted by a given trigger")
                .build(),
        }
    }
}

impl WorkersMetricsPort for WorkersMetricsMeter {
    fn orphan_turn_total(&self, result: &'static str) {
        self.orphan_turn_total
            .add(1, &[KeyValue::new("result", result)]);
    }

    fn streams_aborted_total(&self, trigger: &'static str) {
        self.streams_aborted_total
            .add(1, &[KeyValue::new("trigger", trigger)]);
    }
}

