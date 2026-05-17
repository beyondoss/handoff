//! Observability name constants.
//!
//! Implementations emit `tracing` events with these names and metric backends
//! register counters/histograms with these names so dashboards stay
//! consistent across primitives.

/// Counters and histograms.
pub const HANDOFFS_TOTAL: &str = "handoff_handoffs_total";
pub const HANDOFFS_FAILED_TOTAL: &str = "handoff_failures_total";
pub const HANDOFFS_ROLLED_BACK_TOTAL: &str = "handoff_rolled_back_total";
pub const SEAL_FAILURES_TOTAL: &str = "handoff_seal_failures_total";

pub const HANDOFF_DURATION_SECONDS: &str = "handoff_duration_seconds";
pub const HANDOFF_DRAIN_SECONDS: &str = "handoff_drain_seconds";
pub const HANDOFF_SEAL_SECONDS: &str = "handoff_seal_seconds";
pub const HANDOFF_BEGIN_TO_READY_SECONDS: &str = "handoff_begin_to_ready_seconds";

/// `tracing` event names — emitted as spans or events per phase transition.
pub mod events {
    pub const PREPARE: &str = "handoff.prepare";
    pub const DRAINED: &str = "handoff.drained";
    pub const SEAL: &str = "handoff.seal";
    pub const SEAL_COMPLETE: &str = "handoff.seal_complete";
    pub const READY: &str = "handoff.ready";
    pub const COMMIT: &str = "handoff.commit";
    pub const ABORT: &str = "handoff.abort";
    pub const RESUME: &str = "handoff.resume";
}
