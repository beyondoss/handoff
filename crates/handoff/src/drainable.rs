//! The `Drainable` trait — the consumer contract for opaque handoff-side
//! lifecycle hooks. The library calls these in a defined order over a handoff;
//! the consumer (the primitive being handed off) implements them in terms of
//! its own writer state, accept loop, and shard layout.

use std::time::Instant;

use crate::error::Result;

/// Lifecycle hooks the primitive must implement.
///
/// All methods are sync. Consumers that run on an async runtime bridge to it
/// via channels — see `ARCHITECTURE.md` for the recommended pattern.
pub trait Drainable: Send + Sync {
    /// Stop accepting new connections, cancel background tasks, drain in-flight
    /// requests, reject new writes. Reads on already-accepted connections may
    /// continue. Must `fsync` before returning so no acked write is lost.
    fn drain(&self, deadline: Instant) -> Result<DrainReport>;

    /// Per shard: flush, write footer, fsync, close the active file. Release
    /// the data-dir flock immediately on success (the library does this for
    /// you by dropping its `DataDirLock` — your `seal` need only flush state).
    fn seal(&self) -> Result<SealReport>;

    /// Restart the accept loop after an aborted handoff. Called by the library
    /// in every case where `drain` ran but `seal` either failed or never
    /// committed: post-seal `Abort`/`ResumeAfterAbort`, post-`SealFailed`,
    /// and supervisor-disconnect-while-drained. The implementation must be
    /// idempotent and must restart accepting in all cases. If the
    /// pre-handoff state included an open writer that `seal` closed, this is
    /// also where it gets re-opened.
    fn resume_after_abort(&self) -> Result<()>;

    /// Best-effort introspection for diagnostics.
    fn snapshot_state(&self) -> StateSnapshot;
}

#[derive(Debug, Clone, Default)]
pub struct DrainReport {
    pub open_conns_remaining: u32,
    pub accept_closed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SealReport {
    pub last_revision_per_shard: Vec<u64>,
    pub data_dir_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    pub shard_count: u32,
    pub open_conns: u32,
    pub last_revision_per_shard: Vec<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ReadinessSnapshot {
    pub listening_on: Vec<String>,
    pub healthz_ok: bool,
    pub advertised_revision_per_shard: Vec<u64>,
}
