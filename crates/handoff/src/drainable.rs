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
///
/// # Long-running hooks are fine
///
/// While `drain` and `seal` are executing, the incumbent runs a background
/// thread that emits `Heartbeat` frames every ~2s on the control socket.
/// The supervisor's per-recv liveness timeout (10s) is reset by each
/// heartbeat, so a hook that takes 30s, 5 minutes, or longer will *not*
/// trip a peer-dead timeout — only an unresponsive peer (no frames for
/// over 10 seconds) will. The overall handoff is still bounded by
/// `SpawnSpec::deadline` (5 minutes by default; size it above the p99 of
/// `drain` + `seal` for your workload).
pub trait Drainable: Send + Sync {
    /// Stop accepting new connections, cancel background tasks, drain in-flight
    /// requests, reject new writes. Reads on already-accepted connections may
    /// continue. Must `fsync` before returning so no acked write is lost.
    ///
    /// Bounded by `deadline` (passed in) and by `SpawnSpec::drain_grace`
    /// (wall-clock cap on the supervisor side). Slow-but-progressing drains
    /// are kept alive by the library's heartbeat thread — there's no need
    /// to artificially shorten the work to fit a tight timeout.
    fn drain(&self, deadline: Instant) -> Result<DrainReport>;

    /// Per shard: flush, write footer, fsync, close the active file. Release
    /// the data-dir flock immediately on success (the library does this for
    /// you by dropping its `DataDirLock` — your `seal` need only flush state).
    ///
    /// May take as long as the consumer needs. While `seal` is running, the
    /// library emits heartbeats on the control socket so the supervisor's
    /// liveness clock stays fresh; only the overall `SpawnSpec::deadline`
    /// (default 5 minutes) caps the wall-clock duration.
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
