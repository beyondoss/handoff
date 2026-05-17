//! The `Drainable` trait and its report/snapshot types. Implemented in task #3.

use std::time::Instant;

use crate::error::Result;

pub trait Drainable: Send + Sync {
    fn drain(&self, deadline: Instant) -> Result<DrainReport>;
    fn seal(&self) -> Result<SealReport>;
    fn resume_after_abort(&self) -> Result<()>;
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
