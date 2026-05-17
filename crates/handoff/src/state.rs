//! Handoff state journal — persisted across supervisor restarts.
//!
//! Writes are atomic (`write tmp + rename`). The supervisor records a new
//! [`Phase`] after each acknowledged protocol step, so a crashed-and-restarted
//! supervisor can read the journal and resume the protocol from exactly where
//! it left off. Supports correctness invariant #7.
//!
//! The journal lives at `/var/lib/beyond/handoff/<svc>/state.bin` by
//! convention; the location is supplied by the consumer.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::protocol::HandoffId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Idle,
    Negotiating,
    Draining,
    Sealing,
    Beginning,
    AwaitingReady,
    Committed,
    Aborting,
    ResumingAfterAbort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateJournal {
    pub handoff_id: HandoffId,
    pub phase: Phase,
    pub incumbent_pid: u32,
    pub successor_pid: Option<u32>,
    /// Unix millis when the handoff was initiated.
    pub started_at_unix_ms: u64,
}

impl StateJournal {
    /// Atomically write the journal. Creates the parent directory if missing.
    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("bin.tmp");
        let bytes = postcard::to_allocvec(self)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Read a previously-persisted journal. `Ok(None)` if no journal exists.
    pub fn read(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(postcard::from_bytes(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove the journal. Idempotent.
    pub fn delete(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_persists_phase_and_pids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        let original = StateJournal {
            handoff_id: HandoffId::new(),
            phase: Phase::Sealing,
            incumbent_pid: 1234,
            successor_pid: Some(5678),
            started_at_unix_ms: 1_700_000_000_000,
        };
        original.write_atomic(&path).unwrap();
        let loaded = StateJournal::read(&path).unwrap().unwrap();
        assert_eq!(loaded.phase, Phase::Sealing);
        assert_eq!(loaded.incumbent_pid, 1234);
        assert_eq!(loaded.successor_pid, Some(5678));
        assert_eq!(loaded.handoff_id, original.handoff_id);
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        assert!(StateJournal::read(&path).unwrap().is_none());
    }

    #[test]
    fn delete_missing_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        StateJournal::delete(&path).unwrap();
        StateJournal::delete(&path).unwrap();
    }
}
