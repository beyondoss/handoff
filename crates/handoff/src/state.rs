//! Handoff state journal — persisted across supervisor restarts.
//!
//! Writes are atomic (`write tmp + rename`). The supervisor records a new
//! [`Phase`] after each acknowledged protocol step, so a crashed-and-restarted
//! supervisor can read the journal and resume the protocol from exactly where
//! it left off. Supports correctness invariant #7.
//!
//! The journal lives at `/var/lib/beyond/handoff/<svc>/state.bin` by
//! convention; the location is supplied by the consumer.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::protocol::HandoffId;

/// Coarse phase recorded in the on-disk journal between protocol steps. Used
/// by the supervisor for crash-recovery diagnostics — not the in-memory
/// state machine. Each variant maps 1:1 to a transition documented in
/// `ARCHITECTURE.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// `Hello`/`HelloAck` exchanged with both peers; no protocol message
    /// sent or received yet.
    Negotiating,
    /// `Drained` received from O. Next supervisor action is `SealRequest`.
    Draining,
    /// `SealComplete` received from O. O has released the flock. Next
    /// supervisor action is `Begin` to N.
    Sealing,
    /// `Begin` sent to N. Waiting for `Ready`.
    AwaitingReady,
    /// `Commit` sent to O. Cleanup pending (journal clear, child disarm).
    Committed,
    /// `ResumeAfterAbort` sent to O after a post-seal abort.
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
    ///
    /// Writes the payload to `<path>.tmp`, fsyncs it, renames, then fsyncs
    /// the parent directory. The file fsync makes the contents durable;
    /// the directory fsync makes the rename's link-update durable. Without
    /// the directory fsync the rename can be lost on power failure even
    /// though the file contents survived — leaving a journaled phase that
    /// silently rolls back to the prior entry on supervisor restart. Pairs
    /// with the same pattern in `lock.rs::write_pid_atomic`.
    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("bin.tmp");
        let bytes = postcard::to_allocvec(self)?;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            fsync_dir(parent)?;
        }
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

/// fsync a directory inode so a rename or unlink performed on a file
/// within it becomes crash-durable. `File::open` on a directory is
/// read-only on POSIX; we just need a usable FD to pass to `fsync`.
/// Empty paths fall back to the current directory.
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let target = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    File::open(target)?.sync_all()
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
