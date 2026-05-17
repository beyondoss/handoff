//! Shared test helpers for handoff integration tests.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use handoff::{DrainReport, Drainable, SealReport, StateSnapshot};

#[derive(Debug, Default, Clone)]
pub struct MockState {
    pub drained: bool,
    pub sealed: bool,
    pub resumed: u32,
    pub seal_should_fail: bool,
}

/// `Drainable` implementation backed by a shared `Mutex<MockState>` so tests
/// can observe what the protocol asked the consumer to do.
#[derive(Clone, Default)]
pub struct MockDrainable {
    pub state: Arc<Mutex<MockState>>,
}

impl Drainable for MockDrainable {
    fn drain(&self, _deadline: Instant) -> handoff::Result<DrainReport> {
        let mut s = self.state.lock().unwrap();
        s.drained = true;
        Ok(DrainReport {
            open_conns_remaining: 0,
            accept_closed: true,
        })
    }

    fn seal(&self) -> handoff::Result<SealReport> {
        let mut s = self.state.lock().unwrap();
        if s.seal_should_fail {
            return Err(handoff::Error::SealFailed("mock seal failure".into()));
        }
        s.sealed = true;
        Ok(SealReport {
            last_revision_per_shard: vec![42],
            data_dir_fingerprint: [0xab; 32],
        })
    }

    fn resume_after_abort(&self) -> handoff::Result<()> {
        let mut s = self.state.lock().unwrap();
        s.resumed += 1;
        s.sealed = false;
        Ok(())
    }

    fn snapshot_state(&self) -> StateSnapshot {
        StateSnapshot::default()
    }
}
