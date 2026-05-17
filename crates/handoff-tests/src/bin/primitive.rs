//! Test primitive — the cold-start incumbent and the spawned successor are
//! both instances of this binary, differentiated by [`handoff::detect_role`].
//!
//! Reads its configuration from env vars set by the test harness:
//!
//! | Var | Purpose |
//! |-----|---------|
//! | `HANDOFF_DATA_DIR`       | Where the data-dir flock lives |
//! | `HANDOFF_CONTROL_SOCKET` | Where `Incumbent::bind_cold_start` listens |
//! | `HANDOFF_MARKER_DIR`     | Lifecycle markers + crash markers go here |
//! | `HANDOFF_CRASH_AT`       | If set + matches `crash_here!` point → exit 99 |
//! | `HANDOFF_SEAL_FAILS_ONCE`| `"1"` → `Drainable::seal` returns Err once |
//!
//! Markers emitted (under `HANDOFF_MARKER_DIR`):
//!
//! - `serving.marker`             — Incumbent::serve loop entered
//! - `successor-handshake.marker` — successor finished handshake
//! - `successor-begin.marker`     — successor received `Begin`
//! - `successor-ready.marker`     — successor sent `Ready`
//! - `drain-called.marker`        — `Drainable::drain` entered
//! - `seal-called.marker`         — `Drainable::seal` entered
//! - `resume-called.marker`       — `Drainable::resume_after_abort` entered

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};

use handoff::crash::points as crash_points;
use handoff::crash_here;
use handoff::{
    DataDirLock, DrainReport, Drainable, Incumbent, ReadinessSnapshot, Role, SealReport,
    StateSnapshot, detect_role,
};

use handoff_tests::{env_path, primitive_points, write_marker};

fn main() -> Result<()> {
    init_logging();

    let data_dir = env_path("HANDOFF_DATA_DIR");
    let control_socket = env_path("HANDOFF_CONTROL_SOCKET");

    match detect_role().context("detect_role")? {
        Role::ColdStart { .. } => run_cold_start(&data_dir, &control_socket),
        Role::Successor(succ) => run_successor(succ, &data_dir, &control_socket),
    }
}

fn run_cold_start(data_dir: &std::path::Path, control_socket: &std::path::Path) -> Result<()> {
    let lock = DataDirLock::acquire(data_dir).context("acquire flock")?;
    let incumbent =
        Incumbent::bind_cold_start(control_socket, lock).context("bind control socket")?;
    write_marker_pid("incumbent-pid", std::process::id());
    write_marker("serving");
    incumbent
        .serve(TestDrainable::from_env())
        .context("serve")?;
    Ok(())
}

fn run_successor(
    mut succ: handoff::Successor,
    data_dir: &std::path::Path,
    control_socket: &std::path::Path,
) -> Result<()> {
    write_marker_pid("successor-pid", std::process::id());
    crash_here!(primitive_points::N_BEFORE_HANDSHAKE);
    succ.handshake(b"handoff-test".to_vec())
        .context("handshake")?;
    write_marker("successor-handshake");
    crash_here!(primitive_points::N_AFTER_HANDSHAKE);

    succ.wait_for_begin().context("wait_for_begin")?;
    write_marker("successor-begin");
    crash_here!(primitive_points::N_AFTER_BEGIN);

    // The successor must hold the data-dir flock before binding the control
    // socket — this matches the architecture invariant: N refuses to write
    // until it holds the flock.
    let lock = DataDirLock::acquire(data_dir).context("successor acquire flock")?;

    crash_here!(primitive_points::N_BEFORE_ANNOUNCE_READY);
    let snapshot = ReadinessSnapshot {
        listening_on: Vec::new(),
        healthz_ok: true,
        advertised_revision_per_shard: vec![43],
    };
    let incumbent = succ
        .announce_and_bind(snapshot, control_socket, lock)
        .context("announce_and_bind")?;
    write_marker("successor-ready");

    incumbent
        .serve(TestDrainable::from_env())
        .context("successor serve")?;
    Ok(())
}

fn write_marker_pid(name: &str, pid: u32) {
    let dir = match std::env::var_os("HANDOFF_MARKER_DIR") {
        Some(d) => std::path::PathBuf::from(d),
        None => return,
    };
    let _ = std::fs::write(dir.join(format!("{name}.marker")), pid.to_string());
}

/// Test-only `Drainable` that records what the protocol asked it to do via
/// marker files and optionally fails seal on the first call.
#[derive(Clone)]
struct TestDrainable {
    seal_fails_once: Arc<AtomicBool>,
    drain_count: Arc<AtomicU32>,
    seal_count: Arc<AtomicU32>,
    resume_count: Arc<AtomicU32>,
}

impl TestDrainable {
    fn from_env() -> Self {
        let fails = std::env::var("HANDOFF_SEAL_FAILS_ONCE").as_deref() == Ok("1");
        Self {
            seal_fails_once: Arc::new(AtomicBool::new(fails)),
            drain_count: Arc::new(AtomicU32::new(0)),
            seal_count: Arc::new(AtomicU32::new(0)),
            resume_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl Drainable for TestDrainable {
    fn drain(&self, _deadline: Instant) -> handoff::Result<DrainReport> {
        self.drain_count.fetch_add(1, Ordering::SeqCst);
        write_marker("drain-called");
        crash_here!(primitive_points::O_INSIDE_DRAIN);
        Ok(DrainReport {
            open_conns_remaining: 0,
            accept_closed: true,
        })
    }

    fn seal(&self) -> handoff::Result<SealReport> {
        self.seal_count.fetch_add(1, Ordering::SeqCst);
        write_marker("seal-called");
        crash_here!(primitive_points::O_INSIDE_SEAL);
        if self.seal_fails_once.swap(false, Ordering::SeqCst) {
            return Err(handoff::Error::SealFailed("injected seal failure".into()));
        }
        // Touch the library's S-side point name to keep the const referenced
        // in fixture code (helps catch accidental const removal).
        let _ = crash_points::S_AFTER_COMMIT_SENT;
        Ok(SealReport {
            last_revision_per_shard: vec![42],
            data_dir_fingerprint: [0xab; 32],
        })
    }

    fn resume_after_abort(&self) -> handoff::Result<()> {
        self.resume_count.fetch_add(1, Ordering::SeqCst);
        write_marker("resume-called");
        Ok(())
    }

    fn snapshot_state(&self) -> StateSnapshot {
        StateSnapshot::default()
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
