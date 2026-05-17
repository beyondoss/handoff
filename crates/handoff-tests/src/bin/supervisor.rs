//! Test supervisor — performs exactly one handoff against a running
//! [`handoff_test_primitive`] incumbent, then exits with a status that
//! encodes the outcome.
//!
//! Reads its configuration from env vars set by the test harness:
//!
//! | Var | Purpose |
//! |-----|---------|
//! | `HANDOFF_CONTROL_SOCKET`  | Path of the incumbent's control socket |
//! | `HANDOFF_DATA_DIR`        | Data dir, propagated to N |
//! | `HANDOFF_JOURNAL`         | Path for the state journal |
//! | `HANDOFF_MARKER_DIR`      | Lifecycle markers go here |
//! | `HANDOFF_PRIMITIVE_BINARY`| Binary to spawn as N |
//! | `HANDOFF_CRASH_AT`        | If set → S crashes at this point |
//! | `HANDOFF_CRASH_AT_FOR_N`  | If set → S propagates to N via spec.env |
//!
//! Exit codes:
//!
//! - `0`  — handoff committed
//! - `2`  — handoff aborted with a recoverable outcome
//! - `3`  — `perform_handoff` returned `Err`
//! - `99` — crash injection (set by `crash_here!`)
//!
//! Markers emitted:
//!
//! - `supervisor-resume-from-journal.marker` — `resume_from_journal` returned `Some`
//! - `supervisor-committed.marker`            — outcome.committed == true
//! - `supervisor-aborted.marker`              — outcome.committed == false

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};

use handoff::supervisor::{SpawnSpec, Supervisor};

use handoff_tests::{crash_for_successor, env_path, write_marker};

fn main() -> ExitCode {
    init_logging();
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("test supervisor error: {e:#}");
            ExitCode::from(3)
        }
    }
}

fn run() -> Result<ExitCode> {
    let control_socket = env_path("HANDOFF_CONTROL_SOCKET");
    let journal = env_path("HANDOFF_JOURNAL");
    let primitive_binary = env_path("HANDOFF_PRIMITIVE_BINARY");
    let data_dir = env_path("HANDOFF_DATA_DIR");
    let markers = env_path("HANDOFF_MARKER_DIR");

    let mut sup = Supervisor::new(&control_socket).context("Supervisor::new")?;
    if !journal.as_os_str().is_empty() {
        sup = sup.with_journal(journal);
    }
    let sup = sup;

    // First, ALWAYS call resume_from_journal: this exercises the
    // restart-time recovery path on every supervisor invocation. If a prior
    // run left a journal on disk, this clears it. If not, it's a no-op.
    if let Some(prior) = sup.resume_from_journal().context("resume_from_journal")? {
        write_marker("supervisor-resume-from-journal");
        tracing::warn!(
            handoff_id = %prior.handoff_id,
            phase = ?prior.phase,
            "resumed from prior handoff journal"
        );
    }

    // Build spec.env that explicitly OVERRIDES any inherited HANDOFF_CRASH_AT
    // for the successor: we always pass an explicit value (possibly empty)
    // so N never inherits S's crash point by accident.
    let n_crash = crash_for_successor();
    let spec = SpawnSpec {
        binary: primitive_binary,
        args: Vec::new(),
        env: vec![
            ("HANDOFF_CRASH_AT".into(), n_crash),
            ("HANDOFF_CRASH_ROLE".into(), "successor".into()),
            (
                "HANDOFF_CRASH_MARKER_DIR".into(),
                markers
                    .to_str()
                    .context("marker dir not utf-8")?
                    .to_string(),
            ),
            (
                "HANDOFF_DATA_DIR".into(),
                data_dir.to_str().context("data dir not utf-8")?.to_string(),
            ),
            (
                "HANDOFF_CONTROL_SOCKET".into(),
                control_socket
                    .to_str()
                    .context("control socket not utf-8")?
                    .to_string(),
            ),
            (
                "HANDOFF_MARKER_DIR".into(),
                markers
                    .to_str()
                    .context("marker dir not utf-8")?
                    .to_string(),
            ),
            (
                "HANDOFF_SEAL_FAILS_ONCE".into(),
                std::env::var("HANDOFF_SEAL_FAILS_ONCE").unwrap_or_default(),
            ),
        ],
        deadline: Duration::from_secs(30),
        drain_grace: Duration::from_secs(10),
    };

    let outcome = sup.perform_handoff(spec).context("perform_handoff")?;
    if outcome.committed {
        write_marker("supervisor-committed");
        // Hand the new primitive's lifecycle off — leak the Child so it
        // keeps running after this process exits. The harness will reap it
        // by killing the orphan when the fixture drops.
        if let Some(child) = outcome.child {
            std::mem::forget(child);
        }
        Ok(ExitCode::from(0))
    } else {
        write_marker("supervisor-aborted");
        eprintln!("handoff aborted: {:?}", outcome.abort_reason);
        Ok(ExitCode::from(2))
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
