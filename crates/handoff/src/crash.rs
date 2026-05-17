//! Crash-injection points for fault-tolerance testing.
//!
//! Gated behind the `crash-points` cargo feature so production builds pay
//! exactly nothing — without the feature, [`crash_here!`] is a no-op and the
//! compiler elides every call site. Under test, calls become a guarded
//! `libc::_exit(99)` when the `HANDOFF_CRASH_AT` env var equals the named
//! point.
//!
//! Why `_exit` and not panic, abort, or kill? Three reasons:
//! - `_exit` bypasses Rust destructors. No `Drop::drop` on `DataDirLock`, no
//!   tempfile cleanup, no journal flush — the kernel reclaims everything.
//!   This is the worst case for crash recovery and the closest in-process
//!   simulation of a real `SIGKILL`.
//! - Exit code 99 distinguishes injected crashes from normal exits (0, 1)
//!   and from real panics (134, 139, …). Tests assert on this code.
//! - `_exit` writes a marker file before exiting so the harness can verify
//!   the *intended* crash point fired, not some unrelated abort.

/// Inject a crash point at the call site. No-op without the `crash-points`
/// feature.
///
/// Pass a constant from [`points`] rather than an inline literal — the
/// constant is also what the harness reads via `HANDOFF_CRASH_AT`, so using
/// the const eliminates spelling drift between library and test code.
#[macro_export]
macro_rules! crash_here {
    ($point:expr) => {
        // Dispatched through [`maybe_crash`] so the `cfg(feature)` branch is
        // resolved inside `handoff` (where the feature is declared) instead
        // of at each downstream call site. Without this indirection, every
        // crate that calls `crash_here!` would see `unexpected cfg feature`
        // warnings from check-cfg.
        $crate::crash::maybe_crash($point)
    };
}

/// Canonical crash-point names. Constants instead of an enum so the macro can
/// accept a literal at the call site and the value matches the env var
/// without any conversion layer.
pub mod points {
    // Supervisor side — `perform_handoff` in `supervisor.rs`.
    pub const S_AFTER_O_HELLO: &str = "s-after-o-hello";
    pub const S_AFTER_SPAWN_SUCCESSOR: &str = "s-after-spawn-successor";
    pub const S_AFTER_N_HELLO: &str = "s-after-n-hello";
    pub const S_AFTER_PREPARE_SENT: &str = "s-after-prepare-sent";
    pub const S_AFTER_DRAINED_RECV: &str = "s-after-drained-recv";
    pub const S_AFTER_SEAL_REQUEST_SENT: &str = "s-after-seal-request-sent";
    pub const S_AFTER_SEAL_COMPLETE_RECV: &str = "s-after-seal-complete-recv";
    pub const S_AFTER_BEGIN_SENT: &str = "s-after-begin-sent";
    pub const S_AFTER_READY_RECV: &str = "s-after-ready-recv";
    pub const S_AFTER_COMMIT_SENT: &str = "s-after-commit-sent";
    pub const S_AFTER_JOURNAL_CLEAR: &str = "s-after-journal-clear";

    // Incumbent side — `run_session_loop` in `incumbent.rs`.
    pub const O_AFTER_DRAINED_SENT: &str = "o-after-drained-sent";
    pub const O_AFTER_SEAL_FLOCK_RELEASED: &str = "o-after-seal-flock-released";
    pub const O_AFTER_SEAL_COMPLETE_SENT: &str = "o-after-seal-complete-sent";
    pub const O_AFTER_COMMIT_RECV: &str = "o-after-commit-recv";
}

/// If `HANDOFF_CRASH_AT == point`, write a marker file and immediately
/// `_exit(99)`. Otherwise return. No-op when the `crash-points` feature is
/// disabled (the entire body is gated by `cfg!`).
///
/// The marker file lets the harness distinguish "crashed at the right point"
/// from "crashed somewhere else" — without it, a test that asserts
/// "supervisor crashed at after-commit" can't tell whether the crash was
/// intentional or a bug. The marker path is `$HANDOFF_CRASH_MARKER_DIR/
/// crashed-<role>.marker` when both env vars are set; if the marker dir is
/// unset, the crash still fires but is unmarked (used for ad-hoc debugging).
#[inline]
pub fn maybe_crash(point: &str) {
    if !cfg!(feature = "crash-points") {
        // Keep the argument referenced so call sites that import the points
        // module aren't flagged as `unused_imports` when the feature is off.
        let _ = point;
        return;
    }
    let want = match std::env::var("HANDOFF_CRASH_AT") {
        Ok(v) => v,
        Err(_) => return,
    };
    if want != point {
        return;
    }

    if let Ok(dir) = std::env::var("HANDOFF_CRASH_MARKER_DIR") {
        let role = std::env::var("HANDOFF_CRASH_ROLE").unwrap_or_else(|_| "unknown".into());
        let marker = std::path::Path::new(&dir).join(format!("crashed-{role}.marker"));
        let _ = std::fs::write(&marker, point);
    }

    // SAFETY: `_exit` is an async-signal-safe libc call that terminates the
    // process without running Rust destructors. We invoke it intentionally
    // to simulate SIGKILL.
    unsafe { libc::_exit(99) };
}
