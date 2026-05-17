//! Crash-injection matrix: spawn real subprocesses, kill one at a specific
//! protocol boundary, and assert the system converges to a valid state.
//!
//! Each test follows the same shape:
//!
//! 1. Cold-start O.
//! 2. Run the supervisor with a named crash injection.
//! 3. Observe the supervisor's exit + assert it crashed at the right point.
//! 4. Assert post-crash invariants (flock, journal, marker files).
//! 5. (Where applicable) verify recovery by running a clean handoff.
//!
//! Crash points live in [`handoff_tests::points`] (library) and
//! [`handoff_tests::primitive_points`] (fixture-binary).

use std::time::Duration;

use handoff_tests::{FlockState, Phase, fixture, points, primitive_points, read_marker_value};

const SPAWN: Duration = Duration::from_secs(5);
const HANDOFF: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------- supervisor

/// S crashes after sending `PrepareHandoff`. O is mid-drain (or about to be);
/// the socketpair closes when S dies, so O sees EOF before sealing. The
/// drained-not-sealed cleanup path must fire and O stays alive holding the
/// flock.
#[test]
fn supervisor_crashes_after_prepare_sent() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_PREPARE_SENT)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_PREPARE_SENT);

    // O is still serving — it drained and then resumed when S vanished.
    assert!(primitive.alive(), "incumbent must survive S crash pre-seal");
    assert!(fx.marker_exists("drain-called"));
    assert!(
        fx.marker_exists("resume-called"),
        "drained-without-seal cleanup should call resume_after_abort"
    );

    // Flock still held by O.
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => {
            assert_eq!(pid as u32, o_pid, "O should still hold its own flock");
        }
        other => panic!("flock not held by live O: {other:?}"),
    }

    // Journal phase is Negotiating (last value S wrote before the crash).
    assert_eq!(fx.journal_phase(), Some(Phase::Negotiating));
}

/// S crashes between receiving `SealComplete` and sending `Begin`. O has
/// already released the flock and is in the sealed state. The supervisor
/// vanishing surfaces as EOF on O's sealed-state branch → O re-acquires the
/// flock and resumes.
#[test]
fn supervisor_crashes_after_seal_complete_recv() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_SEAL_COMPLETE_RECV)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_SEAL_COMPLETE_RECV);

    assert!(primitive.alive(), "O must survive S crash post-seal");
    assert!(fx.marker_exists("seal-called"));
    assert!(
        fx.marker_exists("resume-called"),
        "sealed-then-EOF should trigger resume_after_abort"
    );

    // O re-acquired its flock after sealing.
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => {
            assert_eq!(pid as u32, o_pid, "O should re-hold the flock");
        }
        other => panic!("flock not held by live O after sealed-EOF recovery: {other:?}"),
    }

    // Journal phase is Draining (the value before SealComplete was journaled
    // as Sealing).
    assert_eq!(fx.journal_phase(), Some(Phase::Draining));
}

/// S crashes after sending `Commit` to O. This is the architectural "gap":
/// O exits cleanly, N becomes the new incumbent, and the journal records
/// `AwaitingReady` (S crashed *before* journaling `Committed`).
///
/// We verify the gap is recoverable: a fresh supervisor calling
/// `resume_from_journal` reaches N, clears the journal, and a subsequent
/// handoff against N commits cleanly.
#[test]
fn supervisor_crashes_after_commit_orphans_n_but_recovers() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_COMMIT_SENT)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_COMMIT_SENT);

    // O received Commit and exited cleanly; N is now the live incumbent.
    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    o_exit.assert_clean_exit();

    let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
        .expect("successor wrote its pid")
        .parse()
        .expect("pid is a u32");
    assert_ne!(n_pid, o_pid);

    // N holds the flock; the journal is mid-handoff (AwaitingReady is the
    // last phase S journaled before reading Ready and sending Commit).
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, n_pid),
        other => panic!("flock not held by N after S-after-commit crash: {other:?}"),
    }
    assert_eq!(
        fx.journal_phase(),
        Some(Phase::AwaitingReady),
        "S crashed before journaling Committed"
    );

    // Recovery: a fresh supervisor (no crash injection) cleans the journal
    // and successfully drives another handoff against N.
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
    assert!(
        !fx.journal_present(),
        "fresh supervisor must clear the journal after the second handoff"
    );
    assert!(fx.marker_exists("supervisor-resume-from-journal"));
    assert!(fx.marker_exists("supervisor-committed"));
}

// ----------------------------------------------------------------- successor

/// N crashes before announcing `Ready`. S waits for Ready, reads EOF or
/// times out, aborts the handoff, and sends `ResumeAfterAbort` to O.
#[test]
fn successor_crashes_before_ready() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_successor_at(primitive_points::N_BEFORE_ANNOUNCE_READY)
        .run(HANDOFF);
    // Supervisor returns ExitCode 2 (aborted) — we don't expect S to crash.
    assert_eq!(
        exit.status.code(),
        Some(2),
        "supervisor should return aborted (exit code 2), got {:?}",
        exit.status
    );

    // N crashed at the requested point, recorded its marker.
    assert!(fx.marker_exists("crashed-successor"));

    // O is still alive; resume marker fired.
    assert!(primitive.alive(), "O should survive N crash");
    assert!(fx.marker_exists("resume-called"));

    // O holds the flock; journal cleared (supervisor returned cleanly).
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O after N crash: {other:?}"),
    }
    assert!(!fx.journal_present());
    assert!(fx.marker_exists("supervisor-aborted"));
}

// ----------------------------------------------------------------- incumbent

/// O's `seal()` returns an error. S receives `SealFailed`, aborts N, and
/// returns aborted. O retains the flock and keeps serving (verified via
/// `resume-called` marker + flock state).
#[test]
fn incumbent_seal_failure_keeps_o_alive() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().seal_fails_once().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx.perform_handoff().run(HANDOFF);
    assert_eq!(
        exit.status.code(),
        Some(2),
        "supervisor should return aborted (exit code 2), got {:?}",
        exit.status
    );

    assert!(primitive.alive(), "O survives seal-failure abort");
    assert!(fx.marker_exists("seal-called"));
    assert!(
        fx.marker_exists("resume-called"),
        "seal_failure must trigger O's resume_after_abort"
    );

    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O after seal failure: {other:?}"),
    }
    assert!(!fx.journal_present());
}

// ---------------------------------------------------------- recovery via journal

/// The supervisor's `resume_from_journal` path is fired on every supervisor
/// startup. After a clean prior run there's no journal, so the marker must
/// NOT exist. After a crashed run there *is* a journal, and the next
/// supervisor invocation must observe it.
#[test]
fn resume_from_journal_fires_only_after_crashed_run() {
    let fx = fixture!();
    let _primitive = fx.cold_start_primitive().spawn(SPAWN);

    // First handoff: clean. resume_from_journal should be a no-op.
    let first = fx.perform_handoff().run(HANDOFF);
    first.assert_clean_exit();
    assert!(
        !fx.marker_exists("supervisor-resume-from-journal"),
        "first supervisor must not see a prior journal"
    );

    // Second handoff: crash mid-flight, leaving a journal entry behind.
    let crash = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_DRAINED_RECV)
        .run(HANDOFF);
    crash.assert_crashed_at(&fx, points::S_AFTER_DRAINED_RECV);
    assert_eq!(fx.journal_phase(), Some(Phase::Negotiating));

    // Third supervisor: must call resume_from_journal and observe the
    // crashed run's leftover state.
    let resumed = fx.perform_handoff().run(HANDOFF);
    resumed.assert_clean_exit();
    assert!(
        fx.marker_exists("supervisor-resume-from-journal"),
        "supervisor must report observing the prior journal"
    );
    assert!(
        !fx.journal_present(),
        "journal must be cleared after recovery"
    );
}
