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

/// S crashes right after the O-side `Hello`/`HelloAck` exchange — before
/// spawning N. O sees EOF in `Active` state, closes the session cleanly,
/// keeps serving on its existing flock. No `successor-pid` marker exists
/// because N was never spawned.
#[test]
fn supervisor_crashes_after_o_hello() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_O_HELLO)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_O_HELLO);

    assert!(
        primitive.alive(),
        "O survives S crash before any protocol work"
    );
    assert!(
        read_marker_value(&fx.markers, "successor-pid").is_none(),
        "N must never have been spawned"
    );
    assert!(!fx.marker_exists("drain-called"));
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O: {other:?}"),
    }
    // Journal was never written.
    assert!(!fx.journal_present());

    // A subsequent handoff against O succeeds.
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
}

/// S crashes between `spawn_successor` and the N-side `Hello` exchange. N
/// is up and running but its first I/O on the socketpair sees S's closed
/// end — `handshake` returns `BrokenPipe`, N exits. O is undisturbed.
#[test]
fn supervisor_crashes_after_spawn_successor() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_SPAWN_SUCCESSOR)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_SPAWN_SUCCESSOR);

    assert!(primitive.alive(), "O survives S crash post-spawn");
    // N was spawned and wrote its pid marker before attempting handshake.
    assert!(
        read_marker_value(&fx.markers, "successor-pid").is_some(),
        "N must have written successor-pid before handshake"
    );
    // handshake either never completed (write to dead socket) or N had not
    // yet reached it before EOF was observed — either way, no marker.
    assert!(!fx.marker_exists("successor-handshake"));
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O: {other:?}"),
    }
    assert!(!fx.journal_present());

    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
}

/// S crashes between the N-side `HelloAck` and the first `PrepareHandoff`
/// frame. N has completed `handshake`, is blocked in `wait_for_begin`, and
/// reads EOF. O has done the `HelloAck` exchange but seen no protocol step,
/// returns `Closed`, and keeps serving.
#[test]
fn supervisor_crashes_after_n_hello() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_N_HELLO)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_N_HELLO);

    assert!(primitive.alive(), "O survives S crash post-N-hello");
    assert!(fx.wait_marker("successor-handshake", Duration::from_secs(3)));
    assert!(
        !fx.marker_exists("successor-begin"),
        "N must not have observed Begin (it was never sent)"
    );
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O: {other:?}"),
    }
    assert!(!fx.journal_present());

    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
}

/// S crashes immediately after writing `SealRequest`. O receives it (the
/// frame is already in the kernel buffer), runs `seal()`, releases the
/// flock, and tries to send `SealComplete` — the write fails because S is
/// gone. O then sees the session error in `sealed` state and re-acquires
/// the flock via the recovery path. End state: O alive, holds flock,
/// resumed; journal entry left at `Draining` (the value before
/// `SealRequest` was sent) for a fresh supervisor to clean up.
#[test]
fn supervisor_crashes_after_seal_request_sent() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_SEAL_REQUEST_SENT)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_SEAL_REQUEST_SENT);

    // O processed the seal (it arrived in the kernel buffer before the
    // crash flushed the connection) and then recovered.
    assert!(primitive.alive(), "O survives S crash after SealRequest");
    assert!(fx.marker_exists("drain-called"));
    assert!(fx.wait_marker("seal-called", Duration::from_secs(3)));
    assert!(
        fx.wait_marker("resume-called", Duration::from_secs(3)),
        "sealed-then-EOF must drive the resume path"
    );

    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O after seal+EOF recovery: {other:?}"),
    }
    assert_eq!(fx.journal_phase(), Some(Phase::Draining));

    // Recovery handoff against O — must clean the journal and commit.
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
    assert!(!fx.journal_present());
    assert!(fx.marker_exists("supervisor-resume-from-journal"));
}

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

/// S crashes immediately after writing `Begin` to N. This crash point
/// has a genuine race that the system must converge from:
///
/// - **Outcome A (common)**: N reads `Begin` from the buffer, acquires
///   the flock (O released it during seal), then writes `Ready` — which
///   *succeeds* because the small frame fits in the socket buffer
///   despite S having closed its end. N completes `announce_and_bind`
///   and becomes the new incumbent. O exits via the recovery path
///   (can't re-acquire the flock, retries briefly, gives up).
///
/// - **Outcome B (less common)**: the kernel notices the closed peer
///   before N's `Ready` write completes; the write returns `EPIPE`, N
///   exits, releasing the flock. O's recovery path (with the
///   `acquire_with_short_retry`) eventually acquires the flock and
///   resumes serving.
///
/// Both outcomes leave the system with one live incumbent holding the
/// flock. The test asserts convergence, not which path was taken.
#[test]
fn supervisor_crashes_after_begin_sent_converges() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_BEGIN_SENT)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_BEGIN_SENT);

    assert!(fx.wait_marker("successor-begin", Duration::from_secs(3)));

    // Wait for the system to settle: either O re-acquires the flock via
    // its recovery path (bounded by `RESUME_FLOCK_TIMEOUT` = 2s) or N
    // completes `announce_and_bind` and writes the `successor-ready`
    // marker. Poll for either signal so the test is not pinned to a
    // worst-case wall-clock sleep on slow CI.
    let convergence_deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let n_acquired = fx.marker_exists("successor-ready");
        let o_recovered = matches!(
            fx.flock_state(),
            FlockState::Held { pid, alive: true } if pid as u32 == o_pid
        );
        if n_acquired || o_recovered {
            break;
        }
        if std::time::Instant::now() >= convergence_deadline {
            panic!(
                "system did not converge after S_AFTER_BEGIN_SENT: flock={:?}, successor-ready={}",
                fx.flock_state(),
                fx.marker_exists("successor-ready")
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    match fx.flock_state() {
        FlockState::Held { pid, alive: true } if pid as u32 == o_pid => {
            // Outcome B: O recovered.
            assert!(
                fx.marker_exists("resume-called"),
                "O's recovery path must have run resume_after_abort"
            );
            // Journal could be either Sealing (S journaled it before
            // sending Begin) — never AwaitingReady because S journals
            // that *after* the crash point.
            assert_eq!(fx.journal_phase(), Some(Phase::Sealing));
        }
        FlockState::Held { pid, alive: true } => {
            // Outcome A: N took over.
            let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
                .expect("successor wrote its pid")
                .parse()
                .expect("pid is a u32");
            assert_eq!(pid as u32, n_pid);
            assert!(
                fx.marker_exists("successor-ready"),
                "N must have completed announce_and_bind to be the new incumbent"
            );
            assert_eq!(fx.journal_phase(), Some(Phase::Sealing));
        }
        other => panic!(
            "expected one live incumbent holding the flock after S_AFTER_BEGIN_SENT, \
             got {other:?}"
        ),
    }

    // A fresh supervisor handoff must succeed regardless of which path
    // we took.
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
    assert!(!fx.journal_present());
}

/// S crashes after receiving `Ready` but before sending `Commit`. N has
/// already taken over (it called `announce_and_bind`, which acquires the
/// flock and rebinds the control socket) by the time S reads `Ready`. So
/// when S vanishes here, N is the live incumbent and O — still alive in
/// `sealed` state — sees EOF, tries to re-acquire the flock, fails because
/// N holds it, and exits. The journal records `AwaitingReady`, which the
/// next supervisor invocation must clean up.
#[test]
fn supervisor_crashes_after_ready_recv_n_takes_over() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_READY_RECV)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_READY_RECV);

    // N completed `announce_and_bind` before S crashed.
    assert!(fx.wait_marker("successor-ready", Duration::from_secs(3)));
    let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
        .expect("successor wrote its pid")
        .parse()
        .expect("pid is a u32");
    assert_ne!(n_pid, o_pid);

    // O exits because it can no longer hold the flock. The exit may be
    // either a clean `Committed` (if O happened to read Commit before S
    // died — not possible at this crash point) or an error from the
    // flock re-acquire failing. We just require that O is gone.
    let _o_exit = primitive.wait_exit(Duration::from_secs(5));

    // N holds the flock; journal phase is `AwaitingReady` (last value S
    // journaled before reading Ready; Committed is journaled only after
    // Commit is sent).
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, n_pid),
        other => panic!("flock not held by N after S-after-ready crash: {other:?}"),
    }
    assert_eq!(fx.journal_phase(), Some(Phase::AwaitingReady));

    // Recovery: a fresh supervisor must clean the journal and run another
    // handoff against N successfully.
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
    assert!(!fx.journal_present());
    assert!(fx.marker_exists("supervisor-resume-from-journal"));
    assert!(fx.marker_exists("supervisor-committed"));
}

/// S crashes after the journal-clear that follows `Committed`. By this
/// point O has already received `Commit` and exited, N is serving as the
/// new incumbent, and the journal is gone. From outside, this is
/// indistinguishable from a clean supervisor exit — the test exists as a
/// regression guardrail to confirm the journal is actually gone (not
/// stuck in some intermediate state) when the crash fires after the clear.
#[test]
fn supervisor_crashes_after_journal_clear() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_supervisor_at(points::S_AFTER_JOURNAL_CLEAR)
        .run(HANDOFF);
    exit.assert_crashed_at(&fx, points::S_AFTER_JOURNAL_CLEAR);

    // O received Commit and exited cleanly.
    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    o_exit.assert_clean_exit();

    // N is the new incumbent.
    let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
        .expect("successor wrote its pid")
        .parse()
        .expect("pid is a u32");
    assert_ne!(n_pid, o_pid);
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, n_pid),
        other => panic!("flock not held by N: {other:?}"),
    }
    assert!(
        !fx.journal_present(),
        "journal must be cleared by this crash point"
    );

    // Recovery handoff against N must NOT see a prior journal (it was cleared
    // before the crash fired).
    let recovery = fx.perform_handoff().run(HANDOFF);
    recovery.assert_clean_exit();
    assert!(
        !fx.marker_exists("supervisor-resume-from-journal"),
        "no journal was on disk to resume from"
    );
}

// ----------------------------------------------------------------- successor

/// N crashes before sending its `Hello` to S. S's
/// `exchange_hello_as_supervisor` for the successor reads EOF on the
/// socketpair and returns an error (bounded by `HELLO_READ_TIMEOUT` even
/// in the pathological case where N hangs instead of dying). O is
/// undisturbed — S has not yet sent it any protocol message past the
/// initial Hello exchange.
#[test]
fn successor_crashes_before_handshake() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_successor_at(primitive_points::N_BEFORE_HANDSHAKE)
        .run(HANDOFF);
    assert_eq!(
        exit.status.code(),
        Some(3),
        "supervisor should report perform_handoff Err (exit 3), got {:?}",
        exit.status
    );
    assert!(fx.marker_exists("crashed-successor"));
    assert!(!fx.marker_exists("successor-handshake"));

    assert!(primitive.alive(), "O survives N crash before handshake");
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O: {other:?}"),
    }
    // Negotiating is journaled only after both Hellos complete — neither
    // did, so no journal exists yet.
    assert!(!fx.journal_present());
}

/// N crashes after handshake while blocked in `wait_for_begin`. S
/// proceeds through PrepareHandoff/Drained/SealRequest/SealComplete, then
/// sends `Begin` and waits for `Ready` — but N is dead. The read returns
/// EOF, S takes the abort path, sends `ResumeAfterAbort` to O, and
/// returns aborted.
#[test]
fn successor_crashes_after_handshake() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_successor_at(primitive_points::N_AFTER_HANDSHAKE)
        .run(HANDOFF);
    assert_eq!(
        exit.status.code(),
        Some(2),
        "supervisor should report aborted (exit 2), got {:?}",
        exit.status
    );
    assert!(fx.marker_exists("crashed-successor"));
    assert!(fx.marker_exists("successor-handshake"));
    assert!(!fx.marker_exists("successor-begin"));

    assert!(primitive.alive(), "O survives N crash post-handshake");
    assert!(
        fx.marker_exists("resume-called"),
        "O must be told to resume after N is killed"
    );
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O: {other:?}"),
    }
    assert!(!fx.journal_present());
    assert!(fx.marker_exists("supervisor-aborted"));
}

/// N crashes after receiving `Begin` but before acquiring the flock. O
/// has just released the flock during seal; S is waiting for Ready,
/// reads EOF, abort path, ResumeAfterAbort to O, O re-acquires and
/// resumes serving.
#[test]
fn successor_crashes_after_begin() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx
        .perform_handoff()
        .crash_successor_at(primitive_points::N_AFTER_BEGIN)
        .run(HANDOFF);
    assert_eq!(exit.status.code(), Some(2), "{:?}", exit.status);
    assert!(fx.marker_exists("crashed-successor"));
    assert!(fx.marker_exists("successor-begin"));
    assert!(!fx.marker_exists("successor-ready"));

    assert!(primitive.alive(), "O survives N crash after Begin");
    assert!(fx.marker_exists("resume-called"));
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, o_pid),
        other => panic!("flock not held by live O after N crash + Resume: {other:?}"),
    }
    assert!(!fx.journal_present());
}

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

/// O crashes inside `Drainable::drain`. S is blocked in the drain-wait
/// `read_until`; the EOF surfaces as an error and `perform_handoff`
/// returns Err. `ChildGuard` kills N on the unwind. Journal phase
/// `Negotiating` (the last value journaled — written immediately after
/// both Hellos, before `PrepareHandoff`).
#[test]
fn incumbent_crashes_inside_drain() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        .crash_at(primitive_points::O_INSIDE_DRAIN)
        .spawn(SPAWN);

    let exit = fx.perform_handoff().run(HANDOFF);
    assert_eq!(
        exit.status.code(),
        Some(3),
        "supervisor should report perform_handoff Err (exit 3), got {:?}",
        exit.status
    );

    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(
        o_exit.status.code(),
        Some(99),
        "O should have crashed via injection, got {:?}",
        o_exit.status
    );
    assert!(fx.marker_exists("drain-called"));
    assert!(!fx.marker_exists("seal-called"));

    // O died holding the flock; kernel released on process death.
    fx.flock_state().assert_free();
    assert_eq!(fx.journal_phase(), Some(Phase::Negotiating));
}

/// O crashes inside `Drainable::seal`. The flock is still held by O
/// (release happens after `seal()` returns `Ok`); the kernel reclaims it
/// when O dies. S sees EOF in the seal-wait loop and errors out.
#[test]
fn incumbent_crashes_inside_seal() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        .crash_at(primitive_points::O_INSIDE_SEAL)
        .spawn(SPAWN);

    let exit = fx.perform_handoff().run(HANDOFF);
    assert_eq!(exit.status.code(), Some(3), "{:?}", exit.status);

    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(o_exit.status.code(), Some(99));
    assert!(fx.marker_exists("drain-called"));
    assert!(fx.marker_exists("seal-called"));

    fx.flock_state().assert_free();
    assert_eq!(fx.journal_phase(), Some(Phase::Draining));
}

/// O sends `Drained` then crashes — flock still held at the kernel level
/// (RAII drop is bypassed by `_exit`, but the kernel releases the flock
/// when the process dies). S reads `Drained` from the kernel buffer,
/// journals `Draining`, attempts `SealRequest` → write fails (closed
/// peer), reads back EOF, and propagates an error from
/// `perform_handoff`. `ChildGuard` kills N (which was sitting in
/// `wait_for_begin`).
#[test]
fn incumbent_crashes_after_drained_sent() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        .crash_at(points::O_AFTER_DRAINED_SENT)
        .spawn(SPAWN);

    let exit = fx.perform_handoff().run(HANDOFF);
    assert_eq!(exit.status.code(), Some(3), "{:?}", exit.status);

    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(o_exit.status.code(), Some(99));
    assert!(fx.marker_exists("drain-called"));
    assert!(!fx.marker_exists("seal-called"));
    // N never received Begin.
    assert!(!fx.marker_exists("successor-begin"));

    fx.flock_state().assert_free();
    assert_eq!(fx.journal_phase(), Some(Phase::Draining));
}

/// O crashes between releasing the flock and sending `SealComplete`. S
/// sees EOF on the seal-wait read and propagates an error from
/// `perform_handoff`; `ChildGuard` kills N. The data-dir flock ends up
/// free (kernel reaped it at O's death), so a fresh cold-start can
/// re-acquire and take over.
#[test]
fn incumbent_crashes_after_seal_flock_released() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        .crash_at(points::O_AFTER_SEAL_FLOCK_RELEASED)
        .spawn(SPAWN);

    let exit = fx.perform_handoff().run(HANDOFF);
    // S returned an error from perform_handoff (code 3 in the test
    // supervisor binary's exit-code mapping).
    assert_eq!(
        exit.status.code(),
        Some(3),
        "supervisor should report perform_handoff Err (exit 3), got {:?}",
        exit.status
    );

    // O died via the crash injection.
    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(
        o_exit.status.code(),
        Some(99),
        "incumbent should have crashed via injection, got {:?}",
        o_exit.status
    );

    // Flock is kernel-released (O exited via _exit which bypasses Drop,
    // but the kernel releases the flock on process death). A fresh
    // acquire from the test process succeeds, then drops cleanly.
    fx.flock_state().assert_free();

    // The journal recorded `Draining` (last value before SealRequest sent).
    assert_eq!(fx.journal_phase(), Some(Phase::Draining));
}

/// O crashes immediately after sending `SealComplete`. The interesting
/// flow: S reads `SealComplete` from the buffer, journals `Sealing`,
/// sends `Begin` to N, reads `Ready`, then tries to send `Commit` —
/// which fails because O is dead. The disarm-after-Ready fix means S
/// reports a committed handoff anyway (N is the legitimate new incumbent)
/// and the journal is cleared. Without that fix, this scenario would
/// have killed N alongside the dead O, leaving the system offline.
#[test]
fn incumbent_crashes_after_seal_complete_sent_n_still_takes_over() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        // O_AFTER_SEAL_COMPLETE_SENT is a *library* crash point (inside
        // `incumbent.rs::run_session_loop`), not a fixture point — pass
        // the const through the harness's `crash_at` channel.
        .crash_at(points::O_AFTER_SEAL_COMPLETE_SENT)
        .spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx.perform_handoff().run(HANDOFF);
    // The handoff succeeds despite O's mid-flight death.
    assert_eq!(
        exit.status.code(),
        Some(0),
        "handoff should commit even though O died after sending SealComplete; got {:?}",
        exit.status
    );

    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(
        o_exit.status.code(),
        Some(99),
        "O exits via crash injection"
    );

    // N is the new incumbent.
    let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
        .expect("successor wrote its pid")
        .parse()
        .expect("pid is a u32");
    assert_ne!(n_pid, o_pid);
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, n_pid),
        other => panic!("flock not held by N: {other:?}"),
    }
    assert!(
        !fx.journal_present(),
        "journal cleared on successful commit"
    );
    assert!(fx.marker_exists("supervisor-committed"));
}

/// O crashes inside its `Commit` handler, just before returning `Ok` to
/// exit cleanly. From S's perspective the handoff is fully committed
/// (the `Commit` write succeeded before O died). N is the new incumbent.
/// The only externally-visible difference from a clean handoff is O's
/// exit code.
#[test]
fn incumbent_crashes_after_commit_recv() {
    let fx = fixture!();
    let primitive = fx
        .cold_start_primitive()
        .crash_at(points::O_AFTER_COMMIT_RECV)
        .spawn(SPAWN);
    let o_pid = primitive.pid;

    let exit = fx.perform_handoff().run(HANDOFF);
    exit.assert_clean_exit();

    // O crashed via injection (rather than exiting cleanly from `serve`).
    let o_exit = primitive.wait_exit(Duration::from_secs(3));
    assert_eq!(o_exit.status.code(), Some(99));

    let n_pid: u32 = read_marker_value(&fx.markers, "successor-pid")
        .expect("successor wrote its pid")
        .parse()
        .expect("pid is a u32");
    assert_ne!(n_pid, o_pid);
    match fx.flock_state() {
        FlockState::Held { pid, alive: true } => assert_eq!(pid as u32, n_pid),
        other => panic!("flock not held by N: {other:?}"),
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
