//! Slow-but-progressing consumer hooks must not trip supervisor timeouts.
//!
//! The supervisor uses a two-tier timeout: a per-recv "liveness" timeout
//! (10s — heartbeats reset it) and an overall wall-clock cap (configured
//! via `SpawnSpec::deadline`, 5 minutes default). The incumbent spawns a
//! background thread during `Drainable::drain` and `Drainable::seal` that
//! emits a `Heartbeat` frame every 2s. The two together mean a consumer
//! whose `seal` legitimately takes 15s — or 5 minutes — completes the
//! handoff successfully, as long as it doesn't go fully unresponsive for
//! >10s at a stretch.
//!
//! This test reproduces the scenario the static-timeout design used to
//! mishandle: a 15-second seal under default-ish timeouts.

use std::time::Duration;

use handoff_tests::fixture;

const SPAWN: Duration = Duration::from_secs(5);
const HANDOFF: Duration = Duration::from_secs(45);

/// `Drainable::seal` takes 15 seconds; the handoff must still commit.
/// Without the heartbeat thread + per-recv liveness timeout, the
/// supervisor would have given up around the 10-second mark (the old
/// static `seal_timeout` clamped to wall-clock-remaining).
#[test]
fn fifteen_second_seal_still_commits() {
    let fx = fixture!();
    let _primitive = fx
        .cold_start_primitive()
        .seal_delay(Duration::from_secs(15))
        .spawn(SPAWN);

    let started = std::time::Instant::now();
    let exit = fx.perform_handoff().run(HANDOFF);
    let elapsed = started.elapsed();

    exit.assert_clean_exit();
    assert!(fx.marker_exists("seal-called"));
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(!fx.journal_present(), "journal cleared on clean commit");

    // Sanity check that we actually waited the full seal — otherwise the
    // test would pass for the wrong reason.
    assert!(
        elapsed >= Duration::from_secs(14),
        "elapsed was {elapsed:?} — the seal delay didn't fire"
    );
}

/// Same shape, but on the drain hook. Heartbeats during a long-running
/// drain must also keep the supervisor patient.
#[test]
fn long_drain_still_commits() {
    let fx = fixture!();
    let _primitive = fx
        .cold_start_primitive()
        .drain_delay(Duration::from_secs(12))
        .spawn(SPAWN);

    let exit = fx.perform_handoff().run(HANDOFF);

    exit.assert_clean_exit();
    assert!(fx.marker_exists("drain-called"));
    assert!(fx.marker_exists("seal-called"));
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(!fx.journal_present());
}
