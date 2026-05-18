//! Wire-transit race on phase reads.
//!
//! Three reads in the supervisor share the same race shape — the
//! supervisor's read deadline is anchored to a peer-side budget, but the
//! peer's clock for that budget starts *after* `δ_net + δ_deserialize`
//! and the reply still has to traverse another `δ_net + δ_serialize` on
//! the way back. If the peer runs to (or slightly past) its budget, the
//! reply lands on the wire after the supervisor's read deadline expires.
//! The fix is to extend the supervisor's read deadline by `WIRE_SLACK`
//! beyond the peer's budget.
//!
//! Three tests, one per affected read:
//!
//!  - **`Drained`** (drain phase): peer budget is `drain_grace`.
//!  - **`SealComplete`** (seal phase): peer has no internal cap; the
//!    bound is the overall `total_deadline_at`. `seal()` may run to the
//!    cap, with `SealComplete` arriving slightly later.
//!  - **`Ready`** (begin-ready phase): N has no internal cap for
//!    `announce_and_bind`; same shape, anchored on `total_deadline_at`.
//!
//! Each test makes the peer overshoot its anchor by a small fixed margin
//! that fits inside `WIRE_SLACK`. Without the fix, the supervisor times
//! out; with the fix, the read picks up the in-flight reply.

use std::time::Duration;

use handoff_tests::fixture;

const SPAWN: Duration = Duration::from_secs(5);
const HANDOFF: Duration = Duration::from_secs(30);

/// Overshoot the peer-side anchor by this much. Must be small enough to
/// fit inside `WIRE_SLACK` (1 s) and large enough to be unambiguously past
/// the cap under all realistic scheduling — 150 ms gives ~6× margin in
/// both directions.
const OVERSHOOT_MS: u64 = 150;

const DRAIN_GRACE_MS: u64 = 300;

#[test]
fn drained_in_flight_past_grace_must_not_race_the_supervisor() {
    let fx = fixture!();
    let _primitive = fx
        .cold_start_primitive()
        .drain_delay(Duration::from_millis(DRAIN_GRACE_MS + OVERSHOOT_MS))
        .spawn(SPAWN);

    let started = std::time::Instant::now();
    let exit = fx
        .perform_handoff()
        .drain_grace(Duration::from_millis(DRAIN_GRACE_MS))
        .run(HANDOFF);
    let elapsed = started.elapsed();

    exit.assert_clean_exit();
    assert!(fx.marker_exists("drain-called"));
    assert!(fx.marker_exists("seal-called"));
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(
        !fx.journal_present(),
        "journal must be cleared on clean commit"
    );

    // Sanity: drain actually overshot the grace. If it returned early, the
    // race wouldn't have been exercised and the test would pass for the
    // wrong reason.
    assert!(
        elapsed >= Duration::from_millis(DRAIN_GRACE_MS + OVERSHOOT_MS),
        "handoff finished in {elapsed:?} — drain did not run to its overshoot, \
         so this run did not exercise the wire-race path"
    );
}

/// `Drainable::seal` runs past `total_deadline_at` (the cap the supervisor
/// uses for the seal-wait loop). The resulting `SealComplete` lands on the
/// supervisor's read after the cap. Without `WIRE_SLACK` past
/// `total_deadline_at`, the supervisor aborts with `Timeout("SealComplete")`
/// on a message already in flight.
#[test]
fn seal_complete_in_flight_past_deadline_must_not_race_the_supervisor() {
    let fx = fixture!();
    // Seal sleeps long enough that it finishes past the overall handoff
    // deadline. Drain runs fast so almost all of `DEADLINE_MS` is spent
    // in seal.
    const DEADLINE_MS: u64 = 1500;
    const SEAL_DELAY_MS: u64 = DEADLINE_MS + OVERSHOOT_MS;

    let _primitive = fx
        .cold_start_primitive()
        .seal_delay(Duration::from_millis(SEAL_DELAY_MS))
        .spawn(SPAWN);

    let started = std::time::Instant::now();
    let exit = fx
        .perform_handoff()
        .deadline(Duration::from_millis(DEADLINE_MS))
        .run(HANDOFF);
    let elapsed = started.elapsed();

    exit.assert_clean_exit();
    assert!(fx.marker_exists("seal-called"));
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(
        !fx.journal_present(),
        "journal must be cleared on clean commit"
    );
    // Sanity: total elapsed must exceed `total_deadline_at` — otherwise
    // seal returned early and the in-flight-past-cap path wasn't taken.
    assert!(
        elapsed >= Duration::from_millis(DEADLINE_MS),
        "handoff finished in {elapsed:?} — seal didn't run past the deadline, \
         so this run did not exercise the wire-race path"
    );
}

/// `announce_and_bind` on N completes past `total_deadline_at`; `Ready`
/// lands on the supervisor's read after the cap. Same shape as the seal
/// race, on the `n_stream` side. Without `WIRE_SLACK`, the supervisor
/// aborts with `Timeout("Ready")` on a message already in flight.
#[test]
fn ready_in_flight_past_deadline_must_not_race_the_supervisor() {
    let fx = fixture!();
    // N stalls before `announce_and_bind` long enough that `Ready` is
    // written past `total_deadline_at`. Drain and seal both run fast so
    // most of the budget is consumed by N's stall.
    const DEADLINE_MS: u64 = 1500;
    const READY_DELAY_MS: u64 = DEADLINE_MS + OVERSHOOT_MS;

    let _primitive = fx.cold_start_primitive().spawn(SPAWN);

    let started = std::time::Instant::now();
    let exit = fx
        .perform_handoff()
        .deadline(Duration::from_millis(DEADLINE_MS))
        .ready_delay(Duration::from_millis(READY_DELAY_MS))
        .run(HANDOFF);
    let elapsed = started.elapsed();

    exit.assert_clean_exit();
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(fx.marker_exists("successor-ready"));
    assert!(
        !fx.journal_present(),
        "journal must be cleared on clean commit"
    );
    assert!(
        elapsed >= Duration::from_millis(DEADLINE_MS),
        "handoff finished in {elapsed:?} — N didn't stall past the deadline, \
         so this run did not exercise the wire-race path"
    );
}
