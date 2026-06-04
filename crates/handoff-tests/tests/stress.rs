//! Repeated-handoff stress test.
//!
//! Runs many consecutive handoffs against a single cold-started primitive
//! (each handoff promotes the previous successor into the incumbent role,
//! the way a production rolling-deploy would). Asserts on three things
//! across the run:
//!
//!  - Every handoff commits cleanly.
//!  - The test process's open-FD count stays stable (no parent-side FD
//!    leaks from socketpair/listener/log handles).
//!  - The journal is empty between handoffs.
//!
//! This is the closest CI can get to a "soak test" — it catches FD/zombie
//! leaks and accumulation bugs that single-shot tests miss.

use std::time::Duration;

use handoff_tests::fixture;

const SPAWN: Duration = Duration::from_secs(5);
const HANDOFF: Duration = Duration::from_secs(15);

/// Number of consecutive handoffs to run. Tuned to take ~30s in CI while
/// still being long enough to surface accumulating-leak patterns: an FD
/// leak of 1 per iteration would be at 100, an O(n²) tempfile leak would
/// be at ~5000 files.
const ITERATIONS: usize = 100;

/// Tolerance for the open-FD delta between start and end. Kernels and
/// test harnesses may legitimately move a few FDs around (allocator
/// internals, tracing subscriber). A leak of 1 FD per handoff would be at
/// `ITERATIONS` here — that's far above this slack.
const FD_DELTA_TOLERANCE: i64 = 16;

#[test]
fn many_handoffs_no_resource_leaks() {
    let fx = fixture!();
    let _primitive = fx.cold_start_primitive().spawn(SPAWN);

    let baseline_fds = count_open_fds();

    for i in 0..ITERATIONS {
        let exit = fx.perform_handoff().run(HANDOFF);
        assert!(
            exit.status.success(),
            "iteration {i}: handoff did not commit, exit = {:?}",
            exit.status
        );
        assert!(
            !fx.journal_present(),
            "iteration {i}: journal must be cleared after a clean handoff"
        );
    }

    let final_fds = count_open_fds();
    let delta = final_fds as i64 - baseline_fds as i64;
    assert!(
        delta.abs() <= FD_DELTA_TOLERANCE,
        "FD count drifted by {delta} (baseline {baseline_fds}, final {final_fds}) \
         over {ITERATIONS} handoffs — likely a parent-side leak"
    );
}

/// Count of open file descriptors in the test process. Reads `/dev/fd`
/// directly so it captures everything — not just FDs we know about.
/// `/dev/fd` is the portable spelling of the per-process FD directory: a
/// symlink to `/proc/self/fd` on Linux, a real fdescfs on macOS and
/// FreeBSD. The directory entry itself opens an FD during enumeration; we
/// measure with the same method on both sides so the bias cancels.
fn count_open_fds() -> usize {
    std::fs::read_dir("/dev/fd")
        .expect("/dev/fd should exist on any supported Unix")
        .count()
}
