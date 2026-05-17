//! End-to-end happy path: cold-start O, run one full handoff, observe N
//! become the new incumbent. Validates the harness itself by exercising
//! every component without crash injection.

use std::time::Duration;

use handoff_tests::{FlockState, fixture};

#[test]
fn full_handoff_commits_and_n_serves() {
    let fx = fixture!();
    let primitive = fx.cold_start_primitive().spawn(Duration::from_secs(5));
    let o_pid = primitive.pid;

    // No crash injection — supervisor should run to completion and commit.
    let exit = fx.perform_handoff().run(Duration::from_secs(15));
    exit.assert_clean_exit();

    // Both phases must have fired on O.
    assert!(fx.marker_exists("drain-called"), "O should have drained");
    assert!(fx.marker_exists("seal-called"), "O should have sealed");

    // N reached every lifecycle milestone.
    assert!(fx.marker_exists("successor-handshake"));
    assert!(fx.marker_exists("successor-begin"));
    assert!(fx.marker_exists("successor-ready"));

    // Supervisor wrote the committed marker; not the aborted one.
    assert!(fx.marker_exists("supervisor-committed"));
    assert!(!fx.marker_exists("supervisor-aborted"));

    // Journal cleared on commit.
    assert!(
        !fx.journal_present(),
        "journal should be cleared after a successful commit"
    );

    // O exited cleanly on Commit; flock now held by N.
    let _ = primitive.wait_exit(Duration::from_secs(3));
    let _ = o_pid;
    match fx.flock_state() {
        FlockState::Held { alive: true, pid } => {
            assert_ne!(pid as u32, o_pid, "flock holder should not be the old O");
        }
        other => panic!("expected flock held by live N, got {other:?}"),
    }

    // Control socket has a server (N) again.
    assert!(fx.control_socket_serves(), "N should be serving");
}
