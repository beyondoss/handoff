//! O's seal returns an error mid-handoff: O sends SealFailed, retains flock,
//! and is ready to accept a future PrepareHandoff.

mod common;

use std::thread;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::{MockDrainable, connect_with_retry};

#[test]
fn seal_failure_retains_flock_and_allows_retry() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("control.sock");
    let data_dir = temp.path().join("data");

    let lock = DataDirLock::acquire(&data_dir).unwrap();
    let incumbent = Incumbent::bind_cold_start(&sock_path, lock).unwrap();

    let drainable = MockDrainable::default();
    let state = drainable.state.clone();
    {
        // Configure the mock to fail seal the first time.
        state.lock().unwrap().seal_should_fail = true;
    }
    let server_thread = thread::spawn(move || incumbent.serve(drainable));

    let mut stream = connect_with_retry(&sock_path);
    let (_v, _hello) = read_message(&mut stream).unwrap();
    let handoff_id = HandoffId::new();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::HelloAck {
            proto_version_chosen: PROTO_MAX,
            handoff_id,
        },
    )
    .unwrap();

    // Drain.
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::PrepareHandoff {
            handoff_id,
            successor_pid: 9999,
            deadline_ms: 5000,
            drain_grace_ms: 1000,
        },
    )
    .unwrap();
    let (_, _) = read_message(&mut stream).unwrap();

    // Seal — will fail per the mock config.
    write_message(&mut stream, PROTO_MAX, &Message::SealRequest { handoff_id }).unwrap();
    let (_, msg) = read_message(&mut stream).unwrap();
    match msg {
        Message::SealFailed {
            handoff_id: id,
            error,
            ..
        } => {
            assert_eq!(id, handoff_id);
            assert!(error.contains("mock seal failure"), "got: {error}");
        }
        other => panic!("expected SealFailed, got {other:?}"),
    }

    // Flock must NOT have been released — verify by trying to acquire it.
    match DataDirLock::acquire(&data_dir) {
        Err(handoff::Error::LockHeld { .. }) => {} // expected
        other => panic!("expected LockHeld, got {other:?}"),
    }

    // After SealFailed, the incumbent must have asked the consumer to restart
    // accepting connections — otherwise O sits idle while the flock is still
    // held.
    assert_eq!(
        state.lock().unwrap().resumed,
        1,
        "resume_after_abort should fire on SealFailed so O can keep accepting"
    );

    // Configure mock to succeed next time, then retry handoff.
    state.lock().unwrap().seal_should_fail = false;
    let new_id = HandoffId::new();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::PrepareHandoff {
            handoff_id: new_id,
            successor_pid: 9998,
            deadline_ms: 5000,
            drain_grace_ms: 1000,
        },
    )
    .unwrap();
    let (_, drained) = read_message(&mut stream).unwrap();
    assert!(matches!(drained, Message::Drained { .. }));
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::SealRequest { handoff_id: new_id },
    )
    .unwrap();
    let (_, msg) = read_message(&mut stream).unwrap();
    assert!(matches!(msg, Message::SealComplete { .. }));
    assert!(state.lock().unwrap().sealed);

    drop(stream);
    drop(server_thread);
}
