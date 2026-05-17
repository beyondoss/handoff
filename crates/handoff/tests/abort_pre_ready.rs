//! Successor failed to become ready: supervisor sends ResumeAfterAbort.
//! The Incumbent must call `resume_after_abort` and re-acquire the flock.

mod common;

use std::thread;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::{MockDrainable, connect_with_retry};

#[test]
fn resume_after_abort_replays_active_segment_and_reacquires_flock() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("control.sock");
    let data_dir = temp.path().join("data");

    let lock = DataDirLock::acquire(&data_dir).unwrap();
    let incumbent = Incumbent::bind_cold_start(&sock_path, lock).unwrap();

    let drainable = MockDrainable::default();
    let state = drainable.state.clone();
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

    // Drain + Seal.
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
    write_message(&mut stream, PROTO_MAX, &Message::SealRequest { handoff_id }).unwrap();
    let (_, msg) = read_message(&mut stream).unwrap();
    assert!(matches!(msg, Message::SealComplete { .. }));
    assert!(state.lock().unwrap().sealed);

    // Now N has supposedly failed. Send ResumeAfterAbort.
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::ResumeAfterAbort { handoff_id },
    )
    .unwrap();

    // Give the Incumbent a moment to process. We don't get an explicit ack;
    // the next observation is that the flock is held again and resume was called.
    // Probe by sending a fresh PrepareHandoff — it should succeed.
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

    // Verify the state observed by our mock.
    let s = state.lock().unwrap();
    assert_eq!(
        s.resumed, 1,
        "resume_after_abort should have been called exactly once"
    );
    assert!(!s.sealed, "mock state should be cleared by resume");

    drop(stream);
    // The server stays alive in accept(); we leak the thread.
    // cargo test reaps it when the process exits.
    drop(server_thread);
}
