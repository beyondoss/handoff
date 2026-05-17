//! Supervisor crashes mid-handoff. The Incumbent must detect the disconnect
//! and, if it had sealed but not committed, resume serving by re-acquiring
//! the flock and calling `resume_after_abort`.

mod common;

use std::thread;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::{MockDrainable, connect_with_retry};

#[test]
fn disconnect_after_seal_triggers_resume() {
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

    // "Supervisor crash" — just drop the socket.
    drop(stream);

    // The serve loop should detect the disconnect, re-acquire the flock, and
    // call resume_after_abort. We then verify by opening a fresh session and
    // running a successful handoff against it.
    let mut stream = connect_with_retry(&sock_path);
    let (_v, _hello) = read_message(&mut stream).unwrap();
    let new_id = HandoffId::new();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::HelloAck {
            proto_version_chosen: PROTO_MAX,
            handoff_id: new_id,
        },
    )
    .unwrap();
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

    let s = state.lock().unwrap();
    assert_eq!(
        s.resumed, 1,
        "resume_after_abort should have been called once"
    );
    drop(s);

    drop(stream);
    drop(server_thread);
}
