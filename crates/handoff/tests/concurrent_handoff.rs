//! Second `PrepareHandoff` arriving with a different `handoff_id` while the
//! first is still active must be rejected. The Incumbent closes the session
//! (the supervisor sees disconnect).

mod common;

use std::thread;
use std::time::Duration;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::{MockDrainable, connect_with_retry};

#[test]
fn second_prepare_with_different_id_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("control.sock");
    let data_dir = temp.path().join("data");

    let lock = DataDirLock::acquire(&data_dir).unwrap();
    let incumbent = Incumbent::bind_cold_start(&sock_path, lock).unwrap();

    let drainable = MockDrainable::default();
    let server_thread = thread::spawn(move || incumbent.serve(drainable));

    let mut stream = connect_with_retry(&sock_path);
    let (_v, _hello) = read_message(&mut stream).unwrap();
    let id1 = HandoffId::new();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::HelloAck {
            proto_version_chosen: PROTO_MAX,
            handoff_id: id1,
        },
    )
    .unwrap();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::PrepareHandoff {
            handoff_id: id1,
            successor_pid: 9999,
            deadline_ms: 5000,
            drain_grace_ms: 1000,
        },
    )
    .unwrap();
    let (_, _) = read_message(&mut stream).unwrap();

    // Second PrepareHandoff with a different id while id1 is still active.
    let id2 = HandoffId::new();
    write_message(
        &mut stream,
        PROTO_MAX,
        &Message::PrepareHandoff {
            handoff_id: id2,
            successor_pid: 9998,
            deadline_ms: 5000,
            drain_grace_ms: 1000,
        },
    )
    .unwrap();
    // Read should observe EOF or error — Incumbent closed the session.
    match read_message(&mut stream) {
        Err(_) => {} // expected
        Ok((_, msg)) => panic!("expected disconnect, got {msg:?}"),
    }

    drop(stream);
    // Server should remain alive (continues accepting other sessions).
    thread::sleep(Duration::from_millis(50));
    // A fresh connection should succeed.
    let mut stream = connect_with_retry(&sock_path);
    let (_v, hello) = read_message(&mut stream).unwrap();
    assert!(matches!(hello, Message::Hello { .. }));

    drop(stream);
    drop(server_thread); // detach; serve() will keep running until process exit
}
