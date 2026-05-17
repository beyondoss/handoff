//! End-to-end Incumbent protocol: drive Hello → PrepareHandoff → SealRequest
//! → Commit and assert all the right Drainable methods got called.

mod common;

use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::MockDrainable;

#[test]
fn full_sequence_commits_and_releases_flock() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("control.sock");
    let data_dir = temp.path().join("data");

    let lock = DataDirLock::acquire(&data_dir).unwrap();
    let incumbent = Incumbent::bind(&sock_path, lock).unwrap();

    let drainable = MockDrainable::default();
    let state = drainable.state.clone();
    let server_thread = thread::spawn(move || incumbent.serve(drainable));

    // Wait for the listener to be ready.
    let mut stream = connect_with_retry(&sock_path);

    // Read O's Hello and respond with HelloAck.
    let (_v, hello) = read_message(&mut stream).unwrap();
    assert!(matches!(hello, Message::Hello { .. }));
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

    // PrepareHandoff → expect Drained.
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
    let (_v, msg) = read_message(&mut stream).unwrap();
    assert!(matches!(msg, Message::Drained { .. }));
    assert!(
        state.lock().unwrap().drained,
        "drain should have been called"
    );

    // SealRequest → expect SealComplete.
    write_message(&mut stream, PROTO_MAX, &Message::SealRequest { handoff_id }).unwrap();
    let (_v, msg) = read_message(&mut stream).unwrap();
    match msg {
        Message::SealComplete {
            handoff_id: id,
            last_revision_per_shard,
            ..
        } => {
            assert_eq!(id, handoff_id);
            assert_eq!(last_revision_per_shard, vec![42]);
        }
        other => panic!("expected SealComplete, got {other:?}"),
    }
    assert!(state.lock().unwrap().sealed, "seal should have been called");

    // After SealComplete the incumbent must have released the flock. Verify
    // by acquiring it from the test process (a fresh, independent FD).
    let probe = DataDirLock::acquire(&data_dir).expect("flock should be free after SealComplete");
    drop(probe);

    // Commit → server exits.
    write_message(&mut stream, PROTO_MAX, &Message::Commit { handoff_id }).unwrap();
    drop(stream);

    let result = server_thread.join().expect("server panicked");
    assert!(
        result.is_ok(),
        "server exited with error: {:?}",
        result.err()
    );
    assert_eq!(state.lock().unwrap().resumed, 0, "should not have resumed");
}

fn connect_with_retry(path: &std::path::Path) -> UnixStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return s,
            Err(_) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("connect failed: {e}"),
        }
    }
}
