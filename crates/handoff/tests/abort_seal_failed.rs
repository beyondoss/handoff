//! O's seal returns an error mid-handoff: O sends SealFailed, retains flock,
//! and is ready to accept a future PrepareHandoff.

mod common;

use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use handoff::frame::{read_message, write_message};
use handoff::protocol::{HandoffId, Message, PROTO_MAX};
use handoff::{DataDirLock, Incumbent};

use common::MockDrainable;

#[test]
fn seal_failure_retains_flock_and_allows_retry() {
    let temp = tempfile::tempdir().unwrap();
    let sock_path = temp.path().join("control.sock");
    let data_dir = temp.path().join("data");

    let lock = DataDirLock::acquire(&data_dir).unwrap();
    let incumbent = Incumbent::bind(&sock_path, lock).unwrap();

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
