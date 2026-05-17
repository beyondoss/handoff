//! Supervisor-side orchestration: spawn the successor, drive the protocol,
//! handle abort/resume.
//!
//! This module is sync. The `handoff-supervisor` reference binary wraps it in
//! tokio for the rest of its orchestration; primitive embedders (guest-agent,
//! beyond-pg) can run `perform_handoff` from a worker thread.

use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::protocol::{
    HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, negotiate_version,
};
use crate::state::{Phase, StateJournal};

/// One supervised primitive instance.
pub struct Supervisor {
    socket_path: PathBuf,
    /// Listener FDs the successor inherits, keyed by logical name. Stored in
    /// insertion order so FD assignment is stable across spawns.
    listener_fds: Vec<(String, RawFd)>,
    journal_path: Option<PathBuf>,
    build_id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SpawnSpec {
    pub binary: PathBuf,
    pub args: Vec<String>,
    /// Extra env vars to pass to the child (in addition to the handoff envelope).
    pub env: Vec<(String, String)>,
    /// Overall deadline for the handoff (post-drain through ready).
    pub deadline: Duration,
    /// Maximum time to spend in `drain` before moving on (or aborting).
    pub drain_grace: Duration,
}

impl Default for SpawnSpec {
    fn default() -> Self {
        Self {
            binary: PathBuf::new(),
            args: Vec::new(),
            env: Vec::new(),
            deadline: Duration::from_secs(60),
            drain_grace: Duration::from_secs(25),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandoffOutcome {
    pub handoff_id: HandoffId,
    pub committed: bool,
    pub abort_reason: Option<String>,
}

impl Supervisor {
    pub fn new(socket_path: &Path) -> Result<Self> {
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            listener_fds: Vec::new(),
            journal_path: None,
            build_id: Vec::new(),
        })
    }

    /// Register an inherited listener. The supervisor must keep the underlying
    /// TcpListener alive elsewhere; this just records the raw FD and the name
    /// to advertise via `LISTEN_FDNAMES`.
    pub fn add_listener(&mut self, name: impl Into<String>, fd: RawFd) -> &mut Self {
        self.listener_fds.push((name.into(), fd));
        self
    }

    pub fn with_journal(mut self, path: PathBuf) -> Self {
        self.journal_path = Some(path);
        self
    }

    pub fn with_build_id(mut self, build_id: Vec<u8>) -> Self {
        self.build_id = build_id;
        self
    }

    pub fn perform_handoff(&self, spec: SpawnSpec) -> Result<HandoffOutcome> {
        let handoff_id = HandoffId::new();
        let started = now_unix_ms();

        // 1. Connect to O.
        let mut o_stream = UnixStream::connect(&self.socket_path)?;
        let chosen_o =
            self.exchange_hello_as_supervisor(&mut o_stream, handoff_id, Side::Incumbent)?;

        // 2. Create a socketpair for N's control channel.
        let (s_end, n_end) = make_socketpair()?;
        let n_end_raw = n_end.as_raw_fd();

        // 3. Spawn N. We keep s_end; n_end becomes the child's HANDOFF_SOCK_FD.
        let mut child = self.spawn_successor(&spec, n_end_raw)?;
        let successor_pid = child.id();
        // Drop our parent-side copy of n_end now that the child has its own
        // duplicate. The kernel keeps the socket alive via the child's FD.
        drop(n_end);

        let mut n_stream = s_end;
        // 4. Hello/HelloAck with N.
        let chosen_n =
            self.exchange_hello_as_supervisor(&mut n_stream, handoff_id, Side::Successor)?;

        self.journal_set(handoff_id, Phase::Negotiating, successor_pid, started)?;

        // 5. PrepareHandoff → Drained.
        write_message(
            &mut o_stream,
            chosen_o,
            &Message::PrepareHandoff {
                handoff_id,
                successor_pid,
                deadline_ms: spec.deadline.as_millis() as u64,
                drain_grace_ms: spec.drain_grace.as_millis() as u64,
            },
        )?;
        expect_message(&mut o_stream, "Drained", |m| {
            matches!(m, Message::Drained { .. })
        })?;
        self.journal_set(handoff_id, Phase::Draining, successor_pid, started)?;

        // 6. SealRequest → SealComplete (or SealFailed).
        write_message(
            &mut o_stream,
            chosen_o,
            &Message::SealRequest { handoff_id },
        )?;
        let sealed = loop {
            let (_v, msg) = read_message(&mut o_stream)?;
            match msg {
                Message::SealProgress { .. } => continue,
                Message::SealComplete { handoff_id: id, .. } if id == handoff_id => break true,
                Message::SealFailed {
                    handoff_id: id,
                    error,
                    ..
                } if id == handoff_id => {
                    // O retains its writer state. Abort N and report failure.
                    let _ = write_message(
                        &mut n_stream,
                        chosen_n,
                        &Message::Abort {
                            handoff_id,
                            reason: format!("seal failed: {error}"),
                        },
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    self.journal_clear();
                    return Ok(HandoffOutcome {
                        handoff_id,
                        committed: false,
                        abort_reason: Some(format!("seal failed: {error}")),
                    });
                }
                other => {
                    return Err(Error::UnexpectedMessage(short_name(&other)));
                }
            }
        };
        if !sealed {
            // unreachable per the loop above but the compiler doesn't know.
            return Err(Error::Protocol("seal loop terminated unexpectedly".into()));
        }
        self.journal_set(handoff_id, Phase::Sealing, successor_pid, started)?;

        // 7. Begin → Ready (deadline-bounded).
        write_message(&mut n_stream, chosen_n, &Message::Begin { handoff_id })?;
        self.journal_set(handoff_id, Phase::AwaitingReady, successor_pid, started)?;

        n_stream.set_read_timeout(Some(spec.deadline))?;
        let ready_result = read_message(&mut n_stream);
        let _ = n_stream.set_read_timeout(None);

        match ready_result {
            Ok((_v, Message::Ready { handoff_id: id, .. })) if id == handoff_id => {
                // 8. Commit O.
                write_message(&mut o_stream, chosen_o, &Message::Commit { handoff_id })?;
                self.journal_set(handoff_id, Phase::Committed, successor_pid, started)?;
                self.journal_clear();
                Ok(HandoffOutcome {
                    handoff_id,
                    committed: true,
                    abort_reason: None,
                })
            }
            other => {
                let reason = match &other {
                    Ok((_, m)) => format!("expected Ready, got {}", short_name(m)),
                    Err(Error::Io(e)) => format!("ready read failed: {e}"),
                    Err(e) => format!("ready read failed: {e}"),
                };
                // Abort N, resume O.
                let _ = write_message(
                    &mut n_stream,
                    chosen_n,
                    &Message::Abort {
                        handoff_id,
                        reason: reason.clone(),
                    },
                );
                let _ = child.kill();
                let _ = child.wait();
                write_message(
                    &mut o_stream,
                    chosen_o,
                    &Message::ResumeAfterAbort { handoff_id },
                )?;
                self.journal_set(
                    handoff_id,
                    Phase::ResumingAfterAbort,
                    successor_pid,
                    started,
                )?;
                self.journal_clear();
                Ok(HandoffOutcome {
                    handoff_id,
                    committed: false,
                    abort_reason: Some(reason),
                })
            }
        }
    }

    /// Run the Hello/HelloAck exchange where we are the supervisor: receive
    /// the peer's Hello, send a HelloAck with our chosen version.
    fn exchange_hello_as_supervisor(
        &self,
        stream: &mut UnixStream,
        handoff_id: HandoffId,
        expected_role: Side,
    ) -> Result<ProtoVersion> {
        let (_v, peer_hello) = read_message(stream)?;
        let (their_role, their_min, their_max) = match peer_hello {
            Message::Hello {
                role,
                proto_min,
                proto_max,
                ..
            } => (role, proto_min, proto_max),
            other => return Err(Error::UnexpectedMessage(short_name(&other))),
        };
        if their_role != expected_role {
            return Err(Error::Protocol(format!(
                "peer announced role {:?}, expected {:?}",
                their_role, expected_role
            )));
        }
        let chosen = negotiate_version(PROTO_MIN, PROTO_MAX, their_min, their_max)?;
        write_message(
            stream,
            chosen,
            &Message::HelloAck {
                proto_version_chosen: chosen,
                handoff_id,
            },
        )?;
        Ok(chosen)
    }

    fn spawn_successor(&self, spec: &SpawnSpec, n_sock_fd: RawFd) -> Result<Child> {
        let listener_count = self.listener_fds.len();
        let names: Vec<String> = self.listener_fds.iter().map(|(n, _)| n.clone()).collect();
        let sock_target_fd = 3 + listener_count as RawFd;

        let mut cmd = Command::new(&spec.binary);
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.env("HANDOFF_ROLE", "successor");
        cmd.env("HANDOFF_SOCK_FD", sock_target_fd.to_string());
        cmd.env("LISTEN_FDS", listener_count.to_string());
        cmd.env("LISTEN_FDNAMES", names.join(":"));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Source FDs in target-order: listeners first (3, 4, ...), then control sock.
        let mut sources: Vec<RawFd> = self.listener_fds.iter().map(|(_, f)| *f).collect();
        sources.push(n_sock_fd);

        // SAFETY: `pre_exec` runs in the child after fork(2), before execve(2).
        // We use only async-signal-safe operations (dup2, fcntl) — no
        // allocations, no Rust locks.
        unsafe {
            cmd.pre_exec(move || {
                for (i, src) in sources.iter().enumerate() {
                    let dst = 3 + i as RawFd;
                    if *src == dst {
                        // Already in position: explicitly clear CLOEXEC so the
                        // fd survives the upcoming execve.
                        if libc::fcntl(*src, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else if libc::dup2(*src, dst) == -1 {
                        return Err(std::io::Error::last_os_error());
                        // Note: dup2 result always has CLOEXEC=false, no further work.
                    }
                }
                Ok(())
            });
        }

        let child = cmd.spawn()?;
        Ok(child)
    }

    fn journal_set(
        &self,
        handoff_id: HandoffId,
        phase: Phase,
        successor_pid: u32,
        started_at_unix_ms: u64,
    ) -> Result<()> {
        if let Some(path) = &self.journal_path {
            StateJournal {
                handoff_id,
                phase,
                incumbent_pid: std::process::id(),
                successor_pid: Some(successor_pid),
                started_at_unix_ms,
            }
            .write_atomic(path)?;
        }
        Ok(())
    }

    fn journal_clear(&self) {
        if let Some(path) = &self.journal_path {
            let _ = StateJournal::delete(path);
        }
    }
}

fn make_socketpair() -> Result<(UnixStream, UnixStream)> {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    // SAFETY: both ends are freshly owned by us, valid, non-blocking unset.
    let s_a = unsafe {
        use std::os::fd::FromRawFd;
        UnixStream::from_raw_fd(a.into_raw_fd())
    };
    let s_b = unsafe {
        use std::os::fd::FromRawFd;
        UnixStream::from_raw_fd(b.into_raw_fd())
    };
    Ok((s_a, s_b))
}

fn expect_message<F: FnOnce(&Message) -> bool>(
    stream: &mut UnixStream,
    name: &'static str,
    pred: F,
) -> Result<Message> {
    let (_v, msg) = read_message(stream)?;
    if pred(&msg) {
        Ok(msg)
    } else {
        Err(Error::UnexpectedMessage(name))
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn short_name(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "Hello",
        Message::HelloAck { .. } => "HelloAck",
        Message::PrepareHandoff { .. } => "PrepareHandoff",
        Message::Drained { .. } => "Drained",
        Message::SealRequest { .. } => "SealRequest",
        Message::SealProgress { .. } => "SealProgress",
        Message::SealComplete { .. } => "SealComplete",
        Message::SealFailed { .. } => "SealFailed",
        Message::Begin { .. } => "Begin",
        Message::Ready { .. } => "Ready",
        Message::Commit { .. } => "Commit",
        Message::Abort { .. } => "Abort",
        Message::ResumeAfterAbort { .. } => "ResumeAfterAbort",
        Message::Heartbeat { .. } => "Heartbeat",
    }
}
