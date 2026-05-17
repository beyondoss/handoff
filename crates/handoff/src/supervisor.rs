//! Supervisor-side orchestration: spawn the successor, drive the protocol,
//! handle abort/resume.
//!
//! This module is sync. The `handoff-supervisor` reference binary wraps it in
//! tokio for the rest of its orchestration; primitive embedders (guest-agent,
//! beyond-pg) can run `perform_handoff` from a worker thread.

use std::io::ErrorKind;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use crate::crash::points;
use crate::crash_here;
use crate::error::{Error, Result};
use crate::fd::arrange_inherited_fds_on_spawn;
use crate::frame::{read_message, write_message};
use crate::metrics::events;
use crate::protocol::{
    HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, negotiate_version,
};
use crate::state::{Phase, StateJournal};

/// Floor for any phase read timeout. Reads shorter than this are likely a
/// programming error (no time left to even receive one frame).
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(100);
/// Extra slack on top of `drain_grace` for the wire to deliver the `Drained`
/// frame after the consumer's drain returns.
const DRAIN_WIRE_BUFFER: Duration = Duration::from_secs(1);

/// One supervised primitive instance.
pub struct Supervisor {
    socket_path: PathBuf,
    /// Listener FDs the successor inherits, keyed by logical name. Stored in
    /// insertion order so FD assignment is stable across spawns.
    listener_fds: Vec<(String, RawFd)>,
    journal_path: Option<PathBuf>,
    build_id: Vec<u8>,
    /// Serializes `perform_handoff` calls so two threads can't drive
    /// overlapping handoffs against the same incumbent (correctness invariant:
    /// at most one in-flight swap per primitive).
    in_flight: Mutex<()>,
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

#[derive(Debug)]
pub struct HandoffOutcome {
    pub handoff_id: HandoffId,
    pub committed: bool,
    pub abort_reason: Option<String>,
    /// On a committed handoff, the `Child` for the new primitive (N). The
    /// caller owns it from here — the supervisor relinquishes lifecycle
    /// tracking. `None` on every non-committed outcome (the child was
    /// killed and reaped before this struct was constructed).
    pub child: Option<Child>,
}

/// Kills + reaps the wrapped child on drop unless `disarm()` was called.
/// Ensures we don't leak a spawned successor if `perform_handoff` returns
/// via an early `?` after the spawn. The pid is cached at construction so
/// [`ChildGuard::id`] never panics — it remains readable after the inner
/// `Child` has been taken by `disarm` or the drop path.
struct ChildGuard {
    child: Option<Child>,
    pid: u32,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
        }
    }

    fn id(&self) -> u32 {
        self.pid
    }

    /// Take the child without killing it. Used on the commit path: the new
    /// primitive is now legitimately running and we hand it to the caller.
    fn disarm(mut self) -> Child {
        // `new` always populates `child` and `disarm` consumes `self` by
        // value, so this take cannot observe `None`. Treat as an invariant.
        self.child
            .take()
            .expect("BUG: ChildGuard inner Child missing — constructor invariant violated")
    }

    /// Kill + reap explicitly so the caller can log the result.
    fn kill_and_reap(mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            tracing::warn!(
                pid = self.pid,
                "killing leaked successor child on guard drop"
            );
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Supervisor {
    pub fn new(socket_path: &Path) -> Result<Self> {
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            listener_fds: Vec::new(),
            journal_path: None,
            build_id: Vec::new(),
            in_flight: Mutex::new(()),
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
        let _in_flight = self
            .in_flight
            .try_lock()
            .map_err(|_| Error::HandoffInProgress)?;

        let handoff_id = HandoffId::new();
        let started_instant = Instant::now();
        let started_unix_ms = now_unix_ms();
        let total_deadline_at = started_instant + spec.deadline;

        // 1. Connect to O.
        let mut o_stream = UnixStream::connect(&self.socket_path)?;
        let chosen_o =
            self.exchange_hello_as_supervisor(&mut o_stream, handoff_id, Side::Incumbent, None)?;
        crash_here!(points::S_AFTER_O_HELLO);

        // 2. Create a socketpair for N's control channel.
        let (s_end, n_end) = make_socketpair()?;
        let n_end_raw = n_end.as_raw_fd();

        // 3. Spawn N. We keep s_end; n_end becomes the child's HANDOFF_SOCK_FD.
        let child = self.spawn_successor(&spec, n_end_raw)?;
        let child_guard = ChildGuard::new(child);
        let successor_pid = child_guard.id();
        // Drop our parent-side copy of n_end now that the child has its own
        // duplicate. The kernel keeps the socket alive via the child's FD.
        drop(n_end);
        crash_here!(points::S_AFTER_SPAWN_SUCCESSOR);

        let mut n_stream = s_end;
        // 4. Hello/HelloAck with N. Verify the child's announced PID matches
        // the one we spawned.
        let chosen_n = self.exchange_hello_as_supervisor(
            &mut n_stream,
            handoff_id,
            Side::Successor,
            Some(successor_pid),
        )?;
        crash_here!(points::S_AFTER_N_HELLO);

        self.journal_set(
            handoff_id,
            Phase::Negotiating,
            successor_pid,
            started_unix_ms,
        )?;

        // 5. PrepareHandoff → Drained.
        let prepare_at = Instant::now();
        tracing::info!(
            target: events::PREPARE,
            %handoff_id, successor_pid,
            drain_grace_ms = spec.drain_grace.as_millis() as u64,
            deadline_ms = spec.deadline.as_millis() as u64,
            "prepare handoff"
        );
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
        crash_here!(points::S_AFTER_PREPARE_SENT);
        let drain_timeout = spec.drain_grace + DRAIN_WIRE_BUFFER;
        let drained_msg = read_until(&mut o_stream, drain_timeout, |m| {
            matches!(m, Message::Drained { .. })
        })?;
        let (drained_open_conns, drained_accept_closed) = match &drained_msg {
            Message::Drained {
                open_conns_remaining,
                accept_closed,
            } => (*open_conns_remaining, *accept_closed),
            _ => unreachable!("read_until predicate restricts variant"),
        };
        tracing::info!(
            target: events::DRAINED,
            %handoff_id,
            open_conns_remaining = drained_open_conns,
            accept_closed = drained_accept_closed,
            drain_seconds = prepare_at.elapsed().as_secs_f64(),
            "drain complete"
        );
        crash_here!(points::S_AFTER_DRAINED_RECV);
        self.journal_set(handoff_id, Phase::Draining, successor_pid, started_unix_ms)?;

        // 6. SealRequest → SealComplete (or SealFailed).
        let seal_at = Instant::now();
        tracing::info!(target: events::SEAL, %handoff_id, "seal request");
        write_message(
            &mut o_stream,
            chosen_o,
            &Message::SealRequest { handoff_id },
        )?;
        crash_here!(points::S_AFTER_SEAL_REQUEST_SENT);
        let seal_timeout = remaining_until(total_deadline_at);
        o_stream.set_read_timeout(Some(seal_timeout))?;
        let seal_outcome: std::result::Result<(), String> = loop {
            match read_message(&mut o_stream) {
                Ok((_, Message::SealProgress { .. })) => continue,
                Ok((_, Message::Heartbeat { .. })) => continue,
                Ok((_, Message::SealComplete { handoff_id: id, .. })) if id == handoff_id => {
                    break Ok(());
                }
                Ok((
                    _,
                    Message::SealFailed {
                        handoff_id: id,
                        error,
                        ..
                    },
                )) if id == handoff_id => break Err(error),
                Ok((_, other)) => {
                    let _ = o_stream.set_read_timeout(None);
                    return Err(Error::UnexpectedMessage(short_name(&other)));
                }
                Err(Error::Io(e)) if is_timeout(&e) => {
                    let _ = o_stream.set_read_timeout(None);
                    let _ = write_message(
                        &mut n_stream,
                        chosen_n,
                        &Message::Abort {
                            handoff_id,
                            reason: "seal phase timed out".into(),
                        },
                    );
                    child_guard.kill_and_reap();
                    self.journal_clear();
                    return Err(Error::Timeout("SealComplete"));
                }
                Err(e) => {
                    let _ = o_stream.set_read_timeout(None);
                    return Err(e);
                }
            }
        };
        let _ = o_stream.set_read_timeout(None);

        if let Err(error) = seal_outcome {
            // O retains its writer state. Abort N and report failure.
            tracing::warn!(
                target: events::ABORT,
                %handoff_id, error = %error, "seal failed; aborting handoff"
            );
            let _ = write_message(
                &mut n_stream,
                chosen_n,
                &Message::Abort {
                    handoff_id,
                    reason: format!("seal failed: {error}"),
                },
            );
            child_guard.kill_and_reap();
            self.journal_clear();
            return Ok(HandoffOutcome {
                handoff_id,
                committed: false,
                abort_reason: Some(format!("seal failed: {error}")),
                child: None,
            });
        }
        tracing::info!(
            target: events::SEAL_COMPLETE,
            %handoff_id,
            seal_seconds = seal_at.elapsed().as_secs_f64(),
            "seal complete; flock released by O"
        );
        crash_here!(points::S_AFTER_SEAL_COMPLETE_RECV);
        self.journal_set(handoff_id, Phase::Sealing, successor_pid, started_unix_ms)?;

        // 7. Begin → Ready (deadline-bounded).
        let begin_at = Instant::now();
        write_message(&mut n_stream, chosen_n, &Message::Begin { handoff_id })?;
        crash_here!(points::S_AFTER_BEGIN_SENT);
        self.journal_set(
            handoff_id,
            Phase::AwaitingReady,
            successor_pid,
            started_unix_ms,
        )?;

        let ready_timeout = remaining_until(total_deadline_at);
        let ready_result = read_until(&mut n_stream, ready_timeout, |m| {
            matches!(m, Message::Ready { .. })
        });

        match ready_result {
            Ok(Message::Ready {
                handoff_id: id,
                listening_on,
                healthz_ok,
                advertised_revision_per_shard,
            }) if id == handoff_id => {
                tracing::info!(
                    target: events::READY,
                    %handoff_id,
                    healthz_ok,
                    listeners = ?listening_on,
                    advertised_revisions = ?advertised_revision_per_shard,
                    begin_to_ready_seconds = begin_at.elapsed().as_secs_f64(),
                    "successor ready"
                );
                crash_here!(points::S_AFTER_READY_RECV);
                // 8. Commit O.
                tracing::info!(
                    target: events::COMMIT,
                    %handoff_id,
                    total_seconds = started_instant.elapsed().as_secs_f64(),
                    "commit"
                );
                write_message(&mut o_stream, chosen_o, &Message::Commit { handoff_id })?;
                crash_here!(points::S_AFTER_COMMIT_SENT);
                self.journal_set(handoff_id, Phase::Committed, successor_pid, started_unix_ms)?;
                self.journal_clear();
                crash_here!(points::S_AFTER_JOURNAL_CLEAR);
                // N is now the legitimate writer — hand its Child out to caller.
                let child = child_guard.disarm();
                Ok(HandoffOutcome {
                    handoff_id,
                    committed: true,
                    abort_reason: None,
                    child: Some(child),
                })
            }
            other => {
                let reason = match &other {
                    Ok(m) => format!("expected Ready, got {}", short_name(m)),
                    Err(Error::Timeout(s)) => format!("ready phase timed out waiting for {s}"),
                    Err(e) => format!("ready read failed: {e}"),
                };
                tracing::warn!(
                    target: events::ABORT,
                    %handoff_id, reason, "aborting handoff before commit"
                );
                // Abort N, resume O.
                let _ = write_message(
                    &mut n_stream,
                    chosen_n,
                    &Message::Abort {
                        handoff_id,
                        reason: reason.clone(),
                    },
                );
                child_guard.kill_and_reap();
                write_message(
                    &mut o_stream,
                    chosen_o,
                    &Message::ResumeAfterAbort { handoff_id },
                )?;
                tracing::info!(
                    target: events::RESUME,
                    %handoff_id, "sent ResumeAfterAbort to O"
                );
                self.journal_set(
                    handoff_id,
                    Phase::ResumingAfterAbort,
                    successor_pid,
                    started_unix_ms,
                )?;
                self.journal_clear();
                Ok(HandoffOutcome {
                    handoff_id,
                    committed: false,
                    abort_reason: Some(reason),
                    child: None,
                })
            }
        }
    }

    /// Read any persisted in-flight handoff state and clear it. Call once
    /// before the first `perform_handoff` after a supervisor restart.
    ///
    /// The current incumbent auto-recovers from disconnect (sealed → re-acquire
    /// flock + resume; drained → resume), so the supervisor's restart-time
    /// responsibility is bounded: confirm the incumbent is reachable and
    /// clear the journal. Returns the persisted state (for logging) or `None`
    /// if no journal exists.
    pub fn resume_from_journal(&self) -> Result<Option<StateJournal>> {
        let Some(path) = self.journal_path.as_deref() else {
            return Ok(None);
        };
        let Some(journal) = StateJournal::read(path)? else {
            return Ok(None);
        };
        tracing::warn!(
            handoff_id = %journal.handoff_id,
            phase = ?journal.phase,
            "found prior handoff state on disk; verifying incumbent then clearing"
        );

        // Best-effort liveness probe of the incumbent. The incumbent runs its
        // own EOF-disconnect recovery, so this just confirms we can reach it.
        match UnixStream::connect(&self.socket_path) {
            Ok(mut stream) => {
                // Drain the incumbent's Hello frame so the new session is
                // clean; then drop the connection — incumbent observes EOF
                // and its session-close path runs.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = read_message(&mut stream);
            }
            Err(e) => {
                tracing::warn!(error = %e, "incumbent unreachable during journal resume");
            }
        }

        StateJournal::delete(path)?;
        Ok(Some(journal))
    }

    /// Run the Hello/HelloAck exchange where we are the supervisor: receive
    /// the peer's Hello, send a HelloAck with our chosen version. If
    /// `expected_pid` is set, the peer's announced pid must match.
    fn exchange_hello_as_supervisor(
        &self,
        stream: &mut UnixStream,
        handoff_id: HandoffId,
        expected_role: Side,
        expected_pid: Option<u32>,
    ) -> Result<ProtoVersion> {
        let (_v, peer_hello) = read_message(stream)?;
        let (their_role, their_pid, their_min, their_max) = match peer_hello {
            Message::Hello {
                role,
                pid,
                proto_min,
                proto_max,
                ..
            } => (role, pid, proto_min, proto_max),
            other => return Err(Error::UnexpectedMessage(short_name(&other))),
        };
        if their_role != expected_role {
            return Err(Error::Protocol(format!(
                "peer announced role {:?}, expected {:?}",
                their_role, expected_role
            )));
        }
        if let Some(expected) = expected_pid
            && their_pid != expected
        {
            return Err(Error::PidMismatch {
                expected,
                announced: their_pid,
            });
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
        arrange_inherited_fds_on_spawn(&mut cmd, sources);

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
        if let Some(path) = &self.journal_path
            && let Err(e) = StateJournal::delete(path)
        {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to clear handoff journal; next supervisor start will see stale state"
            );
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

/// Read messages from `stream` until `pred` matches, ignoring incoming
/// `Heartbeat`s. Bounded by `timeout` (clamped to at least `MIN_READ_TIMEOUT`).
fn read_until<F>(stream: &mut UnixStream, timeout: Duration, pred: F) -> Result<Message>
where
    F: Fn(&Message) -> bool,
{
    let deadline = Instant::now() + timeout.max(MIN_READ_TIMEOUT);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(MIN_READ_TIMEOUT)
            .max(MIN_READ_TIMEOUT);
        stream.set_read_timeout(Some(remaining))?;
        match read_message(stream) {
            Ok((_, Message::Heartbeat { .. })) => continue,
            Ok((_, msg)) if pred(&msg) => {
                stream.set_read_timeout(None)?;
                return Ok(msg);
            }
            Ok((_, other)) => {
                let _ = stream.set_read_timeout(None);
                return Err(Error::UnexpectedMessage(short_name(&other)));
            }
            Err(Error::Io(e)) if is_timeout(&e) => {
                let _ = stream.set_read_timeout(None);
                return Err(Error::Timeout("expected message"));
            }
            Err(e) => {
                let _ = stream.set_read_timeout(None);
                return Err(e);
            }
        }
    }
}

fn remaining_until(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(MIN_READ_TIMEOUT)
        .max(MIN_READ_TIMEOUT)
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
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
