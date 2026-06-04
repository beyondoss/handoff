//! Supervisor-side orchestration: spawn the successor, drive the protocol,
//! handle abort/resume.
//!
//! This module is sync. The `handoff-supervisor` reference binary wraps it in
//! tokio for the rest of its orchestration; primitive embedders (guest-agent,
//! beyond-pg) can run `perform_handoff` from a worker thread.

// `FromRawFd` on the socketpair endpoints in `make_socketpair` is `unsafe`
// because the safe wrapper assumes exclusive ownership of the FD; the
// `socketpair(2)` syscall has just produced both FDs and handed us
// ownership, so the invariant holds.
#![allow(unsafe_code)]

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
use crate::fd::pass_listener_fds_on_spawn;
use crate::frame::{read_message, write_message};
use crate::metrics::events;
use crate::protocol::{
    HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, negotiate_version, short_name,
};
use crate::state::{Phase, StateJournal};
use crate::util::now_unix_ms;

/// Floor for any phase read timeout. Reads shorter than this are likely a
/// programming error (no time left to even receive one frame).
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(100);
/// Maximum time the supervisor will wait on any one socket read for a
/// frame from a peer before declaring that peer dead. Each successful
/// read — including a `Heartbeat` — resets this clock. The incumbent
/// emits a heartbeat every 2s while blocked in `drain`/`seal`, so this
/// gives a 5× margin against scheduler hiccups before falsely concluding
/// the peer has died.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on the initial `Hello` read after connecting to a peer. The peer
/// writes `Hello` as its first action, so this should be near-instant —
/// generous slack still bounds a stuck-peer scenario.
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Slack the supervisor adds on top of any peer-side deadline before
/// declaring a read timed out.
///
/// The peer's clock for a phase starts when it deserializes our request —
/// `T_s + δ_net`, where `T_s` is the supervisor's send time — and the
/// response it produces still has to traverse `δ_net + δ_serialize` on the
/// way back. Without slack, the supervisor's read deadline (which starts
/// at `T_s`) expires `2·δ_net + δ_serialize` before a peer that ran to its
/// budget can land its reply on the wire. The reply is in flight; the
/// supervisor has already given up.
///
/// 1s is two orders of magnitude above realistic worst-case Unix-socket
/// round-trip plus frame serialization, so this is a conservative bound
/// on the in-flight window — not a knob to tune.
const WIRE_SLACK: Duration = Duration::from_secs(1);

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
    /// Absolute wall-clock cap on the entire handoff, from
    /// `perform_handoff` start through `Commit` send. Sized to comfortably
    /// exceed the consumer's `Drainable::drain` + `Drainable::seal` p99
    /// under load — the library does not interrupt long-but-progressing
    /// hooks (heartbeats from the incumbent keep the supervisor's
    /// liveness clock fresh), but it will abort once this wall-clock cap
    /// is exceeded regardless of progress.
    ///
    /// The supervisor's reads for `SealComplete` and `Ready` extend up to
    /// `WIRE_SLACK` (1 s) past this cap to pick up replies that were
    /// already on the wire when the deadline elapsed; total wall time can
    /// therefore exceed `deadline` by up to that slack.
    ///
    /// Tuning guidance: set this to `p99(drain) + p99(seal) + 30s`.
    /// Default: 5 minutes.
    pub deadline: Duration,
    /// Wall-clock cap on the `drain` phase specifically. Useful when the
    /// consumer's `drain` has a known upper bound (e.g. drain timeout
    /// configured per-connection) and a tighter cap is wanted than the
    /// overall `deadline`. The supervisor's read for `Drained` extends up
    /// to `WIRE_SLACK` (1 s) past this cap to pick up an in-flight reply.
    /// Default: 60 seconds.
    pub drain_grace: Duration,
}

impl SpawnSpec {
    /// Build a spec for `binary` with the recommended defaults: 5 minute
    /// overall `deadline`, 60 second `drain_grace`, empty `args` and `env`.
    /// Mutate the returned value or build the struct directly when you need
    /// non-default fields. `binary` is required because the library has no
    /// useful fallback — accepting a default of `PathBuf::new()` would just
    /// fail at `Command::spawn` later with a confusing OS error.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            args: Vec::new(),
            env: Vec::new(),
            deadline: Duration::from_secs(300),
            drain_grace: Duration::from_secs(60),
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
    /// `TcpListener` alive elsewhere; this just records the raw FD and the
    /// name to advertise via `LISTEN_FDNAMES`. Consuming-builder shape so it
    /// composes with `with_journal` / `with_build_id`:
    ///
    /// ```ignore
    /// let sup = Supervisor::new(path)?
    ///     .with_listener("http", fd)
    ///     .with_journal(journal_path);
    /// ```
    pub fn with_listener(mut self, name: impl Into<String>, fd: RawFd) -> Self {
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
        // Send the budget *remaining*, not the raw configured duration: the
        // hello exchange and successor spawn have already burned wall-clock
        // time off the overall deadline, and we want O's view of the
        // deadline to track ours. Floored at MIN_READ_TIMEOUT so O still
        // has a usable budget if we cut it very close.
        let deadline_ms = remaining_until(total_deadline_at).as_millis() as u64;
        let drain_grace_ms = spec.drain_grace.as_millis() as u64;
        tracing::info!(
            target: events::PREPARE,
            %handoff_id, successor_pid,
            drain_grace_ms,
            deadline_ms,
            "prepare handoff"
        );
        write_message(
            &mut o_stream,
            chosen_o,
            &Message::PrepareHandoff {
                handoff_id,
                successor_pid,
                deadline_ms,
                drain_grace_ms,
            },
        )?;
        crash_here!(points::S_AFTER_PREPARE_SENT);
        // `drain_grace` is the budget we hand O for the entire drain
        // phase: O may consume up to that long inside `Drainable::drain`
        // before producing a `Drained` frame. Our read deadline must
        // therefore exceed `drain_grace` by `WIRE_SLACK` — O's clock for
        // the grace starts when it deserializes `PrepareHandoff`
        // (T_s + δ_net), and the `Drained` it sends after running to that
        // limit still has to traverse δ_net + δ_serialize on the way back.
        // Per-recv liveness handles peer-dead detection inside
        // `read_until`; the slack is specifically about not aborting a
        // reply that's already on the wire.
        let drained_msg = read_until(
            &mut o_stream,
            spec.drain_grace + WIRE_SLACK,
            "Drained",
            |m| matches!(m, Message::Drained { .. }),
        )?;
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
        // Seal-wait loop. Same two-tier timeout as `read_until`: per-recv
        // capped at LIVENESS_TIMEOUT (heartbeats reset it), wall-clock
        // capped by `total_deadline_at + WIRE_SLACK`. The slack covers a
        // `SealComplete` that's already on the wire when the overall
        // deadline expires — `seal()` runs without an internal deadline,
        // so it can land its reply arbitrarily close to the cap.
        // `SealProgress` and `Heartbeat` frames are both progress signals.
        let seal_read_deadline = total_deadline_at + WIRE_SLACK;
        let seal_outcome: std::result::Result<(), String> = loop {
            let now = Instant::now();
            if now >= seal_read_deadline {
                let _ = o_stream.set_read_timeout(None);
                send_best_effort_abort(
                    &mut n_stream,
                    chosen_n,
                    handoff_id,
                    "seal phase timed out".into(),
                );
                child_guard.kill_and_reap();
                self.journal_clear();
                return Err(Error::Timeout("SealComplete"));
            }
            let remaining = seal_read_deadline - now;
            let recv_timeout = LIVENESS_TIMEOUT.min(remaining).max(MIN_READ_TIMEOUT);
            o_stream.set_read_timeout(Some(recv_timeout))?;
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
                    // No frame for `recv_timeout` — peer has gone silent
                    // for longer than LIVENESS_TIMEOUT (or we're at the
                    // overall wall-clock cap; the next loop iteration
                    // detects that explicitly). Treat as peer-dead and
                    // abort.
                    let _ = o_stream.set_read_timeout(None);
                    send_best_effort_abort(
                        &mut n_stream,
                        chosen_n,
                        handoff_id,
                        "incumbent unresponsive during seal".into(),
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
            send_best_effort_abort(
                &mut n_stream,
                chosen_n,
                handoff_id,
                format!("seal failed: {error}"),
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
        //
        // The Begin write and the Ready read are funneled through one
        // `Result<Message>` so a failure at either step lands in the same
        // abort/resume flow below — sending `ResumeAfterAbort` to O is the
        // correct response in both cases (N is unreachable; O has sealed
        // and must be told to keep serving).
        let begin_at = Instant::now();
        let ready_result =
            match write_message(&mut n_stream, chosen_n, &Message::Begin { handoff_id }) {
                Ok(()) => {
                    crash_here!(points::S_AFTER_BEGIN_SENT);
                    self.journal_set(
                        handoff_id,
                        Phase::AwaitingReady,
                        successor_pid,
                        started_unix_ms,
                    )?;
                    // N has no internal deadline for `announce_and_bind`,
                    // so `Ready` can be in flight at the moment
                    // `total_deadline_at` elapses — give the read
                    // `WIRE_SLACK` past that cap for the same reason the
                    // drain and seal reads do.
                    let ready_timeout = remaining_until(total_deadline_at) + WIRE_SLACK;
                    read_until(&mut n_stream, ready_timeout, "Ready", |m| {
                        matches!(m, Message::Ready { .. })
                    })
                }
                Err(e) => Err(e),
            };

        // The `Ready` match arm pulls the handoff_id apart so a mismatched id
        // produces a precise error rather than the misleading
        // "expected Ready, got Ready" string the generic `other` arm would
        // emit when `short_name` was called on a `Message::Ready` with the
        // wrong id.
        let ready_result = match ready_result {
            Ok(Message::Ready { handoff_id: id, .. }) if id != handoff_id => Err(Error::Protocol(
                format!("Ready carries wrong handoff_id: got {id}, expected {handoff_id}"),
            )),
            other => other,
        };

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
                // N has acknowledged readiness — N has acquired the flock
                // and (when using `announce_and_bind`) bound the control
                // socket, so N is the authoritative new incumbent from
                // this point on regardless of what happens with O.
                //
                // Disarm the guard *before* the Commit write so a dead-O
                // write failure does not propagate via `?` and let the
                // guard's Drop kill the legitimate new incumbent. Any
                // I/O after this point is best-effort cleanup of O.
                let child = child_guard.disarm();

                // 8. Commit O.
                tracing::info!(
                    target: events::COMMIT,
                    %handoff_id,
                    total_seconds = started_instant.elapsed().as_secs_f64(),
                    "commit"
                );
                if let Err(e) =
                    write_message(&mut o_stream, chosen_o, &Message::Commit { handoff_id })
                {
                    tracing::warn!(
                        %handoff_id, error = %e,
                        "failed to send Commit to incumbent; O may have crashed — \
                         N is the new incumbent regardless, handoff is committed"
                    );
                }
                crash_here!(points::S_AFTER_COMMIT_SENT);
                // Journal updates are best-effort here: the handoff is
                // committed and N is serving. A failure to journal
                // `Committed` means the next supervisor sees `AwaitingReady`
                // and runs its standard recovery — also fine.
                if let Err(e) =
                    self.journal_set(handoff_id, Phase::Committed, successor_pid, started_unix_ms)
                {
                    tracing::warn!(%handoff_id, error = %e, "journal Committed failed");
                }
                self.journal_clear();
                crash_here!(points::S_AFTER_JOURNAL_CLEAR);
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
                send_best_effort_abort(&mut n_stream, chosen_n, handoff_id, reason.clone());
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
                // and its session-close path runs. A read error here is not
                // fatal (the EOF on drop still triggers the incumbent's
                // session-close path) but we log it at debug so a corrupted
                // Hello can be correlated post-mortem.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                if let Err(e) = read_message(&mut stream) {
                    tracing::debug!(
                        error = %e,
                        "incumbent Hello read failed during journal resume probe; \
                         continuing — EOF on drop will reset incumbent session"
                    );
                }
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
        // Bound the initial Hello so a peer that accepted the connection but
        // hangs before writing can't block `perform_handoff` indefinitely.
        // Cleared after the read regardless of outcome.
        stream.set_read_timeout(Some(HELLO_READ_TIMEOUT))?;
        let read_result = read_message(stream);
        let _ = stream.set_read_timeout(None);
        let (_v, peer_hello) = match read_result {
            Ok(x) => x,
            Err(Error::Io(e)) if is_timeout(&e) => return Err(Error::Timeout("peer Hello")),
            Err(e) => return Err(e),
        };
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
        let sock_target_fd = 3 + self.listener_fds.len() as RawFd;

        let mut cmd = Command::new(&spec.binary);
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.env("HANDOFF_ROLE", "successor");
        cmd.env("HANDOFF_SOCK_FD", sock_target_fd.to_string());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // LISTEN_FDS env + FD-shuffle dance. Control socket lands at FD
        // `3 + listener_count` so the successor reads HANDOFF_SOCK_FD from
        // its env and finds it there.
        pass_listener_fds_on_spawn(&mut cmd, &self.listener_fds, Some(n_sock_fd));

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

/// Best-effort send of an `Abort` to the successor on a path where we have
/// already decided to tear N down (kill+reap follows). Logs at WARN if the
/// write fails — N may have died or its socket may already be closed, which
/// is expected on these paths, but a silent discard would hide cases where
/// the supervisor's view diverges from the child's.
fn send_best_effort_abort(
    stream: &mut UnixStream,
    version: ProtoVersion,
    handoff_id: HandoffId,
    reason: String,
) {
    let reason_for_log = reason.clone();
    if let Err(e) = write_message(stream, version, &Message::Abort { handoff_id, reason }) {
        tracing::warn!(
            %handoff_id,
            reason = %reason_for_log,
            error = %e,
            "best-effort Abort to successor failed; child will still be killed and reaped"
        );
    }
}

fn make_socketpair() -> Result<(UnixStream, UnixStream)> {
    // Linux and the BSDs create the pair close-on-exec atomically via the
    // SOCK_CLOEXEC flag. macOS doesn't define that flag for socketpair (nix
    // won't even compile the symbol there), so set FD_CLOEXEC with a
    // follow-up fcntl on each end. The non-atomic window on macOS is
    // theoretical: this runs on the rare swap path, not under a fork storm.
    #[cfg(not(target_os = "macos"))]
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    #[cfg(target_os = "macos")]
    let (a, b) = {
        use std::os::fd::AsFd;
        let pair = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )?;
        for fd in [pair.0.as_fd(), pair.1.as_fd()] {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )?;
        }
        pair
    };
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
/// `Heartbeat` and `SealProgress` frames (both are pure liveness/progress
/// signals — never the message a caller is blocking on). Two timeouts
/// apply:
///
/// - **Liveness** (per-recv): each socket read waits at most
///   [`LIVENESS_TIMEOUT`]. Any incoming frame — including a `Heartbeat`
///   — resets this clock. A peer that emits heartbeats every 2s while
///   blocked in a long-running `Drainable::drain` or `Drainable::seal`
///   is therefore *not* declared dead, no matter how long the hook
///   takes.
/// - **Wall-clock** (overall budget): regardless of heartbeats, the
///   call returns `Error::Timeout(awaiting)` once the `timeout` budget
///   has elapsed. This bounds catastrophic cases — consumer hook alive
///   but not making progress — from running forever.
///
/// `awaiting` names the message the caller is blocking on; it surfaces
/// in the timeout error so an operator's log identifies which protocol
/// step expired (e.g. `Timeout("Drained")` vs `Timeout("Ready")`).
fn read_until<F>(
    stream: &mut UnixStream,
    timeout: Duration,
    awaiting: &'static str,
    pred: F,
) -> Result<Message>
where
    F: Fn(&Message) -> bool,
{
    let deadline = Instant::now() + timeout.max(MIN_READ_TIMEOUT);
    loop {
        let now = Instant::now();
        if now >= deadline {
            let _ = stream.set_read_timeout(None);
            return Err(Error::Timeout(awaiting));
        }
        let remaining = deadline - now;
        // Per-recv timeout: bounded above by LIVENESS_TIMEOUT (peer-dead
        // detection), below by what's left of the overall budget. Each
        // successful frame — heartbeat or otherwise — resets this on
        // the next iteration.
        let recv_timeout = LIVENESS_TIMEOUT.min(remaining).max(MIN_READ_TIMEOUT);
        stream.set_read_timeout(Some(recv_timeout))?;
        match read_message(stream) {
            Ok((_, Message::Heartbeat { .. })) => continue,
            Ok((_, Message::SealProgress { .. })) => continue,
            Ok((_, msg)) if pred(&msg) => {
                let _ = stream.set_read_timeout(None);
                return Ok(msg);
            }
            Ok((_, other)) => {
                let _ = stream.set_read_timeout(None);
                return Err(Error::UnexpectedMessage(short_name(&other)));
            }
            Err(Error::Io(e)) if is_timeout(&e) => {
                let _ = stream.set_read_timeout(None);
                return Err(Error::Timeout(awaiting));
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
