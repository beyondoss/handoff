//! Incumbent-side control socket server.
//!
//! Binds a Unix-domain socket at the configured path and accepts one
//! supervisor connection at a time. For each connection, runs the handoff
//! state machine against the supplied [`Drainable`] implementation.
//!
//! `Incumbent::serve` blocks the calling thread; spawn it via
//! `std::thread::Builder` from the consumer's startup sequence.
//!
//! After a successful handoff commits, `serve` returns `Ok(())` and the
//! consumer should exit the process. Other terminal conditions (errors,
//! aborted handoffs that resumed) cause `serve` to keep accepting.

use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::crash::points;
use crate::crash_here;
use crate::drainable::Drainable;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::lock::DataDirLock;
use crate::metrics::events;
use crate::protocol::{
    Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, negotiate_version,
    short_name,
};
use crate::util::now_unix_ms;

/// How long the session-error recovery path will wait for the data-dir
/// flock to become acquirable. Covers the brief race where a successor
/// took the flock after `SealComplete`, then could not complete the
/// handshake (e.g. the supervisor died after sending `Begin`), and is now
/// exiting — kernel-releasing the flock in the process. A few seconds is
/// far longer than that exit takes; if it's still held after this, the
/// holder is a legitimately-installed new incumbent and we should exit.
const RESUME_FLOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Cadence of heartbeats emitted while the incumbent is blocked in a
/// long-running consumer hook (`drain` or `seal`). With the supervisor's
/// `LIVENESS_TIMEOUT` set to 10s, 2s gives us a 5× safety margin against
/// scheduler hiccups before the supervisor would declare the peer dead.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Bound on the `HelloAck` read after a peer connects to the control
/// socket. A well-behaved supervisor writes `HelloAck` immediately after
/// reading our `Hello`, so this should be near-instant — generous slack
/// still bounds the case where a peer connects, stalls, and would
/// otherwise pin the single-session serve loop indefinitely.
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Incumbent {
    listener: UnixListener,
    lock: Option<DataDirLock>,
    data_dir: PathBuf,
    build_id: Vec<u8>,
}

/// Run `work` on the current thread while a background thread emits
/// `Heartbeat` frames on `stream` every [`HEARTBEAT_INTERVAL`]. The
/// heartbeats let a long-running but progressing consumer hook (`drain`,
/// `seal`) complete without tripping the supervisor's per-recv liveness
/// timeout.
///
/// Concurrency contract: while `work` is executing on the main thread,
/// only the heartbeat thread writes to `stream`; the main thread is busy
/// inside the consumer's code and never reads or writes the socket. On
/// return (or panic) the heartbeat thread is signaled to stop and joined
/// before the helper returns control, so the main thread is the sole
/// writer again by the time it sends `Drained`/`SealComplete`.
///
/// A failure to clone the stream for the heartbeat thread is non-fatal:
/// we log a warning and run `work` without heartbeats. The supervisor's
/// liveness timeout would then bound the operation in wall-clock terms.
fn run_with_heartbeats<F, T>(stream: &UnixStream, chosen: ProtoVersion, work: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not clone control stream for heartbeats; running without"
            );
            return work();
        }
    };
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let hb_thread = thread::spawn(move || {
        let mut writer = writer;
        // `recv_timeout` returns Err on timeout — that's our "no stop
        // signal yet, send another heartbeat" trigger. `Ok(())` means
        // the main thread asked us to stop; any other Err means the
        // sender dropped (also a stop signal).
        while stop_rx.recv_timeout(HEARTBEAT_INTERVAL).is_err() {
            let msg = Message::Heartbeat {
                ts_ms: now_unix_ms(),
            };
            if write_message(&mut writer, chosen, &msg).is_err() {
                // Supervisor gone or socket broken — no point continuing.
                return;
            }
        }
    });

    // RAII guard: signal + join the heartbeat thread on every exit path,
    // including a panic inside `work`. After this drops, the heartbeat
    // thread has fully exited and the main thread is the sole writer.
    struct StopGuard {
        stop_tx: Option<mpsc::Sender<()>>,
        thread: Option<thread::JoinHandle<()>>,
    }
    impl Drop for StopGuard {
        fn drop(&mut self) {
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.send(());
            }
            if let Some(h) = self.thread.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = StopGuard {
        stop_tx: Some(stop_tx),
        thread: Some(hb_thread),
    };

    work()
}

/// Bind the control socket, unlinking any prior path binding first.
/// Shared by `Incumbent::bind_cold_start` (no prior incumbent to displace)
/// and `Incumbent::bind_after_ready` (called from a successor immediately
/// after `Ready` so the prior incumbent is committed and exiting). The
/// preconditions are caller-enforced; this routine assumes the unlink is
/// safe at the call site.
fn bind_unlinking(socket_path: &Path, lock: DataDirLock) -> Result<Incumbent> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove any stale (cold start) or about-to-be-orphaned (after-ready)
    // socket file. The caller has established that no live peer is
    // serving on this path.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    let data_dir = lock.data_dir().to_path_buf();
    Ok(Incumbent {
        listener,
        lock: Some(lock),
        data_dir,
        build_id: Vec::new(),
    })
}

/// Acquire the data-dir flock, retrying briefly on `LockHeld` so a
/// transiently-held lock (a dying successor) does not surface as a fatal
/// error in the session-error recovery path. Any other error is returned
/// immediately — only `LockHeld` triggers a retry.
fn acquire_with_short_retry(data_dir: &Path, timeout: Duration) -> Result<DataDirLock> {
    const RETRY_INTERVAL: Duration = Duration::from_millis(25);
    let deadline = Instant::now() + timeout;
    loop {
        match DataDirLock::acquire(data_dir) {
            Ok(lock) => return Ok(lock),
            Err(Error::LockHeld { .. }) if Instant::now() < deadline => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// What happened to one supervisor session.
enum SessionOutcome {
    /// Handoff committed — N is now the writer; this process should exit.
    Committed,
    /// Session closed cleanly without a commit (e.g. cancellation, idle
    /// disconnect, abort with resume). Keep accepting.
    Closed,
}

/// Per-supervisor-session state. Lives entirely inside `handle_session`; the
/// fields move together through `run_session_loop`, so grouping them keeps
/// the invariants explicit (no `&mut bool` triplets passed across the call
/// boundary).
#[derive(Default)]
struct SessionState {
    active: Option<HandoffId>,
    sealed: bool,
    /// True once `drainable.drain` returned successfully for the current
    /// `active` handoff. Used to decide whether the consumer needs a
    /// `resume_after_abort` to restart accepting on any non-Commit exit.
    drained: bool,
}

impl Incumbent {
    /// Bind the control socket for **cold-start** use only.
    ///
    /// "Cold start" means this process has no prior incumbent to displace —
    /// either the very first startup, or a recovery after a crash where the
    /// prior process is already gone. The bind unlinks any stale file at
    /// `socket_path`, which is safe in those scenarios.
    ///
    /// # Do not call from a successor before `Ready`
    ///
    /// A successor process must NOT call this before
    /// [`Successor::announce_ready`] returns — doing so unlinks the prior
    /// incumbent's still-valid path-binding and breaks the supervisor's
    /// abort path. From a successor, prefer
    /// [`Successor::announce_and_bind`], which orders `Ready` and bind in
    /// one call.
    pub fn bind_cold_start(socket_path: &Path, lock: DataDirLock) -> Result<Self> {
        bind_unlinking(socket_path, lock)
    }

    /// Successor-side bind, called by [`crate::BegunSuccessor::announce_and_bind`]
    /// immediately after `Ready` has been sent. The supervisor has by then
    /// disarmed its `ChildGuard` and committed `O`, so unlinking the prior
    /// incumbent's path binding is safe — the prior incumbent is exiting
    /// and will not re-bind.
    ///
    /// Shares its implementation with [`Self::bind_cold_start`]; the
    /// separate entry point exists so callers see a name that reflects the
    /// preconditions appropriate to their context.
    pub(crate) fn bind_after_ready(socket_path: &Path, lock: DataDirLock) -> Result<Self> {
        bind_unlinking(socket_path, lock)
    }

    /// Set the implementation-defined build identifier announced in `Hello`.
    /// Defaults to empty if unset.
    pub fn with_build_id(mut self, build_id: Vec<u8>) -> Self {
        self.build_id = build_id;
        self
    }

    pub fn serve<D: Drainable + 'static>(mut self, drainable: D) -> Result<()> {
        loop {
            let (stream, _addr) = match self.listener.accept() {
                Ok(x) => x,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            match self.handle_session(stream, &drainable) {
                Ok(SessionOutcome::Committed) => {
                    tracing::info!("handoff committed; incumbent exiting serve loop");
                    return Ok(());
                }
                Ok(SessionOutcome::Closed) => continue,
                Err(e) => {
                    tracing::error!(error = %e, "handoff session ended with error");
                    // If we sealed but didn't commit, try to resume so we keep serving.
                    if self.lock.is_none() {
                        match acquire_with_short_retry(&self.data_dir, RESUME_FLOCK_TIMEOUT) {
                            Ok(lock) => {
                                self.lock = Some(lock);
                                if let Err(e2) = drainable.resume_after_abort() {
                                    tracing::error!(
                                        error = %e2,
                                        "resume_after_abort failed after session error"
                                    );
                                }
                            }
                            Err(e2) => {
                                // The terminal condition is the flock
                                // re-acquire failure — surface that to the
                                // caller rather than the upstream session
                                // error, since this is what actually prevents
                                // recovery. The session error is already in
                                // the log immediately above.
                                tracing::error!(
                                    error = %e2,
                                    "failed to re-acquire flock after session error; \
                                     incumbent cannot resume"
                                );
                                return Err(e2);
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_session<D: Drainable>(
        &mut self,
        mut stream: UnixStream,
        drainable: &D,
    ) -> Result<SessionOutcome> {
        // Incumbent identifies itself first.
        let our_hello = Message::Hello {
            role: Side::Incumbent,
            pid: std::process::id(),
            build_id: self.build_id.clone(),
            proto_min: PROTO_MIN,
            proto_max: PROTO_MAX,
            capabilities: Capabilities::default(),
        };
        write_message(&mut stream, PROTO_MAX, &our_hello)?;

        // Receive HelloAck. Bound the read so a peer that connected and then
        // stalled without responding can't pin the serve loop. `serve()`
        // accepts one session at a time, so a single stuck peer would
        // otherwise block every legitimate handoff.
        stream.set_read_timeout(Some(HELLO_READ_TIMEOUT))?;
        let read_result = read_message(&mut stream);
        let _ = stream.set_read_timeout(None);
        let (_v, ack) = match read_result {
            Ok(x) => x,
            Err(Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Err(Error::Timeout("HelloAck"));
            }
            Err(e) => return Err(e),
        };
        let chosen = match ack {
            Message::HelloAck {
                proto_version_chosen,
                ..
            } => negotiate_version(
                PROTO_MIN,
                PROTO_MAX,
                proto_version_chosen,
                proto_version_chosen,
            )?,
            other => return Err(Error::UnexpectedMessage(short_name(&other))),
        };

        let mut state = SessionState::default();
        let outcome = self.run_session_loop(&mut stream, chosen, drainable, &mut state);

        // Drain-without-commit cleanup. The consumer stopped accepting when we
        // called `drain`; we need to tell them to start again before we leave
        // the session.
        let committed = matches!(outcome, Ok(SessionOutcome::Committed));
        if state.drained
            && !state.sealed
            && !committed
            && let Err(e) = drainable.resume_after_abort()
        {
            tracing::error!(
                error = %e,
                "resume_after_abort during drained-session cleanup failed"
            );
        }
        outcome
    }

    fn run_session_loop<D: Drainable>(
        &mut self,
        stream: &mut UnixStream,
        chosen: u16,
        drainable: &D,
        state: &mut SessionState,
    ) -> Result<SessionOutcome> {
        loop {
            let (_v, msg) = match read_message(stream) {
                Ok(x) => x,
                Err(Error::Io(e))
                    if matches!(
                        e.kind(),
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                    ) =>
                {
                    // Supervisor disconnected. If we sealed, surface as an
                    // error so the serve() loop re-acquires the flock. If we
                    // only drained, the outer cleanup will run resume.
                    if state.sealed {
                        return Err(Error::Protocol(
                            "supervisor disconnected after seal; resuming".into(),
                        ));
                    }
                    return Ok(SessionOutcome::Closed);
                }
                Err(e) => return Err(e),
            };

            match msg {
                Message::PrepareHandoff {
                    handoff_id,
                    deadline_ms,
                    drain_grace_ms,
                    ..
                } => {
                    if let Some(existing) = state.active
                        && existing != handoff_id
                    {
                        return Err(Error::HandoffInProgress);
                    }
                    state.active = Some(handoff_id);
                    let now = Instant::now();
                    let deadline = now + Duration::from_millis(drain_grace_ms.min(deadline_ms));
                    tracing::info!(
                        target: events::PREPARE,
                        %handoff_id, "drain start"
                    );
                    // Heartbeats during drain: the consumer's `drain` may
                    // block for many seconds (drain in-flight requests,
                    // fsync, …). A background thread emits Heartbeat
                    // frames so the supervisor's liveness timer stays
                    // fresh; without this, slow-but-progressing drains
                    // would trip the supervisor's per-recv timeout.
                    let report = run_with_heartbeats(stream, chosen, || drainable.drain(deadline))?;
                    state.drained = true;
                    tracing::info!(
                        target: events::DRAINED,
                        %handoff_id, open_conns_remaining = report.open_conns_remaining,
                        "drain done"
                    );
                    write_message(
                        stream,
                        chosen,
                        &Message::Drained {
                            open_conns_remaining: report.open_conns_remaining,
                            accept_closed: report.accept_closed,
                        },
                    )?;
                    crash_here!(points::O_AFTER_DRAINED_SENT);
                }
                Message::SealRequest { handoff_id } => {
                    if state.active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("SealRequest for unknown id"));
                    }
                    tracing::info!(
                        target: events::SEAL,
                        %handoff_id, "seal start"
                    );
                    // Heartbeats during seal: the consumer's `seal` is
                    // commonly the longest hook in a handoff (flush, fsync,
                    // footer-write per shard). A background thread emits
                    // Heartbeat frames so the supervisor's liveness timer
                    // doesn't trip just because seal is slow — only if O
                    // becomes genuinely unresponsive.
                    let seal_outcome = run_with_heartbeats(stream, chosen, || drainable.seal());
                    match seal_outcome {
                        Ok(report) => {
                            // Release the flock immediately on seal success — N
                            // will acquire it. We continue serving reads until Commit.
                            self.lock.take();
                            state.sealed = true;
                            crash_here!(points::O_AFTER_SEAL_FLOCK_RELEASED);
                            tracing::info!(
                                target: events::SEAL_COMPLETE,
                                %handoff_id, "seal complete; flock released"
                            );
                            write_message(
                                stream,
                                chosen,
                                &Message::SealComplete {
                                    handoff_id,
                                    last_revision_per_shard: report.last_revision_per_shard,
                                    data_dir_fingerprint: report.data_dir_fingerprint,
                                },
                            )?;
                            crash_here!(points::O_AFTER_SEAL_COMPLETE_SENT);
                        }
                        Err(e) => {
                            tracing::error!(
                                %handoff_id, error = %e, "seal failed; remaining as incumbent"
                            );
                            write_message(
                                stream,
                                chosen,
                                &Message::SealFailed {
                                    handoff_id,
                                    error: format!("{e}"),
                                    partial_state: String::new(),
                                },
                            )?;
                            // Lock still held; restart the consumer's accept
                            // loop so it can serve while we wait for a retry.
                            drainable.resume_after_abort()?;
                            state.drained = false;
                            state.active = None;
                        }
                    }
                }
                Message::Commit { handoff_id } => {
                    if state.active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Commit for unknown id"));
                    }
                    if !state.sealed {
                        return Err(Error::Protocol("Commit before SealComplete".into()));
                    }
                    tracing::info!(
                        target: events::COMMIT,
                        %handoff_id, "handoff committed"
                    );
                    crash_here!(points::O_AFTER_COMMIT_RECV);
                    return Ok(SessionOutcome::Committed);
                }
                Message::ResumeAfterAbort { handoff_id } => {
                    if state.active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Resume for unknown id"));
                    }
                    if state.sealed {
                        // Re-acquire the flock first — N is dead so it has
                        // been released. Doing acquire before resume means
                        // that if acquire fails, the serve loop's recovery
                        // path will invoke resume exactly once on retry
                        // rather than producing a double-resume.
                        let lock = DataDirLock::acquire(&self.data_dir)?;
                        self.lock = Some(lock);
                        drainable.resume_after_abort()?;
                        state.sealed = false;
                        state.drained = false;
                        tracing::info!(
                            target: events::RESUME,
                            %handoff_id, "resumed after abort; flock re-acquired"
                        );
                    } else if state.drained {
                        drainable.resume_after_abort()?;
                        state.drained = false;
                    }
                    state.active = None;
                }
                Message::Abort { handoff_id, reason } => {
                    if state.active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Abort for unknown id"));
                    }
                    tracing::warn!(
                        target: events::ABORT,
                        %handoff_id, reason, "handoff aborted"
                    );
                    if state.sealed {
                        // Acquire first, then resume — see the matching
                        // comment in the `ResumeAfterAbort` arm above.
                        let lock = DataDirLock::acquire(&self.data_dir)?;
                        self.lock = Some(lock);
                        drainable.resume_after_abort()?;
                        state.sealed = false;
                        state.drained = false;
                    } else if state.drained {
                        drainable.resume_after_abort()?;
                        state.drained = false;
                    }
                    state.active = None;
                }
                Message::Heartbeat { .. } => {
                    write_message(
                        stream,
                        chosen,
                        &Message::Heartbeat {
                            ts_ms: now_unix_ms(),
                        },
                    )?;
                }
                other => return Err(Error::UnexpectedMessage(short_name(&other))),
            }
        }
    }
}
