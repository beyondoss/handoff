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
use std::time::{Duration, Instant};

use crate::crash::points;
use crate::crash_here;
use crate::drainable::Drainable;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::lock::DataDirLock;
use crate::metrics::events;
use crate::protocol::{
    Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, Side, negotiate_version,
};

pub struct Incumbent {
    listener: UnixListener,
    lock: Option<DataDirLock>,
    data_dir: PathBuf,
    build_id: Vec<u8>,
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
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Remove any stale socket file left by a crashed predecessor.
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        let data_dir = lock.data_dir().to_path_buf();
        Ok(Self {
            listener,
            lock: Some(lock),
            data_dir,
            build_id: Vec::new(),
        })
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
                        match DataDirLock::acquire(&self.data_dir) {
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
                                tracing::error!(
                                    error = %e2,
                                    "failed to re-acquire flock after session error; \
                                     incumbent cannot resume"
                                );
                                return Err(e);
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

        // Receive HelloAck.
        let (_v, ack) = read_message(&mut stream)?;
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
                    let report = drainable.drain(deadline)?;
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
                    match drainable.seal() {
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

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn short_name(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "Hello (unexpected)",
        Message::HelloAck { .. } => "HelloAck (unexpected)",
        Message::PrepareHandoff { .. } => "PrepareHandoff (unexpected)",
        Message::Drained { .. } => "Drained (unexpected)",
        Message::SealRequest { .. } => "SealRequest (unexpected)",
        Message::SealProgress { .. } => "SealProgress (unexpected)",
        Message::SealComplete { .. } => "SealComplete (unexpected)",
        Message::SealFailed { .. } => "SealFailed (unexpected)",
        Message::Begin { .. } => "Begin (unexpected)",
        Message::Ready { .. } => "Ready (unexpected)",
        Message::Commit { .. } => "Commit (unexpected)",
        Message::Abort { .. } => "Abort (unexpected)",
        Message::ResumeAfterAbort { .. } => "ResumeAfterAbort (unexpected)",
        Message::Heartbeat { .. } => "Heartbeat (unexpected)",
    }
}
