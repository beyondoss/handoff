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

use crate::drainable::Drainable;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::lock::DataDirLock;
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

impl Incumbent {
    pub fn bind(socket_path: &Path, lock: DataDirLock) -> Result<Self> {
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

        let mut active: Option<HandoffId> = None;
        let mut sealed = false;

        loop {
            let (_v, msg) = match read_message(&mut stream) {
                Ok(x) => x,
                Err(Error::Io(e))
                    if matches!(
                        e.kind(),
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                    ) =>
                {
                    // Supervisor disconnected. If we sealed, we need to recover.
                    if sealed {
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
                    if let Some(existing) = active {
                        if existing != handoff_id {
                            return Err(Error::HandoffInProgress);
                        }
                    }
                    active = Some(handoff_id);
                    let now = Instant::now();
                    let deadline = now + Duration::from_millis(drain_grace_ms.min(deadline_ms));
                    tracing::info!(
                        target: crate::metrics::events::PREPARE,
                        %handoff_id, "drain start"
                    );
                    let report = drainable.drain(deadline)?;
                    tracing::info!(
                        target: crate::metrics::events::DRAINED,
                        %handoff_id, open_conns_remaining = report.open_conns_remaining,
                        "drain done"
                    );
                    write_message(
                        &mut stream,
                        chosen,
                        &Message::Drained {
                            open_conns_remaining: report.open_conns_remaining,
                            accept_closed: report.accept_closed,
                        },
                    )?;
                }
                Message::SealRequest { handoff_id } => {
                    if active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("SealRequest for unknown id"));
                    }
                    tracing::info!(
                        target: crate::metrics::events::SEAL,
                        %handoff_id, "seal start"
                    );
                    match drainable.seal() {
                        Ok(report) => {
                            // Release the flock immediately on seal success — N
                            // will acquire it. We continue serving reads until Commit.
                            self.lock.take();
                            sealed = true;
                            tracing::info!(
                                target: crate::metrics::events::SEAL_COMPLETE,
                                %handoff_id, "seal complete; flock released"
                            );
                            write_message(
                                &mut stream,
                                chosen,
                                &Message::SealComplete {
                                    handoff_id,
                                    last_revision_per_shard: report.last_revision_per_shard,
                                    data_dir_fingerprint: report.data_dir_fingerprint,
                                },
                            )?;
                        }
                        Err(e) => {
                            tracing::error!(
                                %handoff_id, error = %e, "seal failed; remaining as incumbent"
                            );
                            write_message(
                                &mut stream,
                                chosen,
                                &Message::SealFailed {
                                    handoff_id,
                                    error: format!("{e}"),
                                    partial_state: String::new(),
                                },
                            )?;
                            // Lock still held; supervisor will Abort N. We can
                            // safely accept a future PrepareHandoff.
                            active = None;
                        }
                    }
                }
                Message::Commit { handoff_id } => {
                    if active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Commit for unknown id"));
                    }
                    if !sealed {
                        return Err(Error::Protocol("Commit before SealComplete".into()));
                    }
                    tracing::info!(
                        target: crate::metrics::events::COMMIT,
                        %handoff_id, "handoff committed"
                    );
                    return Ok(SessionOutcome::Committed);
                }
                Message::ResumeAfterAbort { handoff_id } => {
                    if active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Resume for unknown id"));
                    }
                    if sealed {
                        drainable.resume_after_abort()?;
                        // Re-acquire the flock — N is dead so it has been released.
                        let lock = DataDirLock::acquire(&self.data_dir)?;
                        self.lock = Some(lock);
                        sealed = false;
                        tracing::info!(
                            target: crate::metrics::events::RESUME,
                            %handoff_id, "resumed after abort; flock re-acquired"
                        );
                    }
                    active = None;
                }
                Message::Abort { handoff_id, reason } => {
                    if active != Some(handoff_id) {
                        return Err(Error::UnexpectedMessage("Abort for unknown id"));
                    }
                    tracing::warn!(
                        target: crate::metrics::events::ABORT,
                        %handoff_id, reason, "handoff aborted"
                    );
                    if sealed {
                        drainable.resume_after_abort()?;
                        let lock = DataDirLock::acquire(&self.data_dir)?;
                        self.lock = Some(lock);
                        sealed = false;
                    }
                    active = None;
                }
                Message::Heartbeat { .. } => {
                    write_message(
                        &mut stream,
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
