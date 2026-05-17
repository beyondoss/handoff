//! Successor detection via env vars + inherited listener handling.
//!
//! Spawned-as-successor processes receive their identity through env vars
//! (systemd-style):
//!
//! - `HANDOFF_ROLE=successor`
//! - `HANDOFF_SOCK_FD=<n>` — open Unix socket to supervisor
//! - `LISTEN_FDS=<n>` — count of inherited listener FDs (starting at FD 3)
//! - `LISTEN_FDNAMES=resp:http:…` — colon-separated logical names in FD order
//!
//! [`detect_role`] reads these and consumes them so an accidental double-detect
//! gives [`Role::ColdStart`] (which is what fresh re-execs should do).

use std::collections::HashMap;
use std::env;
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::drainable::ReadinessSnapshot;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::protocol::{Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side};

pub const ENV_HANDOFF_ROLE: &str = "HANDOFF_ROLE";
pub const ENV_HANDOFF_SOCK_FD: &str = "HANDOFF_SOCK_FD";
pub const ENV_LISTEN_FDS: &str = "LISTEN_FDS";
pub const ENV_LISTEN_FDNAMES: &str = "LISTEN_FDNAMES";

/// Inherited listener FDs start here, matching the systemd convention.
pub const SD_LISTEN_FDS_START: RawFd = 3;

pub enum Role {
    /// No `HANDOFF_ROLE` env var was set. This is a fresh boot — either a
    /// supervisor's first spawn (in which case `inherited` may carry listeners)
    /// or an unsupervised local-dev run (in which case `inherited` is empty
    /// and the primitive binds its own listeners).
    ColdStart { inherited: InheritedListeners },
    /// Spawned as a successor mid-handoff. Use the embedded [`Successor`] to
    /// drive the protocol (handshake, wait_for_begin, take_listener, announce_ready).
    Successor(Successor),
}

/// Listener FDs handed in via `LISTEN_FDS` / `LISTEN_FDNAMES`. Available on
/// both `ColdStart` (supervisor's first spawn) and inside `Successor`.
#[derive(Default)]
pub struct InheritedListeners {
    listeners: HashMap<String, RawFd>,
}

impl InheritedListeners {
    /// Consume the inherited listener for `name`. Returns `None` if no such
    /// listener was passed (or it was already taken).
    pub fn take(&mut self, name: &str) -> Option<TcpListener> {
        let fd = self.listeners.remove(name)?;
        // SAFETY: kernel inherited the FD to us via fork+exec; we own it.
        Some(unsafe { TcpListener::from_raw_fd(fd) })
    }

    /// Names of all listeners that haven't yet been taken.
    pub fn names(&self) -> Vec<String> {
        self.listeners.keys().cloned().collect()
    }

    /// True if no listeners were inherited (or all have been taken).
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

/// Successor-side state. Created by [`detect_role`] when the spawning supervisor
/// has populated the env vars above. The successor uses this to:
///
/// 1. Handshake with the supervisor (`handshake`).
/// 2. Wait for the supervisor's `Begin` cue (`wait_for_begin`).
/// 3. Take each inherited listener (`take_listener`).
/// 4. Open its state, then announce readiness (`announce_ready`).
pub struct Successor {
    control: UnixStream,
    handoff_id: Option<HandoffId>,
    proto_version: Option<ProtoVersion>,
    inherited: InheritedListeners,
}

/// Inspect the environment and decide whether this process is a fresh start
/// or a successor of a running supervisor.
///
/// In both cases, any `LISTEN_FDS`/`LISTEN_FDNAMES` are consumed into the
/// returned struct so the caller can take ownership of the inherited
/// listeners. Env vars are removed so re-entry yields a clean state.
pub fn detect_role() -> Result<Role> {
    let inherited = read_inherited_listeners();
    // Remove listener env vars regardless of role.
    unsafe {
        env::remove_var(ENV_LISTEN_FDS);
        env::remove_var(ENV_LISTEN_FDNAMES);
    }

    match env::var(ENV_HANDOFF_ROLE) {
        Ok(s) if s == "successor" => {}
        _ => return Ok(Role::ColdStart { inherited }),
    }

    let sock_raw =
        env::var(ENV_HANDOFF_SOCK_FD).map_err(|_| Error::MissingEnv(ENV_HANDOFF_SOCK_FD))?;
    let sock_fd: RawFd = sock_raw.parse().map_err(|_| Error::BadEnv {
        var: ENV_HANDOFF_SOCK_FD,
        value: sock_raw,
    })?;

    // Consume successor-only env vars so a re-entry takes the ColdStart branch.
    unsafe {
        env::remove_var(ENV_HANDOFF_ROLE);
        env::remove_var(ENV_HANDOFF_SOCK_FD);
    }

    // SAFETY: the supervisor handed us this FD via `fork+exec`. It's open and
    // owned by us from here on.
    let control = unsafe { UnixStream::from_raw_fd(sock_fd) };
    Ok(Role::Successor(Successor {
        control,
        handoff_id: None,
        proto_version: None,
        inherited,
    }))
}

fn read_inherited_listeners() -> InheritedListeners {
    let count: usize = env::var(ENV_LISTEN_FDS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if count == 0 {
        return InheritedListeners::default();
    }
    let names: Vec<String> = env::var(ENV_LISTEN_FDNAMES)
        .ok()
        .map(|s| s.split(':').map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let mut map = HashMap::with_capacity(count);
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i as RawFd;
        let name = names.get(i).cloned().unwrap_or_else(|| i.to_string());
        map.insert(name, fd);
    }
    InheritedListeners { listeners: map }
}

impl Successor {
    /// Send `Hello`, receive `HelloAck`. Returns the negotiated handoff id.
    pub fn handshake(&mut self, build_id: Vec<u8>) -> Result<HandoffId> {
        let hello = Message::Hello {
            role: Side::Successor,
            pid: std::process::id(),
            build_id,
            proto_min: PROTO_MIN,
            proto_max: PROTO_MAX,
            capabilities: Capabilities::default(),
        };
        write_message(&mut self.control, PROTO_MAX, &hello)?;
        let (_ver, ack) = read_message(&mut self.control)?;
        match ack {
            Message::HelloAck {
                proto_version_chosen,
                handoff_id,
            } => {
                self.handoff_id = Some(handoff_id);
                self.proto_version = Some(proto_version_chosen);
                Ok(handoff_id)
            }
            other => Err(Error::UnexpectedMessage(message_name(&other))),
        }
    }

    /// Block until the supervisor sends `Begin`. Returns the handoff id (must
    /// match the one from `handshake`).
    pub fn wait_for_begin(&mut self) -> Result<HandoffId> {
        let (_ver, msg) = read_message(&mut self.control)?;
        match msg {
            Message::Begin { handoff_id } => Ok(handoff_id),
            other => Err(Error::UnexpectedMessage(message_name(&other))),
        }
    }

    /// Consume the inherited listener for `name`. Returns `None` if no such
    /// listener was passed (or has already been taken).
    pub fn take_listener(&mut self, name: &str) -> Option<TcpListener> {
        self.inherited.take(name)
    }

    /// Names of all listeners that haven't yet been taken.
    pub fn listener_names(&self) -> Vec<String> {
        self.inherited.names()
    }

    /// Send `Ready`. Consumes self because once the supervisor knows we're
    /// ready, the main serving loop takes over and this object's job is done.
    pub fn announce_ready(mut self, snapshot: ReadinessSnapshot) -> Result<()> {
        let handoff_id = self
            .handoff_id
            .ok_or_else(|| Error::Protocol("announce_ready called before handshake".into()))?;
        let ver = self.proto_version.unwrap_or(PROTO_MAX);
        let ready = Message::Ready {
            handoff_id,
            listening_on: snapshot.listening_on,
            healthz_ok: snapshot.healthz_ok,
            advertised_revision_per_shard: snapshot.advertised_revision_per_shard,
        };
        write_message(&mut self.control, ver, &ready)?;
        Ok(())
    }

    /// Negotiated handoff id (after `handshake`).
    pub fn handoff_id(&self) -> Option<HandoffId> {
        self.handoff_id
    }
}

fn message_name(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "expected HelloAck, got Hello",
        Message::HelloAck { .. } => "expected HelloAck",
        Message::PrepareHandoff { .. } => "expected HelloAck/Begin, got PrepareHandoff",
        Message::Drained { .. } => "expected HelloAck/Begin, got Drained",
        Message::SealRequest { .. } => "expected HelloAck/Begin, got SealRequest",
        Message::SealProgress { .. } => "expected HelloAck/Begin, got SealProgress",
        Message::SealComplete { .. } => "expected HelloAck/Begin, got SealComplete",
        Message::SealFailed { .. } => "expected HelloAck/Begin, got SealFailed",
        Message::Begin { .. } => "expected Begin",
        Message::Ready { .. } => "expected HelloAck/Begin, got Ready",
        Message::Commit { .. } => "expected HelloAck/Begin, got Commit",
        Message::Abort { .. } => "expected HelloAck/Begin, got Abort",
        Message::ResumeAfterAbort { .. } => "expected HelloAck/Begin, got ResumeAfterAbort",
        Message::Heartbeat { .. } => "expected HelloAck/Begin, got Heartbeat",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env mutation is process-global; run env-touching tests sequentially in
    // one function to avoid races with the cargo test thread pool.
    #[test]
    fn detect_env_branches() {
        // Clean env first; some other test or the user shell may have set them.
        unsafe {
            env::remove_var(ENV_HANDOFF_ROLE);
            env::remove_var(ENV_HANDOFF_SOCK_FD);
            env::remove_var(ENV_LISTEN_FDS);
            env::remove_var(ENV_LISTEN_FDNAMES);
        }
        assert!(matches!(detect_role().unwrap(), Role::ColdStart { .. }));

        unsafe {
            env::set_var(ENV_HANDOFF_ROLE, "other");
        }
        assert!(matches!(detect_role().unwrap(), Role::ColdStart { .. }));
        unsafe {
            env::remove_var(ENV_HANDOFF_ROLE);
        }
    }
}
