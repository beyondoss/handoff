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

// Env mutation (`env::remove_var`, `env::set_var`) is `unsafe` in Rust 2024
// because it races with concurrent env reads in other threads; this module
// is contracted to run before the primitive spawns its serving threads.
// `FromRawFd` is `unsafe` because the safe wrapper assumes exclusive
// ownership; the supervisor handed us the FD via fork+exec, so that holds.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::marker::PhantomData;
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::drainable::ReadinessSnapshot;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_message};
use crate::protocol::{
    Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, short_name,
};
use crate::util::now_unix_ms;

/// Cadence matched to the incumbent's heartbeat thread; with the
/// supervisor's `LIVENESS_TIMEOUT` of 10s, 2s gives a 5× margin against
/// scheduler hiccups before the supervisor would declare the successor dead.
const SUCCESSOR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

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

/// Successor-side state machine, encoded as three concrete types so the
/// compiler enforces protocol ordering. Lifecycle:
///
/// 1. [`detect_role`] returns [`Role::Successor(Successor)`] — initial state.
/// 2. [`Successor::handshake`] consumes self and returns [`HandshookSuccessor`].
/// 3. [`HandshookSuccessor::wait_for_begin`] consumes self and returns
///    [`BegunSuccessor`].
/// 4. From [`BegunSuccessor`] the consumer takes inherited listeners,
///    opens its state, then calls
///    [`BegunSuccessor::announce_and_bind`] (preferred) or
///    [`BegunSuccessor::announce_ready`].
///
/// Out-of-order calls don't compile: there is no path from `Successor` to
/// `take_listener` or `announce_ready` that doesn't pass through every
/// preceding state.
pub struct Successor {
    control: UnixStream,
    inherited: InheritedListeners,
}

/// `Hello`/`HelloAck` exchanged with the supervisor; waiting for `Begin`.
/// Created by [`Successor::handshake`].
pub struct HandshookSuccessor {
    control: UnixStream,
    inherited: InheritedListeners,
    handoff_id: HandoffId,
    proto_version: ProtoVersion,
}

/// `Begin` received from the supervisor; the consumer may now take its
/// inherited listeners, open state, and announce readiness. Created by
/// [`HandshookSuccessor::wait_for_begin`].
pub struct BegunSuccessor {
    control: UnixStream,
    inherited: InheritedListeners,
    handoff_id: HandoffId,
    proto_version: ProtoVersion,
}

/// Inspect the environment and decide whether this process is a fresh start
/// or a successor of a running supervisor.
///
/// In both cases, any `LISTEN_FDS`/`LISTEN_FDNAMES` are consumed into the
/// returned struct so the caller can take ownership of the inherited
/// listeners. Env vars are removed so re-entry yields a clean state.
pub fn detect_role() -> Result<Role> {
    let inherited = read_inherited_listeners();
    // SAFETY: `env::remove_var` races with concurrent env reads on other
    // threads (`std::env::set_var` / `getenv` from libc). `detect_role` is
    // contracted to run during single-threaded startup before the primitive
    // spawns its serving threads — see the module docstring. Callers that
    // violate that contract are responsible for the data race.
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

    // SAFETY: same single-threaded-startup invariant as the listener env
    // removal above; clearing these vars makes a re-entry take the
    // ColdStart branch instead of trying to re-attach to a consumed FD.
    unsafe {
        env::remove_var(ENV_HANDOFF_ROLE);
        env::remove_var(ENV_HANDOFF_SOCK_FD);
    }

    // SAFETY: the supervisor handed us this FD via `fork+exec`. It's open and
    // owned by us from here on.
    let control = unsafe { UnixStream::from_raw_fd(sock_fd) };
    Ok(Role::Successor(Successor { control, inherited }))
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
    /// Send `Hello`, receive `HelloAck`. Consumes self and returns a
    /// [`HandshookSuccessor`] from which the next phase can proceed. On
    /// protocol error the underlying `UnixStream` and inherited listeners
    /// are dropped — the caller has no usable post-error state.
    pub fn handshake(mut self, build_id: Vec<u8>) -> Result<HandshookSuccessor> {
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
            } => Ok(HandshookSuccessor {
                control: self.control,
                inherited: self.inherited,
                handoff_id,
                proto_version: proto_version_chosen,
            }),
            other => Err(Error::UnexpectedMessage(short_name(&other))),
        }
    }

    /// Names of all inherited listeners. Safe to call before `handshake` for
    /// diagnostic / sanity checks (e.g. asserting the supervisor passed the
    /// expected listeners). Listener consumption only happens post-`Begin`
    /// via [`BegunSuccessor::take_listener`].
    pub fn listener_names(&self) -> Vec<String> {
        self.inherited.names()
    }
}

impl HandshookSuccessor {
    /// Block until the supervisor sends `Begin`. Consumes self and returns a
    /// [`BegunSuccessor`] on success. `Abort` from the supervisor surfaces
    /// as [`Error::Aborted`]; `Heartbeat` frames are skipped silently. A
    /// `Begin` with a different handoff id than the one negotiated in
    /// [`Successor::handshake`] returns [`Error::Protocol`] — that's a
    /// supervisor bug, not a recoverable condition.
    pub fn wait_for_begin(mut self) -> Result<BegunSuccessor> {
        let expected = self.handoff_id;
        loop {
            let (_ver, msg) = read_message(&mut self.control)?;
            match msg {
                Message::Begin { handoff_id } if handoff_id == expected => {
                    return Ok(BegunSuccessor {
                        control: self.control,
                        inherited: self.inherited,
                        handoff_id,
                        proto_version: self.proto_version,
                    });
                }
                Message::Begin { handoff_id } => {
                    return Err(Error::Protocol(format!(
                        "Begin handoff_id {handoff_id} does not match \
                         handshake id {expected}"
                    )));
                }
                Message::Abort { reason, .. } => return Err(Error::Aborted(reason)),
                Message::Heartbeat { .. } => continue,
                other => return Err(Error::UnexpectedMessage(short_name(&other))),
            }
        }
    }

    /// Names of all inherited listeners. Diagnostic accessor.
    pub fn listener_names(&self) -> Vec<String> {
        self.inherited.names()
    }

    /// The handoff id negotiated in [`Successor::handshake`].
    pub fn handoff_id(&self) -> HandoffId {
        self.handoff_id
    }
}

impl BegunSuccessor {
    /// Consume the inherited listener for `name`. Returns `None` if no such
    /// listener was passed (or has already been taken).
    pub fn take_listener(&mut self, name: &str) -> Option<TcpListener> {
        self.inherited.take(name)
    }

    /// Names of inherited listeners that haven't yet been taken.
    pub fn listener_names(&self) -> Vec<String> {
        self.inherited.names()
    }

    /// The handoff id negotiated in [`Successor::handshake`].
    pub fn handoff_id(&self) -> HandoffId {
        self.handoff_id
    }

    /// Send `Ready`. Consumes self because once the supervisor knows we're
    /// ready, the main serving loop takes over and this object's job is done.
    ///
    /// # Caveat: don't bind the control socket immediately after this
    ///
    /// After `Ready` is sent there is a brief window during which the
    /// supervisor still has to deliver `Commit` to the prior incumbent and
    /// that incumbent still has to exit. During that window the prior
    /// incumbent is the authoritative owner of the control-socket path;
    /// rebinding from the successor here would unlink its path-binding and
    /// break the abort path if the successor then crashes.
    ///
    /// Prefer [`announce_and_bind`](Self::announce_and_bind) — it combines
    /// `Ready` + bind into one call and is the only path that orders them
    /// correctly by construction. Use this lower-level entry point only
    /// when you genuinely need to delay binding (e.g. for additional
    /// post-`Ready` setup that does not require the control socket).
    pub fn announce_ready(mut self, snapshot: ReadinessSnapshot) -> Result<()> {
        let ready = Message::Ready {
            handoff_id: self.handoff_id,
            listening_on: snapshot.listening_on,
            healthz_ok: snapshot.healthz_ok,
            advertised_revision_per_shard: snapshot.advertised_revision_per_shard,
        };
        write_message(&mut self.control, self.proto_version, &ready)?;
        Ok(())
    }

    /// Send `Ready` to the supervisor, then bind this process as the new
    /// incumbent on `socket_path`. The two operations are combined to
    /// enforce ordering: by the time the bind runs, the supervisor has
    /// observed `Ready` and is about to (or has just) committed the prior
    /// incumbent, so the path-binding takeover is safe.
    ///
    /// This is the safe path for successor processes; cold-start callers
    /// use [`crate::Incumbent::bind_cold_start`] directly.
    pub fn announce_and_bind(
        self,
        snapshot: ReadinessSnapshot,
        socket_path: &std::path::Path,
        lock: crate::DataDirLock,
    ) -> Result<crate::Incumbent> {
        self.announce_ready(snapshot)?;
        crate::Incumbent::bind_after_ready(socket_path, lock)
    }

    /// Spawn a background thread that emits `Heartbeat` frames on the
    /// control socket every ~2s. The returned guard stops + joins the
    /// thread on drop. Use this to keep the supervisor's per-recv
    /// `LIVENESS_TIMEOUT` (10s) from tripping while the successor is
    /// doing slow synchronous init work between `wait_for_begin` and
    /// `announce_and_bind` — DB pool warm-up, state rebuild, TLS load,
    /// etc. Mirrors the incumbent's existing heartbeat thread which
    /// covers `drain` / `seal`.
    ///
    /// # Ordering contract
    ///
    /// **The guard must be dropped before `announce_ready` /
    /// `announce_and_bind`.** While the guard is live, the heartbeat
    /// thread is the sole writer to the control socket; interleaving
    /// the main thread's `Ready` frame with a heartbeat would corrupt
    /// the wire. The borrow of `&self` enforces this: the compiler
    /// rejects any path that calls a consuming method while the guard
    /// is still alive.
    ///
    /// # Failure mode
    ///
    /// On `try_clone` failure (rare; FD table exhausted) the returned
    /// guard is inert — no thread spawned — and a warning is logged.
    /// The supervisor's liveness timer then bounds init in wall-clock
    /// terms exactly as before this API existed.
    pub fn start_heartbeats(&self) -> HeartbeatGuard<'_> {
        HeartbeatGuard::start(&self.control, self.proto_version)
    }
}

/// RAII handle for a successor-side heartbeat thread. See
/// [`BegunSuccessor::start_heartbeats`].
pub struct HeartbeatGuard<'a> {
    stop_tx: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    _borrow: PhantomData<&'a UnixStream>,
}

impl<'a> HeartbeatGuard<'a> {
    fn start(stream: &'a UnixStream, chosen: ProtoVersion) -> Self {
        let writer = match stream.try_clone() {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not clone control stream for successor heartbeats; running without"
                );
                return Self {
                    stop_tx: None,
                    thread: None,
                    _borrow: PhantomData,
                };
            }
        };
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            let mut writer = writer;
            // `recv_timeout` returns Err on timeout — "no stop yet, send
            // another heartbeat". `Ok(())` or any other Err (sender
            // dropped) is the stop signal.
            while stop_rx.recv_timeout(SUCCESSOR_HEARTBEAT_INTERVAL).is_err() {
                let msg = Message::Heartbeat {
                    ts_ms: now_unix_ms(),
                };
                if write_message(&mut writer, chosen, &msg).is_err() {
                    // Supervisor gone or socket broken — no point continuing.
                    return;
                }
            }
        });
        Self {
            stop_tx: Some(stop_tx),
            thread: Some(thread),
            _borrow: PhantomData,
        }
    }
}

impl Drop for HeartbeatGuard<'_> {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env mutation is process-global; run env-touching tests sequentially in
    // one function to avoid races with the cargo test thread pool.
    #[test]
    fn detect_env_branches() {
        // SAFETY: env mutation is process-global and unsafe under
        // concurrent reads. This whole test runs as a single function on
        // one thread; no other code in the test process touches these
        // handoff-specific vars, so there is no concurrent reader to race.
        unsafe {
            env::remove_var(ENV_HANDOFF_ROLE);
            env::remove_var(ENV_HANDOFF_SOCK_FD);
            env::remove_var(ENV_LISTEN_FDS);
            env::remove_var(ENV_LISTEN_FDNAMES);
        }
        assert!(matches!(detect_role().unwrap(), Role::ColdStart { .. }));

        // SAFETY: same single-threaded-test invariant as above.
        unsafe {
            env::set_var(ENV_HANDOFF_ROLE, "other");
        }
        assert!(matches!(detect_role().unwrap(), Role::ColdStart { .. }));
        // SAFETY: same single-threaded-test invariant as above.
        unsafe {
            env::remove_var(ENV_HANDOFF_ROLE);
        }
    }
}
