//! Successor detection via env vars + inherited listener handling.
//!
//! Spawned-as-successor processes receive their identity through env vars
//! (systemd-style):
//!
//! - `HANDOFF_ROLE=successor`
//! - `HANDOFF_SOCK_FD=<n>` — open Unix socket to supervisor
//! - `LISTEN_FDS=<n>` — count of inherited listener FDs (starting at FD 3)
//! - `LISTEN_FDNAMES=resp:http:…` — colon-separated logical names in FD order
//! - `LISTEN_PID=<pid>` — optional; when present it must equal our pid
//!
//! [`detect_role`] reads these and consumes them so an accidental double-detect
//! gives [`Role::ColdStart`] (which is what fresh re-execs should do).
//!
//! # Why the descriptors are validated before adoption
//!
//! `LISTEN_FDS`/`LISTEN_FDNAMES`/`LISTEN_PID` are systemd's variables, not
//! ours — we speak that convention so a socket-activated unit can cold-start a
//! handoff-aware daemon unchanged. The cost is that these names can arrive
//! from somewhere other than a handoff supervisor, and `FromRawFd` validates
//! nothing: a stale `LISTEN_FDS=3` inherited through an unrelated `execve`
//! would have us wrap FDs 3–5 — possibly a log file, a database connection, or
//! nothing at all — in `TcpListener`s and close them when they drop.
//!
//! Two defenses, in the order the kernel lets us apply them:
//!
//! 1. **`LISTEN_PID`.** systemd always sets it to the pid it is activating.
//!    If it is present and names a different process, the whole block belongs
//!    to an ancestor and is ignored. (The supervisor in this crate cannot set
//!    it — the value is only knowable after `fork`, and `Command`'s
//!    environment is materialized before `pre_exec` runs — so its absence is
//!    not by itself suspicious. Successor identity is instead verified on the
//!    wire by the `Hello` pid check.)
//! 2. **Per-descriptor validation.** Every slot must be an open socket
//!    (`fstat` reports `S_IFSOCK`), and [`InheritedListeners::take`] /
//!    [`InheritedListeners::take_unix`] additionally require the listening
//!    state and the right address family before handing back a typed listener.
//!
//! Adopted descriptors are also normalized: `FD_CLOEXEC` is re-armed (the
//! parent's `dup2` cleared it so the FD could survive `execve`, but leaving it
//! clear leaks listeners and the control socket into every subprocess the
//! daemon later spawns) and `O_NONBLOCK` is cleared (it lives on the open file
//! description, so a parent that gave its listener to an async runtime would
//! otherwise hand us a listener whose first `accept()` returns `EAGAIN`).

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
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::drainable::ReadinessSnapshot;
use crate::error::{Error, Result};
use crate::frame::{read_message, write_frame};
use crate::protocol::{
    Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, ProtoVersion, Side, short_name,
};
use crate::sock;
use crate::util::now_unix_ms;

/// Cadence matched to the incumbent's heartbeat thread; with the
/// supervisor's `LIVENESS_TIMEOUT` of 10s, 2s gives a 5× margin against
/// scheduler hiccups before the supervisor would declare the successor dead.
const SUCCESSOR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

pub const ENV_HANDOFF_ROLE: &str = "HANDOFF_ROLE";
pub const ENV_HANDOFF_SOCK_FD: &str = "HANDOFF_SOCK_FD";
pub const ENV_LISTEN_FDS: &str = "LISTEN_FDS";
pub const ENV_LISTEN_FDNAMES: &str = "LISTEN_FDNAMES";
/// systemd sets this to the pid of the process it is activating. Honored when
/// present; see the module docs for why we never set it ourselves.
pub const ENV_LISTEN_PID: &str = "LISTEN_PID";

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
    /// Consume the inherited TCP listener for `name`.
    ///
    /// Returns `None` if no such listener was passed, if it was already taken,
    /// or if the descriptor is not a listening `AF_INET`/`AF_INET6` socket —
    /// the last case is logged at WARN and leaves the descriptor untouched
    /// rather than wrapping (and eventually closing) a descriptor that belongs
    /// to something else. Use [`Self::take_unix`] for `AF_UNIX` listeners.
    pub fn take(&mut self, name: &str) -> Option<TcpListener> {
        let fd = self.take_validated(
            name,
            &[
                libc::AF_INET as libc::sa_family_t,
                libc::AF_INET6 as libc::sa_family_t,
            ],
            "TCP",
        )?;
        // SAFETY: validated just above as a live, listening AF_INET/AF_INET6
        // socket that the kernel handed us via fork+exec; nothing else in this
        // process owns it, and the map entry is now gone.
        Some(unsafe { TcpListener::from_raw_fd(fd) })
    }

    /// Consume the inherited Unix-domain listener for `name`.
    ///
    /// The same inheritance convention covers `AF_UNIX` listeners — a daemon
    /// serving on a Unix socket has exactly the same reason to keep its
    /// binding across a handoff as one serving TCP, and rebinding the path
    /// would drop connections queued in the backlog.
    pub fn take_unix(&mut self, name: &str) -> Option<UnixListener> {
        let fd = self.take_validated(name, &[libc::AF_UNIX as libc::sa_family_t], "Unix")?;
        // SAFETY: validated as a live, listening AF_UNIX socket owned by us.
        Some(unsafe { UnixListener::from_raw_fd(fd) })
    }

    /// Shared validation for the typed `take*` accessors. Only removes the
    /// entry when the descriptor really is a listening socket of one of
    /// `families`, so a mismatched call can't silently discard a listener the
    /// consumer will ask for again under the right accessor.
    fn take_validated(
        &mut self,
        name: &str,
        families: &[libc::sa_family_t],
        kind: &str,
    ) -> Option<RawFd> {
        let fd = *self.listeners.get(name)?;
        if !sock::fd_is_listening(fd) {
            tracing::warn!(
                name,
                fd,
                "inherited descriptor is not a listening socket; refusing to adopt it"
            );
            return None;
        }
        match sock::socket_family(fd) {
            Some(f) if families.contains(&f) => {}
            other => {
                tracing::warn!(
                    name, fd, family = ?other,
                    "inherited listener is not a {kind} socket; refusing to adopt it"
                );
                return None;
            }
        }
        self.listeners.remove(name);
        Some(fd)
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
    // SAFETY: same single-threaded-startup invariant as the other env
    // mutations in this function.
    unsafe {
        env::remove_var(ENV_LISTEN_PID);
    }
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

    if !sock::fd_is_socket(sock_fd) {
        return Err(Error::BadEnv {
            var: ENV_HANDOFF_SOCK_FD,
            value: format!("fd {sock_fd} is not an open socket"),
        });
    }
    // The control socket needs the same normalization as the listeners: it
    // must not leak into subprocesses (a leaked copy holds the supervisor's
    // EOF open, hiding our death from it) and the protocol code assumes
    // blocking reads.
    normalize_inherited_fd(sock_fd, "control socket");

    // SAFETY: the supervisor handed us this FD via `fork+exec` and we have
    // just confirmed it is an open socket. It's owned by us from here on.
    let control = unsafe { UnixStream::from_raw_fd(sock_fd) };
    if let Err(e) = sock::configure_control_stream(&control, sock::CONTROL_WRITE_TIMEOUT) {
        tracing::warn!(error = %e, "could not configure successor control socket");
    }
    Ok(Role::Successor(Successor { control, inherited }))
}

/// Re-arm `FD_CLOEXEC` and clear `O_NONBLOCK` on an adopted descriptor.
/// Best-effort: a failure is logged and the descriptor is still usable, just
/// with the inherited flag state.
fn normalize_inherited_fd(fd: RawFd, what: &str) {
    if let Err(e) = sock::set_cloexec(fd) {
        tracing::warn!(fd, error = %e, "could not re-arm FD_CLOEXEC on inherited {what}");
    }
    if let Err(e) = sock::clear_nonblocking(fd) {
        tracing::warn!(fd, error = %e, "could not clear O_NONBLOCK on inherited {what}");
    }
}

fn read_inherited_listeners() -> InheritedListeners {
    let count: usize = env::var(ENV_LISTEN_FDS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if count == 0 {
        return InheritedListeners::default();
    }
    // systemd's activation contract: the FD block belongs to the pid named in
    // LISTEN_PID. If it names someone else, we inherited the variables through
    // an intervening exec and the descriptors are not ours to touch.
    if let Ok(raw) = env::var(ENV_LISTEN_PID) {
        let ours = std::process::id();
        match raw.trim().parse::<u32>() {
            Ok(pid) if pid == ours => {}
            other => {
                tracing::warn!(
                    listen_pid = %raw, our_pid = ours, parsed = ?other.ok(),
                    "LISTEN_PID does not name this process; ignoring inherited listeners"
                );
                return InheritedListeners::default();
            }
        }
    }
    let names: Vec<String> = env::var(ENV_LISTEN_FDNAMES)
        .ok()
        .map(|s| s.split(':').map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let mut map = HashMap::with_capacity(count);
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i as RawFd;
        let name = names.get(i).cloned().unwrap_or_else(|| i.to_string());
        if !sock::fd_is_socket(fd) {
            // Either the count over-reports what was passed, or the variables
            // reached us from an unrelated ancestor. Skipping is the only safe
            // response: adopting the slot would hand a `TcpListener` a
            // descriptor it does not own and close it on drop.
            tracing::warn!(
                name,
                fd,
                "LISTEN_FDS names a descriptor that is not an open socket; skipping"
            );
            continue;
        }
        normalize_inherited_fd(fd, "listener");
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
        write_frame(&self.control, PROTO_MAX, &hello)?;
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

    /// Consume the inherited Unix-domain listener for `name`. See
    /// [`InheritedListeners::take_unix`].
    pub fn take_unix_listener(&mut self, name: &str) -> Option<UnixListener> {
        self.inherited.take_unix(name)
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
    pub fn announce_ready(self, snapshot: ReadinessSnapshot) -> Result<()> {
        let ready = Message::Ready {
            handoff_id: self.handoff_id,
            listening_on: snapshot.listening_on,
            healthz_ok: snapshot.healthz_ok,
            advertised_revision_per_shard: snapshot.advertised_revision_per_shard,
        };
        write_frame(&self.control, self.proto_version, &ready)?;
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
            // `recv_timeout` returns Err on timeout — "no stop yet, send
            // another heartbeat". `Ok(())` or any other Err (sender
            // dropped) is the stop signal.
            while stop_rx.recv_timeout(SUCCESSOR_HEARTBEAT_INTERVAL).is_err() {
                let msg = Message::Heartbeat {
                    ts_ms: now_unix_ms(),
                };
                if write_frame(&writer, chosen, &msg).is_err() {
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
    use std::os::fd::AsRawFd;

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

        // LISTEN_PID naming another process: the whole block belongs to an
        // ancestor and must be ignored, however plausible LISTEN_FDS looks.
        // SAFETY: same single-threaded-test invariant as above.
        unsafe {
            env::set_var(ENV_LISTEN_FDS, "3");
            env::set_var(ENV_LISTEN_FDNAMES, "http:grpc:admin");
            env::set_var(ENV_LISTEN_PID, (std::process::id() + 1).to_string());
        }
        match detect_role().unwrap() {
            Role::ColdStart { inherited } => assert!(
                inherited.is_empty(),
                "listeners adopted despite a foreign LISTEN_PID: {:?}",
                inherited.names()
            ),
            _ => panic!("expected ColdStart"),
        }

        // Matching LISTEN_PID: the block is ours, but every slot still has to
        // prove it is an open socket before it lands in the map. Under a test
        // harness those low FDs are the harness's own files and pipes, so a
        // count that over-reports must never produce an adoptable entry.
        // SAFETY: same single-threaded-test invariant as above.
        unsafe {
            env::set_var(ENV_LISTEN_FDS, "3");
            env::remove_var(ENV_LISTEN_FDNAMES);
            env::set_var(ENV_LISTEN_PID, std::process::id().to_string());
        }
        match detect_role().unwrap() {
            Role::ColdStart { inherited } => {
                for (name, fd) in &inherited.listeners {
                    assert!(
                        crate::sock::fd_is_socket(*fd),
                        "adopted non-socket fd {fd} as listener {name}"
                    );
                }
            }
            _ => panic!("expected ColdStart"),
        }

        // SAFETY: same single-threaded-test invariant as above.
        unsafe {
            env::remove_var(ENV_LISTEN_FDS);
            env::remove_var(ENV_LISTEN_PID);
        }
    }

    #[test]
    fn take_and_take_unix_are_family_checked() {
        let dir = tempfile::tempdir().unwrap();
        let unix = crate::sock::bind_socket(&dir.path().join("s.sock")).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut inherited = InheritedListeners {
            listeners: HashMap::from([
                ("unix".to_string(), unix.as_raw_fd()),
                ("tcp".to_string(), tcp.as_raw_fd()),
            ]),
        };

        // Wrong accessor for the family: refuse, and keep the entry so the
        // right accessor still works.
        assert!(inherited.take("unix").is_none());
        assert!(inherited.take_unix("tcp").is_none());

        let adopted_tcp = inherited.take("tcp").expect("tcp listener adoptable");
        let adopted_unix = inherited
            .take_unix("unix")
            .expect("unix listener adoptable");
        assert!(inherited.is_empty());
        // The adopted wrappers own the FDs now; forget the originals so the
        // test doesn't double-close them on drop.
        std::mem::forget(unix);
        std::mem::forget(tcp);
        drop((adopted_tcp, adopted_unix));
    }

    #[test]
    fn take_refuses_a_connected_socket() {
        // A connected (non-listening) socket in a listener slot means the
        // count or the FD order is wrong; adopting it would produce a
        // `TcpListener` whose `accept()` fails forever.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut inherited = InheritedListeners {
            listeners: HashMap::from([("http".to_string(), client.as_raw_fd())]),
        };
        assert!(inherited.take("http").is_none());
    }
}
