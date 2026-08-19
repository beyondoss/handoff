//! Unix-domain socket helpers shared by the incumbent, the supervisor, and
//! the reference binary.
//!
//! Four concerns live here, all of them platform mechanics that the protocol
//! code above should not have to restate:
//!
//! - **`sun_path` validation.** `bind(2)` truncates or rejects paths longer
//!   than `sockaddr_un.sun_path` (108 bytes on Linux, 104 on macOS/BSD).
//!   Catching that up front turns a confusing `EINVAL`/silent-truncation into
//!   [`Error::SocketPathTooLong`].
//! - **Atomic, private bind.** [`bind_socket`] binds a temporary name in the
//!   target directory, tightens the mode to `0600`, then `rename(2)`s it over
//!   the final path. There is never a window in which the published path is
//!   either missing (unlink-then-bind) or world-writable (bind-then-chmod).
//! - **Peer authentication.** [`peer_uid`] reads the connecting process's uid
//!   from the kernel (`SO_PEERCRED` on Linux, `getpeereid(3)` elsewhere), so a
//!   control socket can refuse commands from other local users even if the
//!   filesystem permissions were loosened by an operator.
//! - **SIGPIPE-safe writes.** [`send_all`] uses `MSG_NOSIGNAL` where the
//!   platform has it and `SO_NOSIGPIPE` where it doesn't, so a write to a
//!   control socket whose peer just died surfaces as `EPIPE` instead of a
//!   process-killing signal.

// Every routine here is a thin wrapper over a libc socket call; the raw FFI
// is the point of the module. Each block carries its own SAFETY note.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};

/// Mode applied to a bound control socket: owner read/write only. Peer
/// authentication ([`peer_uid`]) is the real access control; this keeps the
/// filesystem from being the weak link when the process runs under a lax
/// umask (the default `bind(2)` mode is `0777 & ~umask`, i.e. world-writable
/// under `umask 0`).
const SOCKET_MODE: u32 = 0o600;

/// Bound on any single write to a control socket. Matches the supervisor's
/// per-recv liveness timeout: a peer that has not drained our frame within
/// the window it is allowed to go silent is unresponsive by the same
/// definition, and the handoff should fail rather than park a thread in an
/// unbounded `write(2)`.
pub const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Usable bytes in `sockaddr_un.sun_path`, minus the NUL terminator.
pub fn max_socket_path_len() -> usize {
    // SAFETY: reading the size of a field on a zeroed POD struct; no
    // dereference of uninitialized memory beyond `size_of_val`.
    let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    std::mem::size_of_val(&addr.sun_path) - 1
}

/// Reject a socket path the kernel could not represent in `sockaddr_un`.
///
/// Callers should run this before any `bind`/`connect` so an over-long path
/// fails with a diagnosable error naming the limit, rather than an `EINVAL`
/// (Linux) or a silently truncated binding (some BSDs).
pub fn validate_socket_path(path: &Path) -> Result<()> {
    let len = path.as_os_str().len();
    let max = max_socket_path_len();
    if len > max {
        return Err(Error::SocketPathTooLong {
            path: path.to_path_buf(),
            len,
            max,
        });
    }
    Ok(())
}

/// Bind a Unix listener at `path`, atomically and with mode `0600`.
///
/// The bind happens on a temporary sibling name, which is chmod'ed and then
/// `rename(2)`d over `path`. Two properties follow:
///
/// - **Atomic replacement.** A client connecting during a rebind sees either
///   the old binding or the new one, never `ENOENT`. The unlink-then-bind
///   alternative has a window where the path does not exist, and a second
///   binder racing in that window silently steals the name.
/// - **No permissive window.** The socket is never reachable at its published
///   path while its mode is still whatever `0777 & ~umask` produced.
///
/// Any existing binding at `path` is replaced. Callers are responsible for
/// establishing that replacing it is safe (see [`crate::Incumbent`]).
pub fn bind_socket(path: &Path) -> Result<UnixListener> {
    validate_socket_path(path)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let staging = staging_path(path)?;
    validate_socket_path(&staging)?;

    // A leftover staging file (previous process killed mid-bind) is ours to
    // remove: the name embeds our pid and a per-call counter.
    let _ = std::fs::remove_file(&staging);
    let listener = UnixListener::bind(&staging)?;
    let bind_result = (|| -> io::Result<()> {
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(SOCKET_MODE))?;
        std::fs::rename(&staging, path)
    })();
    if let Err(e) = bind_result {
        drop(listener);
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }
    set_cloexec(listener.as_raw_fd())?;
    Ok(listener)
}

/// Sibling path used as the staging name for [`bind_socket`]. The file name
/// is deliberately short (pid + counter, not the full target name) so the
/// staging path stays inside `sun_path` even when the target is close to the
/// limit.
fn staging_path(path: &Path) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let parent = path.parent().unwrap_or(Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok(parent.join(format!(".ho-{}-{seq}.tmp", std::process::id())))
}

/// The uid of the process on the other end of `stream`.
///
/// Reported by the kernel at `connect(2)` time, so it cannot be forged by the
/// peer and does not race with the peer exiting (the credentials are latched
/// with the connection, not looked up per call).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a live, correctly-sized `ucred`; `len` matches it.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut c_void,
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The uid of the process on the other end of `stream`. macOS and the BSDs
/// expose the latched credentials through `getpeereid(3)` rather than a
/// `SO_PEERCRED` socket option.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: both out-params are live locals of the expected types.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// True if `uid` may drive the control protocol on this process's socket.
///
/// Our own effective uid is allowed (the normal case: supervisor and
/// primitive run as the same service account) and so is root, which can
/// `ptrace`/`kill` us anyway — refusing it would buy nothing and would break
/// legitimate operator tooling. Everything else is rejected: a drain+seal is
/// a privileged operation on the daemon's data directory.
pub fn peer_uid_is_allowed(uid: u32, extra_allowed: &[u32]) -> bool {
    // SAFETY: `geteuid` cannot fail and touches no memory.
    let euid = unsafe { libc::geteuid() };
    uid == euid || uid == 0 || extra_allowed.contains(&uid)
}

/// Set `FD_CLOEXEC` on `fd`, preserving other descriptor flags.
///
/// Inherited descriptors arrive CLOEXEC-cleared (that is how they survived
/// `execve`); re-arming the flag keeps a listener or control socket from
/// leaking into every subprocess the daemon later spawns. A leaked control
/// socket is not merely untidy: it holds the peer's EOF open, so the
/// supervisor cannot detect that the primitive died.
pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor owned by the caller; F_GETFD/F_SETFD
    // only read and write that descriptor's flag word.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Clear `O_NONBLOCK` on `fd`, preserving other status flags.
///
/// `O_NONBLOCK` lives on the *open file description*, not the descriptor, so
/// it survives `dup2` and `execve`. A parent that handed its listener to an
/// async runtime therefore passes a non-blocking listener to the child, whose
/// first `accept()` returns `EAGAIN` — a spurious "no connection" that a
/// blocking-API consumer has no reason to expect.
pub fn clear_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor; F_GETFL/F_SETFL only touch its
    // status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0 {
        return Ok(());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True if `fd` is open and refers to a socket. Used before adopting an
/// inherited descriptor: `FromRawFd` performs no validation, so a bogus
/// `LISTEN_FDS` count would otherwise wrap an unrelated descriptor (or a
/// closed one) in a `TcpListener` and later close it out from under its real
/// owner.
pub fn fd_is_socket(fd: RawFd) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a live, correctly-sized `stat`. `fstat` on a closed or
    // invalid fd returns EBADF rather than misbehaving.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
}

/// Address family of the socket behind `fd` (`AF_INET`, `AF_UNIX`, …), or
/// `None` if `fd` is not a bound socket. Read via `getsockname(2)` because
/// `SO_DOMAIN` is Linux-only.
pub fn socket_family(fd: RawFd) -> Option<libc::sa_family_t> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `storage` is a live, correctly-sized `sockaddr_storage` and
    // `len` describes it accurately.
    let rc = unsafe {
        libc::getsockname(
            fd,
            &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut len,
        )
    };
    if rc == -1 {
        return None;
    }
    Some(storage.ss_family)
}

/// True if `fd` is a socket in the listening state.
///
/// `SO_ACCEPTCONN` answers this directly on Linux. It is not dependable
/// elsewhere — XNU's `sogetopt` does not report it for every socket kind —
/// so on other Unices a negative answer falls back to the shape a listener
/// has: a stream socket with no peer. `getpeername(2)` returns `ENOTCONN`
/// for a listener and succeeds for a connected socket, which is the
/// distinction the callers actually need (a bound-but-not-listening socket
/// is indistinguishable this way, and merely surfaces later as an `accept`
/// error rather than as a silently adopted wrong descriptor).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn fd_is_listening(fd: RawFd) -> bool {
    accept_conn_opt(fd).unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn fd_is_listening(fd: RawFd) -> bool {
    accept_conn_opt(fd).unwrap_or(false)
        || (socket_type(fd) == Some(libc::SOCK_STREAM) && !socket_is_connected(fd))
}

/// `SO_ACCEPTCONN`, or `None` where the platform does not implement it.
fn accept_conn_opt(fd: RawFd) -> Option<bool> {
    let mut val: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `val`/`len` are live locals of the sizes the option expects.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut val as *mut libc::c_int as *mut c_void,
            &mut len,
        )
    };
    if rc == 0 {
        return Some(val != 0);
    }
    // EBADF/ENOTSOCK are real answers: not a listening socket.
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) => None,
        _ => Some(false),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut val: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `val`/`len` are live locals of the sizes the option expects.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut libc::c_int as *mut c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(val)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn socket_is_connected(fd: RawFd) -> bool {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `storage` is a live, correctly-sized `sockaddr_storage` and
    // `len` describes it accurately.
    let rc = unsafe {
        libc::getpeername(
            fd,
            &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut len,
        )
    };
    rc == 0
}

/// Prepare a control-socket endpoint: close-on-exec, SIGPIPE suppression
/// where it is a socket option, and a bounded write timeout.
///
/// The write timeout matters as much as the read timeouts the protocol code
/// already arms. Without `SO_SNDTIMEO`, a peer that stops reading (stuck in a
/// consumer hook, or `SIGSTOP`ped) lets our socket buffer fill and parks the
/// writer in an uninterruptible `write(2)` forever — the one place in the
/// handoff where neither the liveness clock nor the overall deadline is
/// running, because both are enforced on the read side.
pub fn configure_control_stream(stream: &UnixStream, write_timeout: Duration) -> io::Result<()> {
    set_cloexec(stream.as_raw_fd())?;
    set_nosigpipe(stream.as_raw_fd());
    // A closed peer makes `setsockopt` return EINVAL on macOS/BSD (see
    // `supervisor::arm_recv_timeout` for the full story). A write to that
    // socket cannot block, so the missing timeout is harmless.
    match stream.set_write_timeout(Some(write_timeout)) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Ask the kernel to report `EPIPE` instead of raising `SIGPIPE` on this
/// socket. Only meaningful on platforms with the option; Linux uses the
/// per-call `MSG_NOSIGNAL` flag in [`send_all`] instead. Best-effort: a
/// failure here leaves the process's SIGPIPE disposition in charge.
#[allow(unused_variables)]
fn set_nosigpipe(fd: RawFd) {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        let val: libc::c_int = 1;
        // SAFETY: `val` is a live `c_int` and the length matches it.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &val as *const libc::c_int as *const c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// Write `buf` to `stream` in full, never raising `SIGPIPE`.
///
/// Rust's runtime ignores `SIGPIPE` by default, but that is a property of the
/// *binary*, not of this library: a consumer that restores the default
/// disposition (common in CLI-shaped daemons that want to die politely when
/// piped into `head`) would otherwise be killed outright when a peer dies
/// mid-handoff. Suppressing the signal here makes the failure an ordinary
/// `EPIPE` that the protocol code already knows how to handle.
pub(crate) fn send_all(stream: &UnixStream, buf: &[u8]) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const FLAGS: libc::c_int = 0;

    let mut sent = 0usize;
    while sent < buf.len() {
        // SAFETY: `buf[sent..]` is a live slice; `send` writes at most
        // `len` bytes from it and never retains the pointer.
        let n = unsafe {
            libc::send(
                stream.as_raw_fd(),
                buf[sent..].as_ptr() as *const c_void,
                buf.len() - sent,
                FLAGS,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        sent += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_over_long_socket_path() {
        let long = PathBuf::from("/tmp").join("x".repeat(max_socket_path_len()));
        match validate_socket_path(&long) {
            Err(Error::SocketPathTooLong { len, max, .. }) => {
                assert!(len > max);
                assert_eq!(max, max_socket_path_len());
            }
            other => panic!("expected SocketPathTooLong, got {other:?}"),
        }
    }

    #[test]
    fn bind_produces_owner_only_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctl.sock");
        let listener = bind_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, SOCKET_MODE,
            "socket must not be group/world reachable"
        );
        // No staging files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "staging file leaked: {leftovers:?}");
        drop(listener);
    }

    #[test]
    fn rebind_replaces_path_without_a_missing_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctl.sock");
        let first = bind_socket(&path).unwrap();
        let first_ino = inode_of(&path);
        // The second bind takes over the name atomically; the path exists
        // continuously and now refers to the new socket.
        let second = bind_socket(&path).unwrap();
        assert!(path.exists());
        assert_ne!(first_ino, inode_of(&path));
        // The displaced listener is still open (its binding is just
        // unreachable by name), which is what lets the prior incumbent keep
        // serving already-accepted sessions.
        assert!(fd_is_listening(first.as_raw_fd()));
        drop(second);
    }

    #[test]
    fn cloexec_and_blocking_normalization_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let listener = bind_socket(&dir.path().join("s.sock")).unwrap();
        let fd = listener.as_raw_fd();
        listener.set_nonblocking(true).unwrap();
        for _ in 0..2 {
            clear_nonblocking(fd).unwrap();
            set_cloexec(fd).unwrap();
        }
        // SAFETY: probing flags on a live fd we own.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(fl & libc::O_NONBLOCK, 0);
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn socket_introspection_distinguishes_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let listener = bind_socket(&dir.path().join("s.sock")).unwrap();
        assert!(fd_is_socket(listener.as_raw_fd()));
        assert!(fd_is_listening(listener.as_raw_fd()));
        assert_eq!(
            socket_family(listener.as_raw_fd()),
            Some(libc::AF_UNIX as libc::sa_family_t)
        );

        let file = std::fs::File::create(dir.path().join("plain")).unwrap();
        assert!(!fd_is_socket(file.as_raw_fd()));
        assert!(!fd_is_listening(file.as_raw_fd()));

        let conn = UnixStream::connect(dir.path().join("s.sock")).unwrap();
        assert!(fd_is_socket(conn.as_raw_fd()));
        assert!(!fd_is_listening(conn.as_raw_fd()));
    }

    #[test]
    fn peer_uid_matches_our_own_for_a_local_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let listener = bind_socket(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        // SAFETY: `geteuid` cannot fail.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&server).unwrap(), euid);
        assert!(peer_uid_is_allowed(euid, &[]));
        assert!(!peer_uid_is_allowed(euid.wrapping_add(1), &[]));
        assert!(peer_uid_is_allowed(euid.wrapping_add(1), &[euid + 1]));
    }

    fn inode_of(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().ino()
    }
}
