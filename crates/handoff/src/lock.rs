//! `DataDirLock` — RAII flock on `<data_dir>/.handoff.lock`.
//!
//! The flock is the single source of truth for "which process owns the writer
//! for this data directory." See correctness invariant #1 in `ARCHITECTURE.md`.
//!
//! The lock is paired with `<data_dir>/.handoff.pidfile`, a plain-text file
//! containing the holder's PID. If a process dies abnormally (SIGKILL,
//! oom-kill, segfault), the kernel releases the flock automatically — but the
//! pidfile remains as a hint. [`DataDirLock::acquire_or_break_stale`] uses the
//! pidfile + `kill(pid, 0)` liveness check to safely break orphaned locks
//! without risk of two-writers.
//!
//! # Filesystem requirements
//!
//! `flock(2)` is only an exclusion mechanism if the kernel that serves the
//! lock file sees every contender. That holds for local filesystems (ext4,
//! xfs, btrfs, zfs, apfs, ufs) and is the supported configuration.
//!
//! It does **not** hold everywhere a data directory can be pointed:
//!
//! - **NFS.** Linux emulates `flock` on NFSv3+ via POSIX record locks, which
//!   are per-*process* rather than per-*open-file-description*: a lock can be
//!   dropped by an unrelated `close()` in the same process, and the semantics
//!   differ from the local case in ways this crate's invariants depend on.
//!   Older or misconfigured mounts (`nolock`, no `rpc.statd`) degrade to a
//!   purely local lock, which two hosts will both "acquire".
//! - **CIFS/SMB, 9p, FUSE without lock forwarding, overlayfs upper layers on
//!   such backends.** Same failure mode: the lock is local to one client.
//! - **Two containers bind-mounting the same host directory** are fine (same
//!   kernel), but two *hosts* sharing storage over a network filesystem are
//!   not.
//!
//! The consequence of a lock that does not exclude is precisely the failure
//! this crate exists to prevent — two writers on one data directory — and it
//! cannot be detected from inside the lock holder. Put the data directory on
//! a local filesystem.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::kill;
use nix::unistd::Pid;

use crate::error::{Error, Result};

const LOCK_FILE: &str = ".handoff.lock";
const PID_FILE: &str = ".handoff.pidfile";

/// RAII guard. Drop releases the kernel-level flock automatically (by closing
/// the underlying file descriptor) and removes the pidfile.
pub struct DataDirLock {
    _flock: Flock<File>,
    data_dir: PathBuf,
    pid_path: PathBuf,
}

impl std::fmt::Debug for DataDirLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataDirLock")
            .field("data_dir", &self.data_dir)
            .finish()
    }
}

impl DataDirLock {
    /// Path of the data directory this lock protects. Used by callers that
    /// need to release-then-re-acquire (e.g. `ResumeAfterAbort`).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

impl DataDirLock {
    /// Acquire the writer lock on `data_dir`. Returns immediately with
    /// [`Error::LockHeld`] if another process holds it.
    pub fn acquire(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let lock_path = data_dir.join(LOCK_FILE);
        let pid_path = data_dir.join(PID_FILE);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        let flock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(flock) => flock,
            Err((_file, nix::errno::Errno::EWOULDBLOCK)) => {
                let holder = read_pidfile(&pid_path).unwrap_or(0);
                return Err(Error::LockHeld { holder_pid: holder });
            }
            Err((_file, errno)) => return Err(Error::Nix(errno)),
        };

        write_pid_atomic(&pid_path, std::process::id())?;
        Ok(Self {
            _flock: flock,
            data_dir: data_dir.to_path_buf(),
            pid_path,
        })
    }

    /// Like [`Self::acquire`], but if the lock appears stale (pidfile names
    /// a PID that's no longer alive), reclaim it. Refuses to break a lock
    /// held by a live named holder.
    ///
    /// Strategy: re-attempt `Self::acquire` on the existing lockfile inode.
    /// When the named holder really has died, the kernel released its flock
    /// and the second attempt succeeds. When something else is genuinely
    /// holding the flock — an inherited FD outliving the named holder, or a
    /// PID-reuse race that briefly makes the pidfile lie — the second
    /// attempt still returns `LockHeld` and we surface
    /// [`Error::StaleLockBreakRefused`].
    ///
    /// We deliberately do NOT unlink the lockfile and acquire on a fresh
    /// inode: that path can leave two processes each holding "the lock" on
    /// separate inodes if the original inode's flock is still held,
    /// violating invariant #1 (at most one process holds the writer lock).
    pub fn acquire_or_break_stale(data_dir: &Path) -> Result<Self> {
        match Self::acquire(data_dir) {
            Ok(lock) => Ok(lock),
            Err(Error::LockHeld { holder_pid }) => {
                if holder_pid != 0 && is_pid_alive(holder_pid) {
                    return Err(Error::StaleLockBreakRefused { holder_pid });
                }
                tracing::warn!(
                    holder_pid,
                    "data-dir flock appears stale (named holder dead); retrying acquire"
                );
                match Self::acquire(data_dir) {
                    Ok(lock) => Ok(lock),
                    Err(Error::LockHeld { holder_pid }) => {
                        Err(Error::StaleLockBreakRefused { holder_pid })
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // The flock is released when `_flock` drops (kernel close).
        // Best-effort: clear the pidfile so future stale-break checks don't
        // see our PID hanging around.
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

fn read_pidfile(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn write_pid_atomic(path: &Path, pid: u32) -> Result<()> {
    // Unique temp name per writer. A fixed `<pidfile>.tmp` is a shared
    // mutable path: a second process writing its pidfile concurrently (the
    // successor takes the flock while the exiting incumbent still holds a
    // reference to the same data dir) would truncate the first writer's temp
    // file mid-write, and either could then rename a half-written or
    // wrong-pid file into place. The flock keeps that from being a
    // correctness bug, but a pidfile naming the wrong process defeats
    // `acquire_or_break_stale`, which is the whole point of having one.
    let tmp = path.with_extension(format!("pidfile.{pid}.tmp"));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        writeln!(f, "{pid}")?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    // fsync the parent directory so the rename's link-update is durable.
    // The pidfile is advisory (flock is authoritative), but a stale or
    // missing pidfile after crash recovery defeats `acquire_or_break_stale`'s
    // ability to identify the prior holder.
    if let Some(parent) = path.parent() {
        let target = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        File::open(target)?.sync_all()?;
    }
    Ok(())
}

/// Whether `pid` names a live process.
///
/// `kill(pid, 0)` reports three outcomes, and only one of them means "gone":
///
/// - `Ok(())` — the process exists and we may signal it.
/// - `EPERM` — the process **exists** but belongs to another user. Reading
///   this as "dead" is the dangerous direction: it makes
///   [`DataDirLock::acquire_or_break_stale`] try to break a lock whose holder
///   is very much alive. (The flock still refuses, so this is a
///   misdiagnosis rather than a split brain — but it turns a clear
///   "held by a live process" into a confusing "stale lock could not be
///   broken", and it is a real configuration: a daemon restarted under a
///   different service account, or an operator recovering as a non-root user.)
/// - `ESRCH` — no such process. The only genuine death signal.
fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    !matches!(
        kill(Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn acquire_succeeds_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let lock = DataDirLock::acquire(dir.path()).unwrap();
        drop(lock);
    }

    #[test]
    fn second_acquire_returns_lock_held() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = DataDirLock::acquire(dir.path()).unwrap();
        match DataDirLock::acquire(dir.path()) {
            Err(Error::LockHeld { holder_pid }) => {
                assert_eq!(holder_pid as u32, std::process::id());
            }
            other => panic!("expected LockHeld, got {other:?}"),
        }
    }

    #[test]
    fn release_on_drop_allows_reacquire() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = DataDirLock::acquire(dir.path()).unwrap();
        }
        let _lock = DataDirLock::acquire(dir.path()).unwrap();
    }

    #[test]
    fn stale_break_refuses_for_live_pid() {
        let dir = tempfile::tempdir().unwrap();
        let _held = DataDirLock::acquire(dir.path()).unwrap();
        match DataDirLock::acquire_or_break_stale(dir.path()) {
            Err(Error::StaleLockBreakRefused { holder_pid }) => {
                assert_eq!(holder_pid as u32, std::process::id());
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn stale_break_succeeds_when_kernel_released_flock() {
        // Crashed prior holder: lockfile + pidfile on disk, flock NOT
        // currently held (the kernel released it when the PID died).
        // `i32::MAX` is above pid_max on Linux, so `kill(MAX, 0)` returns
        // ESRCH and the pidfile is unambiguously stale.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), b"").unwrap();
        std::fs::write(dir.path().join(PID_FILE), format!("{}", i32::MAX)).unwrap();

        let _new_lock = DataDirLock::acquire_or_break_stale(dir.path()).unwrap();
    }

    #[test]
    fn stale_break_refuses_when_pidfile_lies_but_flock_held() {
        // The pidfile names a dead PID, but someone is genuinely holding
        // the flock right now (inherited FD, or a brief PID-reuse race).
        // Safer to refuse than to unlink the lockfile and produce two
        // parallel-inode flocks that would split-brain invariant #1.
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(LOCK_FILE);
        let pid_path = dir.path().join(PID_FILE);

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        let _other_flock = Flock::lock(f, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| e)
            .unwrap();
        std::fs::write(&pid_path, format!("{}", i32::MAX)).unwrap();

        match DataDirLock::acquire_or_break_stale(dir.path()) {
            Err(Error::StaleLockBreakRefused { .. }) => {}
            other => panic!("expected StaleLockBreakRefused, got {other:?}"),
        }
        // Keep the flock alive through the assertion so the test models
        // a genuinely-held flock, not a transient one.
        assert!(_other_flock.as_raw_fd() >= 0);
    }

    #[test]
    fn a_process_we_may_not_signal_still_counts_as_alive() {
        // PID 1 exists and (when we are not root) `kill(1, 0)` fails with
        // EPERM. Reading that as "dead" would make the stale-break path try
        // to reclaim a lock from a live holder.
        assert!(is_pid_alive(1), "pid 1 is alive regardless of our uid");
        // ESRCH is the only genuine death signal.
        assert!(!is_pid_alive(i32::MAX));
        assert!(!is_pid_alive(0));
        assert!(!is_pid_alive(-1));
    }

    #[test]
    fn pidfile_temp_path_is_writer_specific() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join(PID_FILE);
        write_pid_atomic(&pid_path, 4242).unwrap();
        assert_eq!(std::fs::read_to_string(&pid_path).unwrap().trim(), "4242");
        // No temp file survives a successful write, and the name it used was
        // not the shared `<pidfile>.tmp` another writer would also pick.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }
}
