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
    let tmp = path.with_extension("pidfile.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        writeln!(f, "{pid}")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
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

fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    matches!(kill(Pid::from_raw(pid), None), Ok(()))
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
}
