//! Parent-side FD inheritance helper.
//!
//! Places a caller-supplied set of file descriptors at FDs `3..3 + n` in a
//! freshly-`fork`ed child via `pre_exec`, clearing CLOEXEC so they survive
//! `execve`. Used by both [`crate::supervisor::Supervisor::spawn_successor`]
//! and binary embedders that need to cold-start a primitive with inherited
//! listeners (systemd socket-activation convention).
//!
//! The naive approach — looping `dup2(src_i, 3 + i)` over the source list —
//! is order-dependent: if any later source FD happens to sit in the
//! destination range `[3, 3 + n)`, an earlier `dup2` clobbers it before it
//! can be used. [`arrange_inherited_fds_on_spawn`] avoids the shuffle
//! hazard by first staging every source above the destination range with
//! `fcntl(F_DUPFD)`, then settling each one at its target with `dup2`,
//! then closing the staging copies. All syscalls in the post-fork closure
//! are async-signal-safe.

use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Register a `pre_exec` on `cmd` that, after fork and before `execve`,
/// places each FD in `sources` at the canonical inherited-FD slot
/// (`SD_LISTEN_FDS_START + i`). Clears CLOEXEC on every target so the FD
/// survives `execve`. Closes the parent's staging duplicates so they don't
/// leak into the child.
///
/// The caller must keep the underlying open-file resources behind each
/// source FD alive in the parent until `Command::spawn` returns; otherwise
/// the FD numbers may be reassigned in the parent before fork.
pub fn arrange_inherited_fds_on_spawn(cmd: &mut Command, sources: Vec<RawFd>) {
    // The Vec is pre-allocated in the parent and reused as the staging
    // buffer post-fork — no allocator calls inside the closure.
    let mut working = sources;
    // SAFETY: the closure only invokes async-signal-safe libc calls
    // (`fcntl(F_DUPFD)`, `dup2`, `close`). No allocations, no Rust locks,
    // no panicking helpers — the exhaustive list of operations permitted
    // between `fork(2)` and `execve(2)` in a multi-threaded parent
    // (signal-safety(7)).
    unsafe {
        cmd.pre_exec(move || install_inherited_fds(&mut working));
    }
}

/// Post-fork installation routine. Mutates `working` in place: each slot
/// initially holds a parent-side source FD; by the end of stage 1 it holds
/// the staged duplicate; stage 2 settles those staged FDs at `3..3 + n`;
/// stage 3 closes the staged duplicates.
fn install_inherited_fds(working: &mut [RawFd]) -> std::io::Result<()> {
    let n = working.len();
    if n == 0 {
        return Ok(());
    }
    let staging_min: RawFd = 3 + (n as RawFd);

    // Stage 1: lift every source above the destination range. `F_DUPFD`
    // returns the lowest free FD at-or-above `staging_min`, so no staged
    // duplicate can collide with a target slot in `[3, 3 + n)`.
    for slot in working.iter_mut() {
        // SAFETY: `*slot` is a caller-supplied open FD; F_DUPFD allocates a
        // new FD pointing at the same description and never mutates other
        // state. Async-signal-safe.
        let new_fd = unsafe { libc::fcntl(*slot, libc::F_DUPFD, staging_min) };
        if new_fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        *slot = new_fd;
    }

    // Stage 2: settle each staged FD at its canonical target. `dup2` is
    // atomic and clears CLOEXEC on the destination, so the inherited FD
    // survives `execve`.
    for (i, staged_fd) in working.iter().enumerate() {
        let dst = 3 + i as RawFd;
        // SAFETY: `*staged_fd` is owned by us (just produced by F_DUPFD).
        // dup2 is async-signal-safe.
        if unsafe { libc::dup2(*staged_fd, dst) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Stage 3: close the staging duplicates so they don't leak into the
    // child. Each staged FD is in `[staging_min, ..)` and is now redundant
    // with the matching slot in `[3, 3 + n)`.
    for staged_fd in working.iter() {
        // SAFETY: `*staged_fd` is owned by us and is not referenced again
        // after this close. `close` is async-signal-safe.
        unsafe { libc::close(*staged_fd) };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sources_is_noop() {
        let mut empty: Vec<RawFd> = Vec::new();
        install_inherited_fds(&mut empty).unwrap();
    }

    /// Verify the shuffle is correct by running it in a forked child so we
    /// don't clobber the test runner's low FDs. The child opens three
    /// sockets, installs them, then probes FDs 3..6 for openness and
    /// CLOEXEC-cleared status. Exit code communicates the result.
    ///
    /// The child uses only async-signal-safe operations after fork so the
    /// test is safe in a multi-threaded `cargo test` runner.
    #[test]
    fn install_in_forked_child_settles_targets_and_clears_cloexec() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};
        use std::os::fd::IntoRawFd;

        let mk = || {
            let (a, b) = socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            (a.into_raw_fd(), b.into_raw_fd())
        };
        let (s0, _peer0) = mk();
        let (s1, _peer1) = mk();
        let (s2, _peer2) = mk();

        // SAFETY: the child path uses only libc syscalls (fcntl, dup2,
        // close, _exit) — no Rust allocations, no locks, no destructors.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let mut working = vec![s0, s1, s2];
                let code = if install_inherited_fds(&mut working).is_err() {
                    1
                } else {
                    let mut all_good = true;
                    for i in 0..3 {
                        let dst = 3 + i as RawFd;
                        // SAFETY: probing a candidate-open FD in test code.
                        let flags = unsafe { libc::fcntl(dst, libc::F_GETFD) };
                        if flags < 0 || (flags & libc::FD_CLOEXEC) != 0 {
                            all_good = false;
                            break;
                        }
                    }
                    if all_good { 0 } else { 2 }
                };
                // SAFETY: _exit is async-signal-safe; bypasses Rust drop.
                unsafe { libc::_exit(code) };
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).unwrap();
                assert!(
                    matches!(status, WaitStatus::Exited(_, 0)),
                    "child reported failure: {status:?}"
                );
            }
        }
    }
}
