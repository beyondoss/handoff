# handoff Architecture

Takes a running stateful daemon (incumbent), drains its in-flight connections, seals its on-disk state, and hands listener FDs + data-dir ownership to a freshly-spawned successor binary — with no TCP connections dropped and no acked writes lost.

## Roles

Three processes participate in any swap:

| Role | Symbol | What It Owns | Lifetime |
|------|--------|--------------|----------|
| Supervisor | S | Bound listener FDs, spawn policy | Entire service lifetime |
| Incumbent | O | Data-dir flock, active writer segments, accept loop | Until `Commit` received |
| Successor | N | Nothing until `Begin` | Spawned by S; takes ownership on `Begin` |

The supervisor is the only long-lived process. Primitives (O and N) come and go; the supervisor's FDs keep the kernel-side sockets open across swaps so the accept queue absorbs gaps.

## Data Flow

### Happy path

```
TRIGGER arrives at supervisor
        │
        ▼
S: try_lock(in_flight)? ──HELD──► Error::HandoffInProgress (caller)
        │
      ACQUIRED
        │
        ▼
S connects to O's Unix socket
O → S: Hello(incumbent, pid, build_id, proto range)
S → O: HelloAck(chosen_version, handoff_id)
        │
        ▼
S creates socketpair(S-end, N-end)
S forks+execs N with:
  HANDOFF_ROLE=successor
  HANDOFF_SOCK_FD=<n_end_fd>
  LISTEN_FDS=<count>       (listener FDs dup2'd to FD 3, 4, …)
  LISTEN_FDNAMES=<names>
        │
        ▼
N → S: Hello(successor, pid)
S → N: HelloAck(chosen_version, handoff_id)   ← S verifies pid matches spawned child
        │
        ▼
        │── DRAIN ──────────────────────────────────────────────────────┐
        │                                                                │
S → O: PrepareHandoff(handoff_id, successor_pid, deadline_ms,          │
                       drain_grace_ms)                                  │
O: stops calling accept(); cancels background tasks;                   │
   drains in-flight RESP/HTTP; fsyncs (no acked write lost)            │
O → S: Drained(open_conns_remaining, accept_closed)                    │
        │                                                                │
        │── SEAL ─────────────────────────────────────────────────────  │
        │                                                                │
S → O: SealRequest(handoff_id)                                         │
O: per shard — flush, write footer, fsync, close segment               │
O: drops DataDirLock (flock released ← critical ordering)             │
O → S: SealComplete(handoff_id, last_revision_per_shard,               │
                    data_dir_fingerprint)                               │
        │                                                                │
        │── BEGIN / READY ────────────────────────────────────────────  │
        │                                                                │
S → N: Begin(handoff_id)                                               │
N: take_listener("resp"|"http") from inherited FDs                     │
N: acquire DataDirLock (always succeeds — O released it)              │
N: open state from sealed snapshot; start accept loop                  │
N → S: Ready(handoff_id, listening_on, healthz_ok,                     │
             advertised_revision_per_shard)                            │
        │                                                                │
        │── COMMIT ───────────────────────────────────────────────────  │
        │                                                                │
S: disarms ChildGuard (N is authoritative from this point)             │
S → O: Commit(handoff_id)   ← best-effort; failure logged, not fatal  │
O: drains remaining read conns (bounded by grace timeout); exit(0)    │
S: returns HandoffOutcome{committed:true, child:N}                     │
        └────────────────────────────────────────────────────────────────┘
```

### Abort paths

```
Abort trigger (any phase)
        │
        ├─ N crashes before Ready ──► kernel releases N's flock FD
        │                             S sends ResumeAfterAbort → O
        │                             O re-acquires flock, calls resume_after_abort
        │
        ├─ N doesn't send Ready before deadline_ms
        │         S sends Abort → N (SIGTERM → SIGKILL)
        │         S sends ResumeAfterAbort → O
        │         O re-acquires flock, calls resume_after_abort
        │
        ├─ O sends SealFailed (flock still held by O)
        │         S sends Abort → N (kill + reap)
        │         O calls resume_after_abort immediately (re-opens writer)
        │         Returns HandoffOutcome{committed:false}
        │
        └─ S crashes during handoff
                  N exits when its socketpair end closes (EOF)
                  O observes EOF on control socket:
                    if sealed → re-acquire flock + call resume_after_abort
                    if only drained → call resume_after_abort (flock still held)
                  S on restart → resume_from_journal():
                    verifies O is reachable; clears journal file

ChildGuard (Rust RAII) ──► kills + reaps N on any early return from
                            perform_handoff; disarmed on Ready recv,
                            before the Commit write to O
```

## Concepts & Terminology

| Term | What It Controls | NOT |
|------|-----------------|-----|
| `Supervisor` | Spawns successors, drives the protocol, serializes handoffs via `Mutex` | Not a process supervisor like systemd; it's embedded in code |
| `Incumbent` | The Unix socket server inside the primitive process; runs `serve()` on a dedicated thread | Not the process itself — it's a library object the daemon spawns a thread for |
| `Drainable` | Consumer contract: the three lifecycle hooks S calls on O during a swap | Not a generic drain abstraction; specific to handoff ordering |
| `DataDirLock` | RAII `flock(LOCK_EX)` on `<data_dir>/.handoff.lock` + atomic pidfile | Not a mutex; cross-process kernel lock; held by exactly one primitive |
| `HandoffId` | UUID assigned by S in `HelloAck`; tags every message in one swap | Not a transaction id; not persisted to the data dir |
| `Phase` | Journal state machine value; written atomically after each protocol step | Not an in-memory state variable; only used for crash recovery |
| `ChildGuard` | Kills + reaps the spawned child on any early return from `perform_handoff`; disarmed on `Ready` recv so N survives even if the Commit write to O fails | Not visible outside `supervisor.rs`; pure RAII safety net |
| `InheritedListeners` | FD map populated from `LISTEN_FDS`/`LISTEN_FDNAMES`; consumed by `take()` | Not a listener pool; once taken, the entry is gone |
| Seal | Per-shard: flush buffer, write segment footer, fsync, close file | Not a DB-style "seal" on rows; it's the WAL segment close operation |
| Drain | Stop accepting, finish in-flight requests, fsync — before seal | Not a graceful shutdown; O keeps serving reads after drain |

## Core Mechanisms

### Listener inheritance

The supervisor binds sockets once at cold start and passes them to every child via `pre_exec` FD dup2 (FDs 3, 4, … in `LISTEN_FDS` order). The control socket goes to `FD 3 + len(listeners)`. Each spawned child receives a clean FD table with exactly these FDs preserved; all other FDs are CLOEXEC and close on exec. See `supervisor.rs:spawn_successor()`.

The kernel-level socket (and its accept queue) is never closed. Connections arriving during the O→N transition queue in the kernel and N's first `accept()` picks them up. The listen socket never goes "down" from a client's perspective.

### Flock ordering (the load-bearing piece)

O releases the flock in `SealRequest` handling (`incumbent.rs:run_session_loop`), immediately after `drainable.seal()` succeeds — before sending `SealComplete`, before receiving `Commit`, before exiting. This is the critical ordering:

1. O's seal writes and fsyncs all data. No further writes possible.
2. O drops `DataDirLock` (RAII: closes the flock FD).
3. S sends `Begin` to N.
4. N calls `DataDirLock::acquire()` — always succeeds because O released it.
5. N opens sealed state, starts accepting.

If the flock were held until `Commit`, step 4 would block (or fail) until O exited, forcing N to wait. Releasing it right after seal is safe because O has nothing left to write.

### Wire framing

Every message is a length-prefixed frame over a `UnixStream`:

```
[0..4]  u32 frame_len  (little-endian; covers bytes 4..4+frame_len)
[4..6]  u16 proto_version
[6..]   postcard-encoded Message variant
```

Frame size is capped at 1 MiB (`MAX_FRAME_BYTES`) to bound allocation on the reader side. The `Message` enum's variant discriminant is encoded by postcard as part of the payload — no separate type byte. See `frame.rs`.

### Protocol negotiation

Both sides announce `proto_min`/`proto_max` in `Hello`. `negotiate_version()` picks the highest version in the intersection. If ranges are disjoint, returns `Error::VersionMismatch` and the connection is closed before any handoff begins. Currently only version 1 exists (`PROTO_MIN == PROTO_MAX == 1`).

### Journal (crash recovery)

After each acknowledged protocol step, S writes a `StateJournal` to disk atomically (write `.bin.tmp` → rename). On restart, `resume_from_journal()` reads the file, verifies O is reachable (opens control socket, reads one frame, drops), then deletes the journal. The incumbent auto-recovers from disconnect in all phases; the journal gives S enough context to log what happened and start clean.

Journal writes use `postcard` serialization; the rename makes each write crash-safe on POSIX filesystems.

### Stale lock breaking

`DataDirLock::acquire_or_break_stale()` handles the case where the lockfile holds a PID that is no longer alive:

1. Try `acquire()`. If it succeeds, done.
2. If `LockHeld`, read the pidfile and call `kill(pid, 0)`.
3. If the PID is alive: return `StaleLockBreakRefused`. Never break a live holder.
4. If the PID is dead: retry `acquire()` on the same lockfile inode. The kernel released the flock when the holder process died, so the second attempt succeeds. If something is still genuinely holding the flock (an inherited FD outliving the named holder, or a brief PID-reuse race), the retry returns `LockHeld` again and we surface `StaleLockBreakRefused`.

We deliberately do **not** unlink the lockfile and acquire on a fresh inode: that path can split-brain invariant #1 by leaving two processes each holding "the lock" on separate inodes if the original inode's flock is still held. The pidfile is advisory; the kernel-level flock on the existing inode is the source of truth.

See `lock.rs:acquire_or_break_stale()`.

## State Machine

### Journal phase machine (supervisor-side)

```
Idle ──start──► Negotiating ──drain ack──► Draining ──seal ack──► Sealing
                                                                       │
                                                                  seal OK
                                                                       │
                                                                       ▼
                                                    ResumingAfterAbort ◄── AwaitingReady
                                                           ▲                     │
                                                           │                 Ready recv
                                                           │                     │
                                                     Aborting ◄── N timeout      ▼
                                                                            Committed
```

| From | Event | To | What S Actually Does |
|------|-------|----|---------------------|
| `Idle` | `perform_handoff` called | `Negotiating` | Connects to O, spawns N, Hello/HelloAck with both |
| `Negotiating` | `Drained` recv | `Draining` | Sends `SealRequest` |
| `Draining` | `SealComplete` recv | `Sealing` | Sends `Begin` to N |
| `Sealing` | `SealFailed` recv | `Idle` | Kills N; returns `HandoffOutcome{committed:false}` |
| `Sealing` | timeout | `Aborting` | Kills N; journal cleared |
| `Sealing` | `Begin` sent | `AwaitingReady` | Waits for N's `Ready` |
| `AwaitingReady` | `Ready` recv | `Committed` | Disarms `ChildGuard`; sends `Commit` (best-effort) to O; N is now authoritative regardless of Commit outcome |
| `AwaitingReady` | timeout / N error | `ResumingAfterAbort` | Kills N; sends `ResumeAfterAbort` to O |
| `Committed` | journal cleared | `Idle` | Returns `HandoffOutcome{committed:true, child:N}` |
| `ResumingAfterAbort` | journal cleared | `Idle` | Returns `HandoffOutcome{committed:false}` |

### Incumbent session state machine (O-side, per supervisor connection)

```
Idle ──HelloAck──► Active
                      │
              PrepareHandoff
                      │
                   Drained ──SealRequest──► Sealed ──Commit──► Committed (serve() returns Ok(()))
                      │                        │
                 Abort/EOF              Abort / ResumeAfterAbort / EOF
                      │                        │
               resume_after_abort       re-acquire flock + resume_after_abort
                      │                        │
                      └──────────► Idle (keep accepting)
```

| From | Message | To | What O Actually Does |
|------|---------|-----|---------------------|
| `Active` | `PrepareHandoff` | `Drained` | Calls `drainable.drain(deadline)`; sends `Drained` |
| `Drained` | `SealRequest` | `Sealed` | Calls `drainable.seal()`; drops `DataDirLock`; sends `SealComplete` |
| `Drained` | `SealRequest` (seal fails) | `Active` | Calls `resume_after_abort()`; sends `SealFailed`; resets `active=None` |
| `Sealed` | `Commit` | — | Returns `SessionOutcome::Committed`; `serve()` returns `Ok(())` |
| `Sealed` | `ResumeAfterAbort` | `Active` | Calls `resume_after_abort()`; re-acquires `DataDirLock` |
| `Sealed` | EOF (S crash) | `Active` | Re-acquires `DataDirLock`; calls `resume_after_abort()` |
| `Drained` | EOF (S crash) | `Active` | Calls `resume_after_abort()` (flock never released) |
| Any | `Abort` | `Active` | Conditionally calls `resume_after_abort()` + re-acquire flock if sealed |

## Why It Behaves This Way

### Why O releases the flock before commit (not at exit)

After `seal()`, O has no remaining writes. Its data is on disk. Holding the flock until `Commit` would prevent N from acquiring it and opening state, extending the window during which N can't accept new connections. Releasing immediately after seal is safe: O serves only in-flight reads from sealed (read-only) files for the remainder of its life.

### Why listener FDs flow via env vars, not over the control socket

Passing FDs over Unix sockets (`SCM_RIGHTS`) requires an established connection and correct `sendmsg`/`recvmsg` sequencing. The supervisor-to-child relationship is via `fork+exec` — using `pre_exec` + `dup2` into the target FD slots is simpler, more reliable (no timing dependency on the socket being writable), and matches the systemd socket activation convention that existing tooling (systemd, test harnesses) already understands.

### Why the library has no async runtime dependency

The control socket carries one peer at a time, at low throughput, during rare swap events. Synchronous `std::os::unix::net::UnixStream` I/O on a dedicated OS thread is sufficient. Pulling in tokio would force all consumers of the library to match its runtime version. Consumers bridge to their own runtime via channels (`std::sync::mpsc`) where `Drainable` methods need async behavior.

### Why `ChildGuard` instead of manual cleanup

`perform_handoff` has many early-return paths (network errors, timeouts, unexpected messages). Without a guard, each early return would need to kill + reap the spawned child. `ChildGuard` drops automatically on every path except the explicit `disarm()`. See `supervisor.rs:ChildGuard`.

### Why `ChildGuard` is disarmed before the `Commit` write

After `Ready` is received, N has acquired the data-dir flock and (via `announce_and_bind`) bound the control socket — N is the authoritative new incumbent from that point regardless of what happens to O. The `Commit` write to O is therefore best-effort cleanup.

If `ChildGuard` were still armed when the `Commit` write failed (e.g. O crashed right after sending `SealComplete`), the `?` propagation would drop the guard and kill N, leaving the system with neither incumbent. Disarming before the write means a dead O cannot take N down with it. The same logic applies to the journal-update that follows: journal failures are logged but not propagated, because the handoff is already committed.

### Why the state journal uses rename, not O_DSYNC write

`write tmp + rename` produces an atomic view: the on-disk file is always either the old complete state or the new complete state, never a partial write. `O_DSYNC` only ensures the write itself is durable — it doesn't prevent a torn record if the supervisor crashes mid-write. `rename(2)` is atomic with respect to crash consistency on every supported filesystem — Linux ext4/XFS/btrfs, macOS APFS, and BSD UFS/ZFS — so the guarantee is not Linux-specific.

### Liveness: heartbeats during drain/seal + two-tier supervisor timeout

The supervisor enforces two independent timeouts on every read from a peer:

- **Liveness (per-recv, `LIVENESS_TIMEOUT = 10s`).** Each `recv` waits at most this long. Any received frame — including a `Heartbeat` — resets the clock. A peer emitting heartbeats every 2s during a long-running hook is therefore *not* declared dead, no matter how long that hook takes.
- **Wall-clock (per-phase budget) + `WIRE_SLACK`.** Regardless of heartbeats, the supervisor aborts once the configured budget elapses: `drain_grace` for the drain phase, `deadline` (overall) for everything else. Each cap is extended by `WIRE_SLACK` (1 s) on the supervisor's read side. The peer's clock for a phase starts when it deserializes the request (`T_s + δ_net`), and a reply produced after running to that budget still has to traverse `δ_net + δ_serialize` on the way back; without the slack, the supervisor would abort a frame already on the wire. The slack is conservative — Unix-socket round-trip + frame serialization is well under 1 s — and is not a tuning knob.

The incumbent feeds this design by spawning a background heartbeat thread for the duration of `Drainable::drain` and `Drainable::seal`. The thread writes a `Heartbeat` frame every `HEARTBEAT_INTERVAL` (2s). When the hook returns, an RAII guard signals the thread to stop and joins it before the main thread sends the next protocol frame — so there is never concurrent writing on the control socket. The 5× safety margin (2s heartbeat vs 10s liveness) absorbs scheduler hiccups.

The seal-wait loop additionally skips `SealProgress` frames so a consumer with a multi-shard seal can emit explicit progress (`shards_sealed`, `shards_total`, `last_revision`) on top of the implicit heartbeat liveness signal. The payload is consumed silently today; a future version may surface it in metrics.

The default budgets (`deadline = 300s`, `drain_grace = 60s`) are generous. Tuning guidance: set `deadline` to `p99(drain) + p99(seal) + 30s` for your workload. The library does not interrupt long-but-progressing hooks; it does abort once the wall-clock cap is exceeded.

### Flock re-acquire on session error (2 s retry)

When O's `serve()` loop catches a session error and the data-dir flock is not held (i.e. seal completed before the error), it retries `DataDirLock::acquire()` with a 25 ms poll interval for up to 2 s before propagating failure. This covers the race where N acquired the flock after `SealComplete`, then failed before announcing `Ready` — N is still alive just long enough for its flock FD to be in-flight. A fresh acquire after N exits is guaranteed to succeed. If the flock remains held after 2 s, the holder is a legitimate new incumbent and O returns an error, causing the process to exit. See `incumbent.rs:acquire_with_short_retry`.

## Trust Boundaries

**What the library verifies:**

- Successor's announced `pid` in `Hello` matches the PID returned by `Command::spawn()` — prevents a rogue process from connecting and posing as N.
- Protocol version is within the negotiated range — rejects version mismatches before any handoff begins.
- `handoff_id` in every message matches the active handoff — rejects replayed or cross-session messages.
- Frame length is ≤ 1 MiB — prevents unbounded allocation from a malformed peer.
- `Commit` is not accepted before `SealComplete` — protocol ordering is enforced.

**What passes through unchecked:**

- `build_id` in `Hello` — logged but not validated; no signature or hash check.
- `healthz_ok` in `Ready` — S records it but does not abort if false; policy is left to the consumer.
- `advertised_revision_per_shard` in `Ready` — S records it but does not compare against O's `SealComplete` revisions; cross-shard consistency is the consumer's responsibility.
- The content of the data dir after seal — S does not verify the `data_dir_fingerprint` from `SealComplete`; N opens whatever state it finds.

**Why these boundaries are where they are:**

The library is embedded in a trusted, same-host supervisor process. All three roles (S, O, N) are spawned by the same operator; no external network is involved. Authentication between them is not needed — the Unix socket path is the security boundary. If an untrusted process can connect to the control socket, the host is already compromised.

## Package Structure

| File | What It Does |
|------|-------------|
| `crates/handoff/src/lib.rs` | Re-exports public surface; no logic |
| `crates/handoff/src/protocol.rs` | Wire message enum + framing constants; `negotiate_version()` |
| `crates/handoff/src/frame.rs` | `read_message` / `write_message`; 1 MiB frame cap |
| `crates/handoff/src/supervisor.rs` | `Supervisor::perform_handoff()`; `ChildGuard`; journal writes; `spawn_successor()` pre_exec dance |
| `crates/handoff/src/incumbent.rs` | `Incumbent::serve()`; per-session state machine; flock release on seal |
| `crates/handoff/src/drainable.rs` | `Drainable` trait + report types (`DrainReport`, `SealReport`, `StateSnapshot`) |
| `crates/handoff/src/role.rs` | `detect_role()`; successor typestate chain (`Successor → HandshookSuccessor → BegunSuccessor`); `InheritedListeners` |
| `crates/handoff/src/lock.rs` | `DataDirLock` RAII flock; `acquire_or_break_stale()` |
| `crates/handoff/src/state.rs` | `StateJournal` + `Phase`; atomic write-rename persistence |
| `crates/handoff/src/error.rs` | `Error` enum; `mpsc` channel conversions |
| `crates/handoff/src/metrics.rs` | `tracing` event name constants and metric name constants |
| `crates/handoff-supervisor/src/main.rs` | Reference supervisor binary: TOML config, cold-start spawn, Unix trigger socket (`handoff [binary]` command) |

## Configuration

### `handoff-supervisor` TOML config

| Field | Default | What It Controls at Runtime |
|-------|---------|----------------------------|
| `control_socket` | (required) | Path where the incumbent's `Incumbent::bind()` listens; S connects here at handoff start |
| `binary` | (required) | Default executable for primitive spawns; overridable per trigger command |
| `args` | `[]` | Argv passed to every primitive spawn |
| `env` | `[]` | Extra env vars merged into every spawn's environment |
| `listeners` | `[]` | Sockets S binds at startup; inherited by every primitive via LISTEN_FDS |
| `trigger_socket` | (required) | Unix socket S listens on for `handoff [binary]` trigger commands |
| `journal` | `None` | If set, S writes phase journal here for crash recovery |
| `drain_grace_secs` | `25` | Budget S gives O for the drain phase before sending `Drained`; S's read for the reply extends `WIRE_SLACK` (1 s) past this cap |
| `deadline_secs` | `60` | Overall handoff deadline (post-drain through Ready); S's reads for `SealComplete` and `Ready` extend `WIRE_SLACK` (1 s) past this cap |

### `SpawnSpec` (library API)

| Field | Default | What It Controls at Runtime |
|-------|---------|----------------------------|
| `deadline` | `60s` | Overall timeout from PrepareHandoff to Ready; exceeded → N killed, O resumes |
| `drain_grace` | `25s` | Timeout for `Drainable::drain()` to return; `+1s` wire buffer before timeout fires |

## Failure Modes

| Failure | What Actually Happens | Recovery |
|---------|----------------------|----------|
| N crashes before `Ready` | Socketpair EOF; `ChildGuard` kills + reaps N; S sends `ResumeAfterAbort` to O | O re-acquires flock, calls `resume_after_abort()`, keeps serving |
| N doesn't send `Ready` before `deadline_ms` | `read_until` times out; S sends `Abort` to N, kills it; sends `ResumeAfterAbort` to O | Same as above |
| O's `seal()` returns error | O sends `SealFailed`; O immediately calls `resume_after_abort()` (flock never released); S kills N | O stays incumbent; `HandoffOutcome{committed:false}` returned; retry is safe |
| O crashes after `SealComplete` (Commit write fails) | `ChildGuard` already disarmed at `Ready` recv; Commit write error is logged, not propagated; N holds flock, is the new incumbent | `HandoffOutcome{committed:true, child:N}` returned; O is dead |
| S crashes during handoff (any phase) | N exits on socketpair EOF; O observes EOF and self-recovers based on phase | If sealed: O re-acquires flock + resumes (2 s retry loop). If drained: O resumes. Journal cleared on S restart |
| Concurrent `perform_handoff` calls | Second caller gets `Error::HandoffInProgress` immediately from `try_lock` | Caller serializes retries; no protocol message sent to O or N |
| Second `PrepareHandoff` with different `handoff_id` | O returns `Error::HandoffInProgress`; session closes | S observes disconnect; must start fresh session |
| Frame > 1 MiB received | `Error::FrameTooLarge`; connection closed | Peer has a bug; reconnect |
| Protocol version mismatch | `Error::VersionMismatch`; connection closed before any handoff begins | Upgrade either S or the primitive |
| Stale pidfile, holder dead | `acquire_or_break_stale()` detects dead PID via `kill(pid, 0)`; unlinks files; acquires on fresh inode | Automatic; no manual intervention |
| Stale pidfile, holder alive | `Error::StaleLockBreakRefused` — refuses to evict a live process | Manual investigation required; indicates two supervisors for one data dir |

## Observability

The library emits `tracing` events at each phase transition. The `metrics.rs` module exports **string constants** for the recommended counter/histogram names — the library does **not** itself register or update any metric. Consumers wire the constants into their own metrics backend (Prometheus, OpenTelemetry, …) so dashboards stay consistent across daemons that embed `handoff`. Treat the table below as a naming contract, not a list of values the library publishes.

| Metric Name | Type | What It Measures |
|-------------|------|-----------------|
| `handoff_handoffs_total` | counter | Total handoffs attempted |
| `handoff_failures_total` | counter | Handoffs that returned an error |
| `handoff_rolled_back_total` | counter | Handoffs aborted with resume (O kept serving) |
| `handoff_seal_failures_total` | counter | `SealFailed` messages received |
| `handoff_duration_seconds` | histogram | Wall time from PrepareHandoff to Commit |
| `handoff_drain_seconds` | histogram | Wall time for `Drainable::drain()` |
| `handoff_seal_seconds` | histogram | Wall time for `Drainable::seal()` |
| `handoff_begin_to_ready_seconds` | histogram | Wall time from `Begin` sent to `Ready` received |

| Tracing Event | Phase |
|---------------|-------|
| `handoff.prepare` | `PrepareHandoff` sent to O |
| `handoff.drained` | `Drained` received from O |
| `handoff.seal` | `SealRequest` sent to O |
| `handoff.seal_complete` | `SealComplete` received, flock released |
| `handoff.ready` | `Ready` received from N |
| `handoff.commit` | `Commit` sent to O |
| `handoff.abort` | `Abort` sent (either peer) |
| `handoff.resume` | `ResumeAfterAbort` processed; O back to serving |

## Public API

```rust
// Consumer implements this in their daemon.
pub trait Drainable: Send + Sync {
    fn drain(&self, deadline: Instant) -> Result<DrainReport>;
    fn seal(&self) -> Result<SealReport>;
    fn resume_after_abort(&self) -> Result<()>;
    fn snapshot_state(&self) -> StateSnapshot;
}

// In the primitive's startup sequence:
pub fn detect_role() -> Result<Role>;     // Role::ColdStart | Role::Successor

// Successor-side protocol: three typestate types enforce call ordering at
// compile time. Out-of-order calls (e.g. take_listener before wait_for_begin)
// don't compile — there's no path from Successor to BegunSuccessor without
// passing through every preceding state.
pub struct Successor;
impl Successor {
    pub fn handshake(self, build_id: Vec<u8>) -> Result<HandshookSuccessor>;
    pub fn listener_names(&self) -> Vec<String>;
}

pub struct HandshookSuccessor;
impl HandshookSuccessor {
    pub fn wait_for_begin(self) -> Result<BegunSuccessor>;
    pub fn handoff_id(&self) -> HandoffId;
    pub fn listener_names(&self) -> Vec<String>;
}

pub struct BegunSuccessor;
impl BegunSuccessor {
    pub fn take_listener(&mut self, name: &str) -> Option<TcpListener>;
    pub fn handoff_id(&self) -> HandoffId;
    pub fn listener_names(&self) -> Vec<String>;
    /// Send `Ready`. Caller must NOT bind the control socket until the
    /// prior incumbent has exited (i.e. its `serve()` returned). Prefer
    /// `announce_and_bind` unless you have a specific reason to delay bind.
    pub fn announce_ready(self, snapshot: ReadinessSnapshot) -> Result<()>;
    /// Send `Ready` and bind the control socket as the new incumbent in
    /// one call — the only safe ordering for the successor-side rebind.
    pub fn announce_and_bind(
        self,
        snapshot: ReadinessSnapshot,
        socket_path: &Path,
        lock: DataDirLock,
    ) -> Result<Incumbent>;
}

pub struct Incumbent;
impl Incumbent {
    /// Cold-start bind. Unlinks any stale socket file before binding;
    /// safe only when no prior incumbent is alive on this path. From a
    /// successor, use `Successor::announce_and_bind` instead.
    pub fn bind_cold_start(socket_path: &Path, lock: DataDirLock) -> Result<Self>;
    pub fn with_build_id(self, build_id: Vec<u8>) -> Self;
    pub fn serve<D: Drainable + 'static>(self, drainable: D) -> Result<()>;
    // serve() returns Ok(()) after Commit; call process::exit(0) after it returns.
}

pub struct DataDirLock;
impl DataDirLock {
    pub fn acquire(data_dir: &Path) -> Result<Self>;
    pub fn acquire_or_break_stale(data_dir: &Path) -> Result<Self>;
}

// In the supervisor process:
pub mod supervisor {
    pub struct Supervisor;
    impl Supervisor {
        pub fn new(socket_path: &Path) -> Result<Self>;
        pub fn with_listener(self, name: impl Into<String>, fd: RawFd) -> Self;
        pub fn with_journal(self, path: PathBuf) -> Self;
        pub fn with_build_id(self, build_id: Vec<u8>) -> Self;
        pub fn perform_handoff(&self, spec: SpawnSpec) -> Result<HandoffOutcome>;
        // Returns Error::HandoffInProgress immediately if another thread is inside.
        pub fn resume_from_journal(&self) -> Result<Option<StateJournal>>;
        // Call once at startup before the first perform_handoff.
    }
}
```

### Crash-injection points (test-only)

The `crash-points` cargo feature on the `handoff` crate makes named protocol
boundaries injectable via the `HANDOFF_CRASH_AT` env var, terminating the
process with `_exit(99)` on match. Production builds (the feature off) elide
the calls entirely. See `crates/handoff-tests/` for the integration harness
that uses these points to verify recovery from every documented crash
scenario.

## Correctness Invariants

1. At most one process holds the flock at any time.
2. Flock is released only after seal succeeds, or after a seal-failure that leaves no committed-but-orphaned state.
3. No acked write is lost across a handoff — `Drainable::drain` must fsync before returning.
4. The listener socket never closes from the kernel's perspective; the accept queue absorbs the gap between O's last accept and N's first accept.
5. N refuses to write until it holds the flock.
6. An aborted handoff returns the system to the pre-handoff observable state with no resource leaks.
7. The protocol is resumable from any acknowledged state on supervisor restart (state journal at configurable path; default `/var/lib/beyond/handoff/<svc>/state.bin`).
