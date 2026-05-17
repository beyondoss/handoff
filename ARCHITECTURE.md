# handoff architecture

A daemon-side library + a reference supervisor binary that together perform a zero-downtime in-place binary swap of a running stateful process.

## Roles

- **S** — supervisor. Binds the listen sockets at first cold start and holds the FDs for the lifetime of its own process. Spawns each successive primitive process, inheriting the listeners via `LISTEN_FDS` env vars. Drives the swap protocol.
- **O** — old incumbent. The primitive process currently serving traffic and holding the data-dir flock.
- **N** — new successor. Spawned by S during a swap. Starts up, waits for `Begin`, takes the flock, opens state, declares ready.

## Wire protocol

Length-prefixed frames over a Unix-domain socket:

```
u32 length || u16 proto_version || u16 msg_type || postcard payload
```

Listener FDs are never sent over this socket — they flow via env-var inheritance at process spawn (same convention as systemd socket activation).

| #   | Name               | Direction   | Payload                                                                       |
| --- | ------------------ | ----------- | ----------------------------------------------------------------------------- |
| 1   | `Hello`            | O↔S, N↔S    | role, pid, build_id, proto_min, proto_max, capabilities                       |
| 2   | `HelloAck`         | S→peer      | proto_version_chosen, handoff_id (uuid)                                       |
| 3   | `PrepareHandoff`   | S→O         | handoff_id, successor_pid, deadline_ms, drain_grace_ms                        |
| 4   | `Drained`          | O→S         | open_conns_remaining, accept_closed                                           |
| 5   | `SealRequest`      | S→O         | handoff_id                                                                    |
| 6   | `SealProgress`     | O→S         | shards_sealed, shards_total, last_revision (heartbeat while sealing)          |
| 7   | `SealComplete`     | O→S         | handoff_id, last_revision_per_shard, data_dir_fingerprint                     |
| 8   | `SealFailed`       | O→S         | handoff_id, error, partial_state                                              |
| 9   | `Begin`            | S→N         | handoff_id (cue for N to acquire flock, open state, start serving)            |
| 10  | `Ready`            | N→S         | handoff_id, listening_on, healthz_ok, advertised_revision_per_shard           |
| 11  | `Commit`           | S→O         | handoff_id                                                                    |
| 12  | `Abort`            | S→{O,N}     | handoff_id, reason                                                            |
| 13  | `ResumeAfterAbort` | S→O         | handoff_id                                                                    |
| 14  | `Heartbeat`        | both        | ts (every 1s during handoff)                                                  |

## Happy-path sequence

```
[steady state: O has flock, S has listener FDs]

S spawns N with env HANDOFF_SOCK_FD=<n>, HANDOFF_ROLE=successor,
                    LISTEN_FDS=2, LISTEN_FDNAMES=resp:http  (FDs 3, 4)
N→S: Hello(successor)   ; S→N: HelloAck
O→S: Hello(incumbent)   ; S→O: HelloAck   (already established at O's startup)

S→O: PrepareHandoff
  O: stop calling accept(); cancel background tasks; drain in-flight RESP/HTTP;
     reject new writes on remaining conns; continue serving reads
O→S: Drained(open_conns_remaining)

S→O: SealRequest
  O: per shard — flush, write footer, fsync, close active file
  O: release data-dir flock                             ← critical ordering
O→S: SealProgress* (heartbeats while sealing)
O→S: SealComplete(last_revision_per_shard)

S→N: Begin
  N: take_listener("resp" | "http") via from_raw_fd
  N: acquire data-dir flock                             ← always succeeds
  N: open state from sealed snapshot, start accept loop
N→S: Ready(advertised_revision_per_shard)

S→O: Commit
  O: drain remaining read conns (bounded by grace timeout)
  O: exit(0)
```

The transition order is the load-bearing piece: **O releases the flock immediately after sealing, not at exit.** O has no remaining writes post-seal; it serves in-flight reads from sealed files until `Commit`.

## Abort paths

- **N crashes after `Begin`, before `Ready`:** N held the flock briefly; kernel releases on N exit. S sends `ResumeAfterAbort` to O. O re-acquires the flock, opens fresh active segments, restarts accept loop.
- **N's `Ready` doesn't arrive by `deadline_ms`:** S sends `Abort` to N (SIGTERM then SIGKILL), then `ResumeAfterAbort` to O.
- **O's `seal()` errors mid-handoff:** O sends `SealFailed{partial_state}`. O has not released flock. S aborts N. O resumes accepting from its partial state.
- **S crashes during handoff:** Both O and N watch a 5s heartbeat. On disconnect, the flock-holder keeps serving; the other exits with code 75 (EX_TEMPFAIL). S on restart reconstructs state from `/var/lib/beyond/handoff/<svc>/state.json`.
- **Concurrent handoff attempts:** S guards with an in-process mutex plus `/run/beyond/<primitive>/handoff.lock`. O rejects a second `PrepareHandoff` with a different `handoff_id`.
- **Data-dir flock held by zombie:** `acquire_or_break_stale` checks the pidfile, verifies liveness via `pidfd_open`, breaks the lock only if the holder PID is dead.

## Correctness invariants

1. At most one process holds the flock at any time.
2. Flock is released only after seal succeeds, or after a seal-failure that leaves no committed-but-orphaned state.
3. No acked write is lost across a handoff. The `Drainable::drain` impl must fsync before announcing `Drained`.
4. Listener never goes "down" from the kernel's perspective; the accept queue absorbs the gap between O's last accept and N's first accept.
5. Successor refuses to start writing until the flock is held.
6. Aborted handoff returns the system to the pre-handoff state with no leaks.
7. The protocol is resumable from any acknowledged state on supervisor restart (state journal at `/var/lib/beyond/handoff/<svc>/state.json`).

## Public API

```rust
pub trait Drainable: Send + Sync {
    fn drain(&self, deadline: Instant) -> Result<DrainReport>;
    fn seal(&self) -> Result<SealReport>;
    fn resume_after_abort(&self) -> Result<()>;
    fn snapshot_state(&self) -> StateSnapshot;
}

pub fn detect_role() -> Role;          // ColdStart | Successor { ... }

pub struct Successor { /* ... */ }
impl Successor {
    pub fn take_listener(&mut self, name: &str) -> Option<std::net::TcpListener>;
    pub fn announce_ready(self, snapshot: ReadinessSnapshot) -> Result<()>;
}

pub struct Incumbent { /* ... */ }
impl Incumbent {
    pub fn bind(socket_path: &Path, lock: DataDirLock) -> Result<Self>;
    pub fn serve<D: Drainable + 'static>(self, drainable: D) -> Result<()>;
}

pub struct DataDirLock { /* RAII flock guard */ }
impl DataDirLock {
    pub fn acquire(data_dir: &Path) -> Result<Self>;
    pub fn acquire_or_break_stale(data_dir: &Path) -> Result<Self>;
}

pub mod supervisor {
    pub struct Supervisor { /* ... */ }
    impl Supervisor {
        pub fn new(socket_path: &Path) -> Result<Self>;
        pub fn perform_handoff(&self, spec: SpawnSpec) -> Result<HandoffOutcome>;
    }
}
```

## Async runtime

The library has **no async runtime dependency**. The control socket carries one peer with low-throughput frames during rare swap events — sync `std::os::unix::net::UnixStream` I/O on a dedicated OS thread is sufficient.

The `Drainable` trait is sync; each consumer bridges to its own async runtime via a typed channel + oneshot reply. The `handoff-supervisor` reference binary uses tokio internally — that's a per-binary choice, not a library-wide one.

## Env-var contract

A successor process is spawned by its supervisor with:

| Variable          | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| `HANDOFF_ROLE`    | `successor` (presence signals successor mode)            |
| `HANDOFF_SOCK_FD` | FD number of the open control socket                     |
| `LISTEN_FDS`      | Number of inherited listener FDs (always start at FD 3)  |
| `LISTEN_FDNAMES`  | Colon-separated logical names matching the FDs in order  |

`detect_role()` reads these. `Successor::take_listener(name)` returns the `TcpListener` for a named FD, then clears the env var so accidental double-take panics.

A cold-start process (no `HANDOFF_ROLE` set) binds its own listeners as today.
