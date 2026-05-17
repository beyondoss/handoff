# handoff

Replace the binary of a running stateful daemon: no dropped connections, no lost writes, no visible socket close.

## What you get

- **No dropped connections.** The supervisor holds listener FDs across swaps. The kernel's accept queue absorbs the gap between old and new processes.
- **No lost writes.** The old process drains in-flight requests and fsyncs before the new one touches the data directory. The protocol enforces this ordering.
- **No split-brain.** Exactly one process holds the data-directory flock at any time. The new binary cannot write until the old one releases it.
- **Automatic rollback.** If the new binary fails before declaring ready, the old process reacquires the flock, reopens its writer state, and resumes serving. No manual intervention.

## How it works

Three roles: a **supervisor** that holds listener FDs and drives the swap, an **incumbent** (old binary) that drains and seals its state, and a **successor** (new binary) that takes over when the incumbent confirms it's clean. The protocol is acknowledged at every phase; a crash at any point leaves the system in a recoverable state.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the wire protocol, state machine, and correctness invariants.

## Integrate your daemon

### 1. Implement `Drainable`

```rust
use handoff::{Drainable, DrainReport, SealReport, StateSnapshot, error::Result};
use std::time::Instant;

struct MyDrainable {
    db: Arc<MyDatabase>,
}

impl Drainable for MyDrainable {
    fn drain(&self, deadline: Instant) -> Result<DrainReport> {
        // Stop accepting new connections and writes.
        // Finish in-flight requests. Fsync before returning.
        self.db.stop_writes();
        self.db.drain_inflight(deadline)?;
        self.db.fsync()?;
        Ok(DrainReport { open_conns_remaining: 0, accept_closed: true })
    }

    fn seal(&self) -> Result<SealReport> {
        // Flush each shard, write its footer, fsync, close the file.
        // The library releases your DataDirLock immediately after this returns.
        let revisions = self.db.seal_active_segments()?;
        Ok(SealReport {
            last_revision_per_shard: revisions,
            data_dir_fingerprint: self.db.fingerprint(),
        })
    }

    fn resume_after_abort(&self) -> Result<()> {
        // Successor failed. Reopen your writer state and restart accepting.
        self.db.reopen_writer()?;
        Ok(())
    }

    fn snapshot_state(&self) -> StateSnapshot {
        StateSnapshot {
            shard_count: self.db.shard_count(),
            open_conns: self.db.open_conns(),
            last_revision_per_shard: self.db.revisions(),
        }
    }
}
```

### 2. Detect role at startup

```rust
use handoff::{detect_role, Role, DataDirLock, Incumbent};
use handoff::drainable::ReadinessSnapshot;

fn main() -> anyhow::Result<()> {
    let socket_path = Path::new("/run/my-daemon/handoff.sock");
    let data_dir = Path::new("/var/lib/my-daemon/data");

    match handoff::detect_role()? {
        Role::ColdStart { mut inherited } => {
            // First boot, or supervisor's initial spawn.
            // Bind own listener if none was inherited.
            let listener = inherited
                .take("http")
                .unwrap_or_else(|| TcpListener::bind("0.0.0.0:8080").unwrap());

            let lock = DataDirLock::acquire_or_break_stale(data_dir)?;
            let db = MyDatabase::open(data_dir)?;
            let incumbent = Incumbent::bind_cold_start(socket_path, lock)?;

            let drainable = MyDrainable { db: Arc::clone(&db) };
            thread::spawn(move || incumbent.serve(drainable));

            serve(listener, db);
        }

        Role::Successor(mut s) => {
            // Spawned by the supervisor during a swap.
            s.handshake(build_id())?;
            s.wait_for_begin()?; // blocks until incumbent has sealed and released flock

            let listener = s.take_listener("http").expect("supervisor must pass http listener");
            let lock = DataDirLock::acquire(data_dir)?; // always succeeds; incumbent released it
            let db = MyDatabase::open(data_dir)?; // opens sealed snapshot

            // Send Ready and bind in one call. This is the safe path: by the
            // time the bind runs, the supervisor has committed the prior
            // incumbent, so we can take over the control-socket path
            // without breaking the abort guarantee.
            let incumbent = s.announce_and_bind(
                ReadinessSnapshot {
                    listening_on: vec!["0.0.0.0:8080".into()],
                    healthz_ok: true,
                    advertised_revision_per_shard: db.revisions(),
                },
                socket_path,
                lock,
            )?;

            let drainable = MyDrainable { db: Arc::clone(&db) };
            thread::spawn(move || incumbent.serve(drainable));

            serve(listener, db);
        }
    }
    Ok(())
}
```

## Trigger a handoff

### Reference supervisor binary

```toml
# handoff.toml
control_socket = "/run/my-daemon/handoff.sock"
trigger_socket = "/run/my-daemon/handoff.trigger"
binary         = "/usr/local/bin/my-daemon"
drain_grace_secs = 25
deadline_secs    = 60

[[listeners]]
name = "http"
addr = "0.0.0.0:8080"
```

```sh
# Start the supervisor (it cold-starts your daemon):
handoff-supervisor --config handoff.toml

# Later, trigger a swap to a new binary:
echo "handoff /usr/local/bin/my-daemon-v2" | socat - UNIX-CONNECT:/run/my-daemon/handoff.trigger
# ok: handoff_id=... committed=true abort_reason=None
```

### Embedded in code

```rust
use handoff::supervisor::{Supervisor, SpawnSpec};
use std::time::Duration;

let mut sup = Supervisor::new(Path::new("/run/my-daemon/handoff.sock"))?;
sup.add_listener("http", tcp_listener.as_raw_fd());
sup.resume_from_journal()?; // clear any prior crash state

let outcome = sup.perform_handoff(SpawnSpec {
    binary: PathBuf::from("/usr/local/bin/my-daemon-v2"),
    drain_grace: Duration::from_secs(25),
    deadline: Duration::from_secs(60),
    ..Default::default()
})?;

if outcome.committed {
    println!("swap complete; new pid {}", outcome.child.unwrap().id());
} else {
    println!("aborted: {:?}", outcome.abort_reason);
    // incumbent is still serving; retry when ready
}
```

## Crates

- [`handoff`](./crates/handoff): the library. Sync, no async runtime dependency. Implement `Drainable`; spawn `Incumbent::serve` on a dedicated thread.
- [`handoff-supervisor`](./crates/handoff-supervisor): reference supervisor binary for local development, tests, and simple deployments. Production hosts link the library directly.

## Build

```sh
cargo build --workspace --release
```

## License

MIT
