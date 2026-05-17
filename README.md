# handoff

Zero-downtime atomic binary handoff for long-running daemons.

A small Rust library + reference supervisor that lets you replace the binary of a running stateful daemon without dropping in-flight requests, losing acked writes, or visibly closing the listen socket.

## What it does

- **Listener inheritance.** A supervisor binds listen sockets once and passes them to every successor via `LISTEN_FDS` env vars (same convention as systemd). The kernel-side socket lives across binary swaps; the accept queue absorbs the brief window between old and new processes.
- **Coordinated drain + seal.** A typed protocol over a Unix-domain socket sequences "old stops accepting → old finishes in-flight work → old flushes durable state → old releases its data-dir lock → new acquires it → new declares ready → old exits." Each phase is acknowledged.
- **Data-dir flock.** Exactly one process holds the writer lock on the data directory at any time. If the holder dies, the kernel releases the lock; stale holders are detected via `pidfd_open` and broken safely.
- **Abort + resume.** If the successor fails before announcing ready, the incumbent reopens its writable state and resumes serving. No half-state, no orphan WAL segments.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the wire protocol, state machine, and correctness invariants.

## Crates

- [`handoff`](./crates/handoff) — the library. Sync, runtime-agnostic. Implement the `Drainable` trait in your daemon; spawn `Incumbent::serve` on a dedicated thread.
- [`handoff-supervisor`](./crates/handoff-supervisor) — a reference supervisor binary. Useful for local development, tests, and one-off systemd-unit-style deployments. Production embedding hosts (e.g. a guest-agent) link the library directly.

## Quick start

```sh
cargo build --workspace --release
```

## License

MIT
