//! Reference supervisor binary for handoff-aware daemons.
//!
//! Behavior:
//!
//! 1. Read a TOML config.
//! 2. Bind any requested listeners (held for the lifetime of the supervisor;
//!    duplicated to inherited FDs on every primitive spawn).
//! 3. Cold-start the primitive child (no `HANDOFF_ROLE`).
//! 4. Listen on a local Unix-domain trigger socket; on `handoff <binary>`
//!    drive `handoff::Supervisor::perform_handoff` against the running
//!    primitive's control socket.
//!
//! The trigger socket is a privileged control surface: a command on it makes
//! the supervisor drain the daemon and exec a binary. It is bound `0600` and
//! every client's peer uid is checked (see `allowed_uids`), and the binary a
//! client may name is restricted to `binary` plus `allowed_binaries`.
//!
//! This binary is a demonstration of the library API and a convenience for
//! local development and tests. Production embedders (`guest-agent`,
//! `beyond-pg`) link `handoff` directly and integrate it with their own
//! lifecycle, observability, and rollout policy machinery.

#![deny(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use handoff::supervisor::{SpawnSpec, Supervisor};
use handoff::{bind_socket, pass_listener_fds_on_spawn, peer_uid, peer_uid_is_allowed};

/// Cap on how long a trigger client may take to send its command line, and
/// on how long a reply write may block. The loop is single-threaded, so an
/// unbounded read here is a denial of service against every future handoff:
/// one client that connects and never writes wedges the supervisor forever.
const TRIGGER_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on a trigger command line. Commands are a verb plus an optional path;
/// anything longer is a client sending garbage, and reading it unbounded
/// would let one connection grow the supervisor's memory without limit.
const TRIGGER_MAX_LINE: u64 = 4096;

#[derive(Parser, Debug)]
#[command(
    name = "handoff-supervisor",
    about = "Reference supervisor for handoff-aware daemons"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Where the primitive `Incumbent::bind`s its control socket.
    control_socket: PathBuf,
    /// Default primitive binary; overridable per trigger.
    binary: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<(String, String)>,
    #[serde(default)]
    listeners: Vec<ListenerConfig>,
    /// Local Unix socket the supervisor listens on for trigger commands.
    trigger_socket: PathBuf,
    /// Additional uids allowed to issue trigger commands. The supervisor's
    /// own uid and root are always allowed; every other peer is refused.
    /// The socket is bound `0600`, so this only widens access when a
    /// deployment deliberately relaxes the directory permissions too.
    #[serde(default)]
    allowed_uids: Vec<u32>,
    /// Binaries a trigger client may name in `handoff <binary>`, in addition
    /// to `binary`. A client-supplied path that is not in this set is
    /// refused: the trigger would otherwise be a request to execute an
    /// arbitrary file as the supervisor's user.
    #[serde(default)]
    allowed_binaries: Vec<PathBuf>,
    #[serde(default)]
    journal: Option<PathBuf>,
    #[serde(default = "default_drain_grace_secs")]
    drain_grace_secs: u64,
    #[serde(default = "default_deadline_secs")]
    deadline_secs: u64,
}

fn default_drain_grace_secs() -> u64 {
    25
}
fn default_deadline_secs() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerConfig {
    name: String,
    addr: String,
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let cfg: Config = {
        let s = std::fs::read_to_string(&cli.config)
            .with_context(|| format!("read config {}", cli.config.display()))?;
        toml::from_str(&s).context("parse config")?
    };

    // Bind listeners — we hold these FDs for the lifetime of the supervisor.
    let mut listeners: Vec<(String, TcpListener)> = Vec::with_capacity(cfg.listeners.len());
    for lc in &cfg.listeners {
        let l = TcpListener::bind(&lc.addr)
            .with_context(|| format!("bind {} -> {}", lc.name, lc.addr))?;
        // Inheritance contract: target child should be able to accept on it.
        l.set_nonblocking(false)?;
        listeners.push((lc.name.clone(), l));
    }
    let listener_fds: Vec<(String, RawFd)> = listeners
        .iter()
        .map(|(n, l)| (n.clone(), l.as_raw_fd()))
        .collect();

    // Cold-start the primitive (no HANDOFF_ROLE).
    let cold_child = spawn_primitive_cold_start(&cfg, &listener_fds)?;
    let current_child: Arc<Mutex<Child>> = Arc::new(Mutex::new(cold_child));

    // Build the supervisor that will drive future handoffs.
    let mut sup = Supervisor::new(&cfg.control_socket)?;
    for (name, fd) in &listener_fds {
        sup = sup.with_listener(name.clone(), *fd);
    }
    if let Some(j) = &cfg.journal {
        sup = sup.with_journal(j.clone());
    }
    let sup = Arc::new(sup);

    // Clear any leftover handoff journal from a prior supervisor crash.
    // The incumbent self-recovers on disconnect; we just need to verify it
    // and drop the on-disk state so the next handoff starts clean.
    match sup.resume_from_journal() {
        Ok(Some(prior)) => tracing::warn!(
            handoff_id = %prior.handoff_id,
            phase = ?prior.phase,
            "resumed from prior handoff journal"
        ),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "resume_from_journal failed; continuing"),
    }

    // Prepare the trigger socket. `bind_socket` publishes it 0600 and
    // replaces any stale path atomically, so there is no window in which the
    // trigger exists with umask-derived permissions.
    let trigger = bind_socket(&cfg.trigger_socket)
        .with_context(|| format!("bind trigger socket {}", cfg.trigger_socket.display()))?;

    tracing::info!(
        binary = %cfg.binary.display(),
        child_pid = current_child.lock().unwrap().id(),
        trigger = %cfg.trigger_socket.display(),
        "supervisor running"
    );

    // Trigger loop. One client at a time; commands are line-delimited. No
    // failure below is allowed to escape: the supervisor outlives every
    // client, so a bad connection logs and yields to the next one.
    for client in trigger.incoming() {
        let stream = match client {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "trigger accept");
                continue;
            }
        };
        let Some(cmd) = read_trigger_command(&stream, &cfg) else {
            continue;
        };
        let reply = match handle_trigger(cmd.trim(), &cfg, &sup, &current_child) {
            Ok(reply) => reply,
            Err(e) => format!("err: {e}"),
        };
        let mut writer = &stream;
        let _ = writeln!(writer, "{reply}");
    }

    Ok(())
}

/// Authenticate a trigger client and read its command line, or `None` if the
/// connection should be dropped. Every I/O step is time-bounded so one
/// misbehaving client cannot stall the single-threaded loop.
fn read_trigger_command(stream: &UnixStream, cfg: &Config) -> Option<String> {
    let uid = match peer_uid(stream) {
        Ok(uid) => uid,
        Err(e) => {
            tracing::warn!(error = %e, "could not read trigger peer credentials; dropping");
            return None;
        }
    };
    if !peer_uid_is_allowed(uid, &cfg.allowed_uids) {
        tracing::warn!(peer_uid = uid, "refusing trigger from unauthorized uid");
        let mut writer = stream;
        let _ = writeln!(writer, "err: not permitted");
        return None;
    }
    if let Err(e) = stream
        .set_read_timeout(Some(TRIGGER_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TRIGGER_IO_TIMEOUT)))
    {
        tracing::warn!(error = %e, "could not bound trigger client I/O; dropping");
        return None;
    }

    let mut line = String::new();
    let mut reader = BufReader::new(stream.take(TRIGGER_MAX_LINE));
    match reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line),
        Err(e) => {
            tracing::warn!(error = %e, peer_uid = uid, "trigger command read failed");
            None
        }
    }
}

fn handle_trigger(
    cmd: &str,
    cfg: &Config,
    sup: &Supervisor,
    current_child: &Arc<Mutex<Child>>,
) -> Result<String> {
    // Trigger syntax: `handoff [<binary>]`. Optional binary overrides cfg.binary.
    let mut tokens = cmd.split_whitespace();
    match tokens.next() {
        Some("handoff") => {
            let binary = match tokens.next() {
                Some(requested) => resolve_requested_binary(Path::new(requested), cfg)?,
                None => cfg.binary.clone(),
            };
            let spec = SpawnSpec {
                binary,
                args: cfg.args.clone(),
                env: cfg.env.clone(),
                deadline: Duration::from_secs(cfg.deadline_secs),
                drain_grace: Duration::from_secs(cfg.drain_grace_secs),
            };
            let mut outcome = sup.perform_handoff(spec).context("perform_handoff")?;
            let handoff_id = outcome.handoff_id;
            let committed = outcome.committed;
            let abort_reason = outcome.abort_reason.clone();
            if committed
                && let Some(new_child) = outcome.child.take()
                && let Ok(mut current) = current_child.lock()
            {
                let outgoing_pid = current.id();
                // Bounded reap: O should return from `serve()` as soon as
                // it processes `Commit`. If it doesn't (buggy Drainable
                // hanging in cleanup, or `Commit` lost to a crash), don't
                // let it block the trigger handler from accepting the
                // next handoff. Move on after the grace period; the OS
                // will eventually reap the orphan.
                let reap_grace = Duration::from_secs(cfg.deadline_secs);
                match wait_child_with_timeout(&mut current, reap_grace) {
                    Some(Ok(status)) => tracing::info!(
                        pid = outgoing_pid,
                        status = ?status,
                        "outgoing primitive exited"
                    ),
                    Some(Err(e)) => tracing::warn!(
                        pid = outgoing_pid,
                        error = %e,
                        "failed to reap outgoing primitive"
                    ),
                    None => tracing::warn!(
                        pid = outgoing_pid,
                        grace_secs = cfg.deadline_secs,
                        "outgoing primitive did not exit within reap grace; \
                         abandoning to OS reaper and proceeding"
                    ),
                }
                *current = new_child;
            }
            Ok(format!(
                "ok: handoff_id={handoff_id} committed={committed} abort_reason={abort_reason:?}"
            ))
        }
        Some(other) => Ok(format!("err: unknown command '{other}'")),
        None => Ok("err: empty command".to_string()),
    }
}

/// Map a client-supplied binary path onto the configured allowlist.
///
/// The trigger socket is reachable by a local user, and `perform_handoff`
/// execs whatever path it is handed — so an unrestricted override is a
/// "run this file as the supervisor's user" primitive. Paths are compared
/// after canonicalization so `./foo`, `/srv/../srv/foo`, and a symlink to an
/// allowed target are all recognized as the same file.
fn resolve_requested_binary(requested: &Path, cfg: &Config) -> Result<PathBuf> {
    let canonical = requested
        .canonicalize()
        .with_context(|| format!("resolve requested binary {}", requested.display()))?;
    let permitted = std::iter::once(&cfg.binary)
        .chain(cfg.allowed_binaries.iter())
        .any(|allowed| {
            allowed
                .canonicalize()
                .is_ok_and(|allowed| allowed == canonical)
        });
    if !permitted {
        anyhow::bail!(
            "binary {} is not in the configured allowlist (`binary` + `allowed_binaries`)",
            requested.display()
        );
    }
    Ok(canonical)
}

/// Poll-wait on a child up to `timeout`. Returns `Some(result)` if the
/// child exited within the window, `None` if the timeout expired first.
/// 50 ms poll interval — child exits are rare and the cost of one extra
/// syscall per tick is negligible compared to keeping the trigger handler
/// unblocked.
fn wait_child_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::io::Result<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(Ok(status)),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Some(Err(e)),
        }
    }
}

/// Spawn the first primitive process. Same FD-dup dance as
/// `handoff::supervisor::Supervisor::spawn_successor` but without
/// `HANDOFF_ROLE`/`HANDOFF_SOCK_FD`, since this is a cold start (no incumbent
/// to hand off from).
fn spawn_primitive_cold_start(cfg: &Config, listener_fds: &[(String, RawFd)]) -> Result<Child> {
    let mut cmd = Command::new(&cfg.binary);
    cmd.args(&cfg.args);
    for (k, v) in &cfg.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // No `HANDOFF_ROLE` — this is a cold start. No control socket either,
    // so `extra_fd` is `None`. The same helper is used by the library's
    // successor spawn so the env/FD convention stays in lockstep.
    pass_listener_fds_on_spawn(&mut cmd, listener_fds, None);
    let child = cmd.spawn().context("cold-start primitive spawn")?;
    Ok(child)
}
