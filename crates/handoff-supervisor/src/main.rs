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
//! This binary is a demonstration of the library API and a convenience for
//! local development and tests. Production embedders (`guest-agent`,
//! `beyond-pg`) link `handoff` directly and integrate it with their own
//! lifecycle, observability, and rollout policy machinery.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use handoff::supervisor::{SpawnSpec, Supervisor};

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
        sup.add_listener(name.clone(), *fd);
    }
    if let Some(j) = &cfg.journal {
        sup = sup.with_journal(j.clone());
    }
    let sup = Arc::new(sup);

    // Prepare the trigger socket.
    let _ = std::fs::remove_file(&cfg.trigger_socket);
    if let Some(parent) = cfg.trigger_socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let trigger = UnixListener::bind(&cfg.trigger_socket)
        .with_context(|| format!("bind trigger socket {}", cfg.trigger_socket.display()))?;

    tracing::info!(
        binary = %cfg.binary.display(),
        child_pid = current_child.lock().unwrap().id(),
        trigger = %cfg.trigger_socket.display(),
        "supervisor running"
    );

    // Trigger loop. One client at a time; commands are line-delimited.
    for client in trigger.incoming() {
        let stream = match client {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "trigger accept");
                continue;
            }
        };
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let cmd = line.trim();
        match handle_trigger(cmd, &cfg, &sup, &current_child) {
            Ok(reply) => {
                let _ = writeln!(writer, "{reply}");
            }
            Err(e) => {
                let _ = writeln!(writer, "err: {e}");
            }
        }
    }

    Ok(())
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
            let binary = tokens
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| cfg.binary.clone());
            let spec = SpawnSpec {
                binary,
                args: cfg.args.clone(),
                env: cfg.env.clone(),
                deadline: Duration::from_secs(cfg.deadline_secs),
                drain_grace: Duration::from_secs(cfg.drain_grace_secs),
            };
            let outcome = sup.perform_handoff(spec).context("perform_handoff")?;
            if outcome.committed {
                // The previous primitive should be exiting; reap it.
                if let Ok(mut child) = current_child.lock() {
                    let _ = child.wait();
                    // We've lost the std::process::Child handle for the new
                    // primitive (it was dropped inside perform_handoff). Stub
                    // current_child with a no-op placeholder PID-tracking
                    // approach is out of scope for v1 — see future work.
                }
            }
            Ok(format!(
                "ok: handoff_id={} committed={} abort_reason={:?}",
                outcome.handoff_id, outcome.committed, outcome.abort_reason
            ))
        }
        Some(other) => Ok(format!("err: unknown command '{other}'")),
        None => Ok("err: empty command".to_string()),
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
    let names: Vec<String> = listener_fds.iter().map(|(n, _)| n.clone()).collect();
    cmd.env("LISTEN_FDS", listener_fds.len().to_string());
    cmd.env("LISTEN_FDNAMES", names.join(":"));
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let sources: Vec<RawFd> = listener_fds.iter().map(|(_, f)| *f).collect();
    // SAFETY: pre_exec runs in the forked child before execve; only
    // async-signal-safe calls allowed.
    unsafe {
        cmd.pre_exec(move || {
            for (i, src) in sources.iter().enumerate() {
                let dst = 3 + i as RawFd;
                if *src == dst {
                    if libc::fcntl(*src, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(*src, dst) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd.spawn().context("cold-start primitive spawn")?;
    Ok(child)
}
