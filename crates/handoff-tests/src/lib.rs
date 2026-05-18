//! Fault-injection test harness for the `handoff` crate.
//!
//! The harness spawns **real** subprocess binaries for the three roles —
//! supervisor (S), incumbent (O), successor (N) — and lets each one be
//! crashed at any named protocol boundary. Tests then assert post-crash
//! invariants (flock holder, journal contents, control-socket reachability,
//! marker files) and verify recovery via a fresh supervisor.
//!
//! # Layout
//!
//! ```text
//! Fixture                                          tempdir/
//!   ├── data_dir      .handoff.lock, .pidfile, primitive data
//!   ├── control_sock  unix socket where Incumbent binds
//!   ├── journal       supervisor state journal
//!   ├── markers/      *.marker files written by fixture binaries
//!   └── logs/         captured stdout/stderr per role
//! ```
//!
//! # Process model
//!
//! Every fixture binary clears `HANDOFF_CRASH_AT` before spawning children,
//! and the supervisor binary always sets the value explicitly (possibly
//! empty) in `SpawnSpec::env`. This means crash points never leak between
//! roles via env inheritance — each role sees only the crash point the
//! harness intended for it.
//!
//! # Naming
//!
//! Crash points are constants re-exported from [`handoff::crash::points`]
//! plus role-specific points exported from [`primitive_points`]. Use the
//! constant, never a raw string, so the compiler catches typos.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub use handoff::crash::points;
pub use handoff::state::Phase;

/// Exit code used by [`handoff::crash::maybe_crash`] when a crash point
/// fires. Distinct from 0 (success), 1 (normal error), and 134/139 (signal
/// terminations), so tests can pin the cause.
pub const CRASH_EXIT_CODE: i32 = 99;

/// Crash points exported by the fixture binaries (in addition to the
/// library's own points in [`handoff::crash::points`]). These cover lifecycle
/// events that live in fixture code (mock drain/seal failures, successor
/// startup) rather than in the production library.
pub mod primitive_points {
    /// Inside the test primitive's `Drainable::drain` implementation, after
    /// marking "drain start" but before returning `Ok`.
    pub const O_INSIDE_DRAIN: &str = "o-inside-drain";
    /// Inside the test primitive's `Drainable::seal` implementation, after
    /// marking "seal start" but before returning `Ok`.
    pub const O_INSIDE_SEAL: &str = "o-inside-seal";

    /// Successor process: before sending `Hello`.
    pub const N_BEFORE_HANDSHAKE: &str = "n-before-handshake";
    /// Successor process: after `handshake` returns, before `wait_for_begin`.
    pub const N_AFTER_HANDSHAKE: &str = "n-after-handshake";
    /// Successor process: after `wait_for_begin` returns, before opening state.
    pub const N_AFTER_BEGIN: &str = "n-after-begin";
    /// Successor process: about to call `announce_ready`.
    pub const N_BEFORE_ANNOUNCE_READY: &str = "n-before-announce-ready";
}

/// Read a marker file written by a fixture binary that recorded a value
/// (e.g. a PID). Returns the trimmed file contents, or `None` if missing.
pub fn read_marker_value(markers: &Path, marker: &str) -> Option<String> {
    std::fs::read_to_string(markers.join(format!("{marker}.marker")))
        .ok()
        .map(|s| s.trim().to_string())
}

/// One-shot scenario fixture. Owns the tempdir; cleanup is automatic on drop.
///
/// Construct with the [`fixture!`] macro from a test, which resolves the
/// fixture binary paths via Cargo's `CARGO_BIN_EXE_<name>` env vars
/// (available only at integration-test compile time, hence the macro).
pub struct Fixture {
    _root: tempfile::TempDir,
    pub data_dir: PathBuf,
    pub control_socket: PathBuf,
    pub journal: PathBuf,
    pub markers: PathBuf,
    pub logs: PathBuf,
    pub primitive_binary: PathBuf,
    pub supervisor_binary: PathBuf,
}

/// Build a [`Fixture`] from a test, resolving the fixture binary paths at
/// compile time via Cargo's per-binary env vars.
#[macro_export]
macro_rules! fixture {
    () => {{
        $crate::Fixture::new(
            ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_handoff-test-primitive")),
            ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_handoff-test-supervisor")),
        )
    }};
}

impl Fixture {
    /// Construct a fresh fixture with the binary paths the harness should
    /// spawn for each role. Most tests use the [`fixture!`] macro instead of
    /// calling this directly.
    pub fn new(primitive_binary: PathBuf, supervisor_binary: PathBuf) -> Self {
        let root = tempfile::Builder::new()
            .prefix("handoff-tests-")
            .tempdir()
            .expect("create tempdir");
        let path = root.path();
        let data_dir = path.join("data");
        let markers = path.join("markers");
        let logs = path.join("logs");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&markers).unwrap();
        std::fs::create_dir_all(&logs).unwrap();
        Self {
            control_socket: path.join("control.sock"),
            journal: path.join("state.bin"),
            data_dir,
            markers,
            logs,
            primitive_binary,
            supervisor_binary,
            _root: root,
        }
    }

    /// Cold-start the primitive binary as the initial incumbent. Returns a
    /// [`Process`] handle. The harness uses `bind_cold_start` semantics: any
    /// stale socket file is removed before bind.
    pub fn cold_start_primitive(&self) -> PrimitiveBuilder<'_> {
        PrimitiveBuilder {
            fixture: self,
            crash_at: None,
            seal_fails: false,
            seal_delay_ms: 0,
            drain_delay_ms: 0,
        }
    }

    /// Spawn the supervisor binary to perform one handoff against the
    /// running incumbent.
    pub fn perform_handoff(&self) -> SupervisorBuilder<'_> {
        SupervisorBuilder {
            fixture: self,
            crash_at_supervisor: None,
            crash_at_successor: None,
        }
    }

    /// Current state of the data-dir flock. Read-only probe — never holds
    /// the lock across the call.
    pub fn flock_state(&self) -> FlockState {
        let pidfile = self.data_dir.join(".handoff.pidfile");
        let lockfile = self.data_dir.join(".handoff.lock");
        if !lockfile.exists() {
            return FlockState::Free;
        }
        // Attempt a non-blocking acquire from a fresh FD; if EWOULDBLOCK,
        // someone holds it. We deliberately don't hold it across return — we
        // immediately drop our flock so the probe is non-disruptive.
        use nix::fcntl::{Flock, FlockArg};
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&lockfile)
        {
            Ok(f) => f,
            Err(_) => return FlockState::Free,
        };
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(_taken) => FlockState::Free,
            Err((_, _)) => {
                let pid = std::fs::read_to_string(&pidfile)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(0);
                let alive = pid > 0 && is_alive(pid);
                FlockState::Held { pid, alive }
            }
        }
    }

    /// Read the on-disk journal phase, if a journal exists. `None` means no
    /// journal file (either never written or already cleared).
    pub fn journal_phase(&self) -> Option<Phase> {
        let bytes = std::fs::read(&self.journal).ok()?;
        let journal: handoff::state::StateJournal = postcard::from_bytes(&bytes).ok()?;
        Some(journal.phase)
    }

    /// True if the journal file exists on disk.
    pub fn journal_present(&self) -> bool {
        self.journal.exists()
    }

    /// Probe whether the control socket currently has a process accepting
    /// on it. Connects, reads up to the expected `Hello` frame, drops.
    pub fn control_socket_serves(&self) -> bool {
        let Ok(mut stream) = UnixStream::connect(&self.control_socket) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 4];
        // Reading the 4-byte length prefix is enough: if a server is on the
        // other end, it has already written its Hello frame.
        stream.read_exact(&mut buf).is_ok()
    }

    /// Block until `marker` appears in the markers directory, up to
    /// `timeout`. Returns `true` if the file appeared, `false` on timeout.
    pub fn wait_marker(&self, marker: &str, timeout: Duration) -> bool {
        let path = self.markers.join(format!("{marker}.marker"));
        let deadline = Instant::now() + timeout;
        loop {
            if path.exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// True if the named marker file exists.
    pub fn marker_exists(&self, marker: &str) -> bool {
        self.markers.join(format!("{marker}.marker")).exists()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Successful handoffs leak the new primitive's `Child` handle (the
        // supervisor binary `mem::forget`s it because the new primitive is
        // expected to outlive its supervisor). Reap it here so cargo test
        // doesn't accumulate orphans across runs.
        if let Some(pid_str) = std::fs::read_to_string(self.data_dir.join(".handoff.pidfile")).ok()
            && let Ok(pid) = pid_str.trim().parse::<i32>()
            && pid > 0
            && is_alive(pid)
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

/// Builder for cold-starting a primitive. Configure crash injection and
/// drainable behavior before spawning.
pub struct PrimitiveBuilder<'a> {
    fixture: &'a Fixture,
    crash_at: Option<&'static str>,
    seal_fails: bool,
    seal_delay_ms: u64,
    drain_delay_ms: u64,
}

impl PrimitiveBuilder<'_> {
    /// Inject a crash at the named point. Must be a [`points`] or
    /// [`primitive_points`] constant.
    pub fn crash_at(mut self, point: &'static str) -> Self {
        self.crash_at = Some(point);
        self
    }

    /// Configure the test drainable to return `Err` from `seal()` on the
    /// next request. Resets after firing once.
    pub fn seal_fails_once(mut self) -> Self {
        self.seal_fails = true;
        self
    }

    /// Sleep this long inside `Drainable::seal` before returning success.
    /// Used by the slow-seal test to verify that heartbeats keep the
    /// supervisor's liveness clock fresh during long consumer hooks.
    pub fn seal_delay(mut self, delay: Duration) -> Self {
        self.seal_delay_ms = delay.as_millis() as u64;
        self
    }

    /// Sleep this long inside `Drainable::drain` before returning success.
    pub fn drain_delay(mut self, delay: Duration) -> Self {
        self.drain_delay_ms = delay.as_millis() as u64;
        self
    }

    /// Spawn the primitive subprocess. Blocks until the primitive has
    /// written its `serving.marker`, or `timeout` elapses.
    pub fn spawn(self, ready_timeout: Duration) -> Process {
        let binary = &self.fixture.primitive_binary;
        let log_path = self.fixture.logs.join("primitive.log");
        let mut cmd = Command::new(binary);
        cmd.env("HANDOFF_DATA_DIR", &self.fixture.data_dir)
            .env("HANDOFF_CONTROL_SOCKET", &self.fixture.control_socket)
            .env("HANDOFF_MARKER_DIR", &self.fixture.markers)
            .env("HANDOFF_CRASH_AT", self.crash_at.unwrap_or(""))
            .env("HANDOFF_CRASH_ROLE", "primitive")
            .env("HANDOFF_CRASH_MARKER_DIR", &self.fixture.markers)
            .env(
                "HANDOFF_SEAL_FAILS_ONCE",
                if self.seal_fails { "1" } else { "0" },
            )
            .env("HANDOFF_SEAL_DELAY_MS", self.seal_delay_ms.to_string())
            .env("HANDOFF_DRAIN_DELAY_MS", self.drain_delay_ms.to_string())
            .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(open_log(&log_path))
            .stderr(open_log(&log_path));

        let child = cmd.spawn().expect("spawn test primitive");
        let pid = child.id();
        let proc = Process {
            child: Some(child),
            pid,
            role: "primitive",
            log_path,
        };
        if !self.fixture.wait_marker("serving", ready_timeout) {
            panic!(
                "primitive (pid {pid}) did not write serving.marker within {ready_timeout:?}\n{}",
                proc.tail_log()
            );
        }
        proc
    }
}

/// Builder for one supervisor-driven handoff.
pub struct SupervisorBuilder<'a> {
    fixture: &'a Fixture,
    crash_at_supervisor: Option<&'static str>,
    crash_at_successor: Option<&'static str>,
}

impl SupervisorBuilder<'_> {
    /// Make the supervisor crash at the named point. Use a [`points`]
    /// constant prefixed `S_*`.
    pub fn crash_supervisor_at(mut self, point: &'static str) -> Self {
        self.crash_at_supervisor = Some(point);
        self
    }

    /// Make the successor (N) crash at the named point. Use a
    /// [`primitive_points`] constant prefixed `N_*`.
    pub fn crash_successor_at(mut self, point: &'static str) -> Self {
        self.crash_at_successor = Some(point);
        self
    }

    /// Run the supervisor synchronously. Returns when the supervisor
    /// subprocess exits (cleanly or via crash injection).
    pub fn run(self, timeout: Duration) -> ExitObservation {
        let binary = &self.fixture.supervisor_binary;
        let primitive = &self.fixture.primitive_binary;
        let log_path = self.fixture.logs.join("supervisor.log");
        let mut cmd = Command::new(binary);
        cmd.env("HANDOFF_CONTROL_SOCKET", &self.fixture.control_socket)
            .env("HANDOFF_DATA_DIR", &self.fixture.data_dir)
            .env("HANDOFF_JOURNAL", &self.fixture.journal)
            .env("HANDOFF_MARKER_DIR", &self.fixture.markers)
            .env("HANDOFF_PRIMITIVE_BINARY", primitive)
            .env("HANDOFF_CRASH_AT", self.crash_at_supervisor.unwrap_or(""))
            .env("HANDOFF_CRASH_ROLE", "supervisor")
            .env("HANDOFF_CRASH_MARKER_DIR", &self.fixture.markers)
            .env(
                "HANDOFF_CRASH_AT_FOR_N",
                self.crash_at_successor.unwrap_or(""),
            )
            .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(open_log(&log_path))
            .stderr(open_log(&log_path));

        let mut child = cmd.spawn().expect("spawn test supervisor");
        let exit_status = wait_with_timeout(&mut child, timeout)
            .unwrap_or_else(|| panic!("supervisor did not exit within {timeout:?}"));
        let (stdout, stderr) = read_log_split(&log_path);
        ExitObservation {
            status: exit_status,
            stdout,
            stderr,
            role: "supervisor",
        }
    }
}

/// Handle to a running fixture subprocess. Auto-kill+reap on drop unless
/// `wait_exit` consumed the process.
pub struct Process {
    child: Option<Child>,
    pub pid: u32,
    pub role: &'static str,
    pub log_path: PathBuf,
}

impl Process {
    /// Send SIGKILL and reap. Idempotent.
    pub fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Wait up to `timeout` for the process to exit. Panics on timeout —
    /// tests that expect a process to outlive the harness call should not
    /// invoke this.
    pub fn wait_exit(mut self, timeout: Duration) -> ExitObservation {
        let Some(mut child) = self.child.take() else {
            panic!(
                "Process::wait_exit called twice on {} (pid {})",
                self.role, self.pid
            );
        };
        let status = wait_with_timeout(&mut child, timeout).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{} (pid {}) did not exit within {timeout:?}\n{}",
                self.role,
                self.pid,
                self.tail_log()
            )
        });
        let (stdout, stderr) = read_log_split(&self.log_path);
        ExitObservation {
            status,
            stdout,
            stderr,
            role: self.role,
        }
    }

    /// Best-effort check: is the process still alive? Uses `kill(pid, 0)`,
    /// not `try_wait`, so it works even after the parent harness has
    /// relinquished the `Child` handle.
    pub fn alive(&self) -> bool {
        is_alive(self.pid as i32)
    }

    /// Last 4 KiB of the captured log. Used in panic messages.
    pub fn tail_log(&self) -> String {
        read_log_tail(&self.log_path, 4096)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The captured result of a subprocess exit. Carries stdout/stderr so panic
/// messages and assertion failures can quote the actual log instead of just
/// saying "exit status: signal: 9".
pub struct ExitObservation {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub role: &'static str,
}

impl ExitObservation {
    /// Assert the process exited via [`handoff::crash::maybe_crash`] at the
    /// expected point. Verified two ways: the exit code is
    /// [`CRASH_EXIT_CODE`] and a `crashed-<role>.marker` file in the markers
    /// dir contains the point name.
    pub fn assert_crashed_at(&self, fixture: &Fixture, expected_point: &str) {
        let role = self.role;
        let code = self.status.code();
        if code != Some(CRASH_EXIT_CODE) {
            panic!(
                "{role} did not exit via crash injection (status: {:?}, expected code {CRASH_EXIT_CODE})\n\
                 expected crash point: {expected_point}\n--- {role} log ---\n{}",
                self.status,
                self.stdout_and_stderr()
            );
        }
        let marker = fixture.markers.join(format!("crashed-{role}.marker"));
        let observed = std::fs::read_to_string(&marker).unwrap_or_default();
        if observed != expected_point {
            panic!(
                "{role} crashed at unexpected point.\n  expected: {expected_point}\n  observed: {observed:?}\n--- {role} log ---\n{}",
                self.stdout_and_stderr()
            );
        }
    }

    /// Assert a clean (exit code 0) shutdown.
    pub fn assert_clean_exit(&self) {
        if self.status.code() != Some(0) {
            panic!(
                "{} did not exit cleanly: {:?}\n--- {} log ---\n{}",
                self.role,
                self.status,
                self.role,
                self.stdout_and_stderr()
            );
        }
    }

    fn stdout_and_stderr(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// Result of [`Fixture::flock_state`].
#[derive(Debug, PartialEq, Eq)]
pub enum FlockState {
    /// No process holds the data-dir flock right now.
    Free,
    /// Someone holds the flock. `pid` is the PID from the pidfile (0 if
    /// unparseable); `alive` is the result of `kill(pid, 0)`.
    Held { pid: i32, alive: bool },
}

impl FlockState {
    /// Assert the lock is held by *some* live process (we don't know which
    /// PID without more context).
    pub fn assert_held_by_live_process(&self) {
        match self {
            FlockState::Held { alive: true, .. } => {}
            other => panic!("expected flock held by a live process, got {other:?}"),
        }
    }

    /// Assert no process holds the lock.
    pub fn assert_free(&self) {
        if !matches!(self, FlockState::Free) {
            panic!("expected flock free, got {self:?}");
        }
    }
}

// -------------------------------------------------------------------- helpers

fn open_log(path: &Path) -> Stdio {
    // Append so stdout and stderr interleave into one file; readers stitch
    // by line order, not by stream.
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open log");
    Stdio::from(f)
}

fn read_log_split(path: &Path) -> (String, String) {
    // We merge stdout/stderr into one file, so "split" here just returns
    // the combined output as stdout and an empty stderr — keeps the
    // public ExitObservation API future-proof if we later separate them.
    (
        std::fs::read_to_string(path).unwrap_or_default(),
        String::new(),
    )
}

fn read_log_tail(path: &Path, max_bytes: usize) -> String {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    if s.len() <= max_bytes {
        return s;
    }
    let cut = s.len() - max_bytes;
    format!("…(log truncated)\n{}", &s[cut..])
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

fn is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Ok(())
    )
}

/// Sugar for tests that want a fresh tracing subscriber per scenario. Safe
/// to call multiple times — the global default is set at most once per
/// process and ignored thereafter.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// Internal helper used by both fixture binaries to translate
/// `HANDOFF_CRASH_AT_FOR_N` (set by harness) into the per-process
/// `HANDOFF_CRASH_AT` (read by `crash_here!`). No-op if the var is unset.
///
/// Crucially, this does NOT touch the current process's env; the test
/// binaries call `cmd.env("HANDOFF_CRASH_AT", ...)` to explicitly set the
/// child's value, which overrides any inherited copy.
pub fn crash_at_from_self_env() -> String {
    std::env::var("HANDOFF_CRASH_AT").unwrap_or_default()
}

/// Look up the optional `HANDOFF_CRASH_AT_FOR_N` value the harness asked the
/// supervisor binary to propagate to the spawned successor. Empty string
/// means "no successor crash."
pub fn crash_for_successor() -> String {
    std::env::var("HANDOFF_CRASH_AT_FOR_N").unwrap_or_default()
}

/// Write a marker file at `$HANDOFF_MARKER_DIR/<name>.marker`. Used by
/// fixture binaries to signal lifecycle events to the harness.
pub fn write_marker(name: &str) {
    let dir = match std::env::var_os("HANDOFF_MARKER_DIR") {
        Some(d) => PathBuf::from(d),
        None => return,
    };
    let _ = std::fs::write(dir.join(format!("{name}.marker")), name);
}

/// Path-typed wrapper around `OsStr::new`. Helps fixture binaries take
/// values from env vars without litter.
pub fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(key).unwrap_or_else(|| OsStr::new("").to_os_string()))
}
