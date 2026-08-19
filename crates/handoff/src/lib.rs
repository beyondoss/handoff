//! Zero-downtime atomic binary handoff for long-running daemons.
//!
//! See the crate-root `ARCHITECTURE.md` for the wire protocol, state machine,
//! and correctness invariants. This module re-exports the public surface.

// Crate-wide safety gates. `unsafe_code` is denied by default; the modules
// that legitimately need it (FD inheritance, env mutation at single-threaded
// startup, post-fork crash injection, raw socket options and peer-credential
// lookups, and `FromRawFd` on kernel-handed descriptors) opt back in with
// `#[allow(unsafe_code)]` and
// carry per-block `// SAFETY:` comments. `unused_must_use` is denied so a
// dropped `Result` becomes a hard error rather than a silent regression.
#![deny(unsafe_code)]
#![deny(unused_must_use)]

pub mod crash;
pub mod drainable;
pub mod error;
pub mod fd;
pub mod frame;
pub mod incumbent;
pub mod lock;
pub mod metrics;
pub mod protocol;
pub mod role;
pub mod sock;
pub mod state;
pub mod supervisor;
mod util;

pub use drainable::{DrainReport, Drainable, ReadinessSnapshot, SealReport, StateSnapshot};
pub use error::{Error, Result};
pub use fd::{arrange_inherited_fds_on_spawn, pass_listener_fds_on_spawn};
pub use incumbent::Incumbent;
pub use lock::DataDirLock;
pub use protocol::HandoffId;
pub use role::{
    BegunSuccessor, HandshookSuccessor, HeartbeatGuard, InheritedListeners, Role, Successor,
    detect_role,
};
pub use sock::{bind_socket, peer_uid, peer_uid_is_allowed, validate_socket_path};
pub use supervisor::{HandoffOutcome, SpawnSpec, Supervisor};
