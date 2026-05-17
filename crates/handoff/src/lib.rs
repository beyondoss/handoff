//! Zero-downtime atomic binary handoff for long-running daemons.
//!
//! See the crate-root `ARCHITECTURE.md` for the wire protocol, state machine,
//! and correctness invariants. This module re-exports the public surface.

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
pub mod state;
pub mod supervisor;
mod util;

pub use drainable::{DrainReport, Drainable, ReadinessSnapshot, SealReport, StateSnapshot};
pub use error::{Error, Result};
pub use fd::{arrange_inherited_fds_on_spawn, pass_listener_fds_on_spawn};
pub use incumbent::Incumbent;
pub use lock::DataDirLock;
pub use protocol::HandoffId;
pub use role::{InheritedListeners, Role, Successor, detect_role};
pub use supervisor::{HandoffOutcome, SpawnSpec, Supervisor};
