//! Public error type for the `handoff` crate.
//!
//! All fallible operations in the library return [`Result<T>`]. The error enum
//! is `Send` so it can flow across the consumer's runtime-bridging channels.

use std::sync::mpsc::{RecvError, RecvTimeoutError, SendError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("codec: {0}")]
    Codec(#[from] postcard::Error),

    #[error("nix: {0}")]
    Nix(#[from] nix::Error),

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("frame too large: {0} bytes exceeds cap")]
    FrameTooLarge(u32),

    #[error("frame malformed: declared length {0} is below the protocol minimum")]
    FrameMalformed(u32),

    #[error("peer announced pid {announced} does not match expected pid {expected}")]
    PidMismatch { expected: u32, announced: u32 },

    #[error(
        "protocol version mismatch: our range {our_min}..={our_max}, peer range \
         {their_min}..={their_max}"
    )]
    VersionMismatch {
        our_min: u16,
        our_max: u16,
        their_min: u16,
        their_max: u16,
    },

    #[error("unexpected message for current state: {0}")]
    UnexpectedMessage(&'static str),

    #[error("timed out waiting for {0}")]
    Timeout(&'static str),

    #[error("data-dir lock held by pid {holder_pid}")]
    LockHeld { holder_pid: i32 },

    #[error("refused to break lock held by live process {holder_pid}")]
    StaleLockBreakRefused { holder_pid: i32 },

    #[error("handoff already in progress")]
    HandoffInProgress,

    #[error("handoff aborted by peer: {0}")]
    Aborted(String),

    #[error("required env var {0} not set")]
    MissingEnv(&'static str),

    #[error("env var {var} has bad value: {value}")]
    BadEnv { var: &'static str, value: String },

    #[error("internal channel disconnected")]
    Channel,
}

pub type Result<T> = std::result::Result<T, Error>;

// Channel conversions — the bridge pattern relies on `?` working across mpsc.
impl<T> From<SendError<T>> for Error {
    fn from(_: SendError<T>) -> Self {
        Error::Channel
    }
}

impl From<RecvError> for Error {
    fn from(_: RecvError) -> Self {
        Error::Channel
    }
}

impl From<RecvTimeoutError> for Error {
    fn from(e: RecvTimeoutError) -> Self {
        match e {
            RecvTimeoutError::Timeout => Error::Timeout("channel recv"),
            RecvTimeoutError::Disconnected => Error::Channel,
        }
    }
}
