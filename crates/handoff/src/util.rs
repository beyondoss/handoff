//! Internal shared helpers. Not part of the public API.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time as Unix milliseconds. Returns 0 if the system
/// clock predates the Unix epoch (which would indicate a misconfigured
/// host; the protocol carries this value for diagnostics, not ordering).
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
