//! Length-prefixed framing over a sync byte stream (typically `UnixStream`).
//!
//! Frame layout — little-endian throughout:
//!
//! ```text
//! [0..4]  u32 frame_len   (length of everything after this field)
//! [4..6]  u16 proto_version
//! [6..]   postcard-encoded `Message`
//! ```
//!
//! Frames are bounded by [`MAX_FRAME_BYTES`] to keep a malicious or buggy peer
//! from triggering an unbounded allocation on the reader side.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::protocol::{Message, ProtoVersion};

/// Hard cap on a single frame's `frame_len`. 1 MiB is far larger than any
/// legitimate handoff message; receipts above this are treated as malformed.
pub const MAX_FRAME_BYTES: u32 = 1 << 20;

/// Size of the `frame_len` prefix on the wire.
const LEN_PREFIX: usize = 4;
/// Size of the `proto_version` field that lives inside `frame_len`.
const VERSION_FIELD: usize = 2;

/// Encode and write one `Message` to `w`. Flushes before returning.
pub fn write_message<W: Write>(w: &mut W, version: ProtoVersion, msg: &Message) -> Result<()> {
    let payload = postcard::to_allocvec(msg)?;
    let inner_len = VERSION_FIELD
        .checked_add(payload.len())
        .ok_or(Error::FrameTooLarge(u32::MAX))?;
    if inner_len > MAX_FRAME_BYTES as usize {
        return Err(Error::FrameTooLarge(inner_len as u32));
    }
    let frame_len = inner_len as u32;
    w.write_all(&frame_len.to_le_bytes())?;
    w.write_all(&version.to_le_bytes())?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}

/// Read one `Message` from `r`. Blocks until a complete frame is consumed or
/// the stream returns an error / EOF.
pub fn read_message<R: Read>(r: &mut R) -> Result<(ProtoVersion, Message)> {
    let mut len_buf = [0u8; LEN_PREFIX];
    r.read_exact(&mut len_buf)?;
    let frame_len = u32::from_le_bytes(len_buf);
    if frame_len < VERSION_FIELD as u32 {
        return Err(Error::FrameMalformed(frame_len));
    }
    if frame_len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge(frame_len));
    }

    let mut ver_buf = [0u8; VERSION_FIELD];
    r.read_exact(&mut ver_buf)?;
    let version = u16::from_le_bytes(ver_buf);

    let payload_len = (frame_len as usize) - VERSION_FIELD;
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload)?;

    let msg = postcard::from_bytes(&payload)?;
    Ok((version, msg))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::protocol::{Capabilities, HandoffId, Message, PROTO_MAX, PROTO_MIN, Side};

    fn roundtrip(msg: Message) -> Message {
        let mut buf = Vec::new();
        write_message(&mut buf, PROTO_MAX, &msg).unwrap();
        let mut cursor = Cursor::new(buf);
        let (ver, decoded) = read_message(&mut cursor).unwrap();
        assert_eq!(ver, PROTO_MAX);
        decoded
    }

    #[test]
    fn roundtrip_hello() {
        let msg = Message::Hello {
            role: Side::Incumbent,
            pid: 1234,
            build_id: vec![0xab; 20],
            proto_min: PROTO_MIN,
            proto_max: PROTO_MAX,
            capabilities: Capabilities::default(),
        };
        let decoded = roundtrip(msg.clone());
        match (msg, decoded) {
            (Message::Hello { pid: a, .. }, Message::Hello { pid: b, .. }) => assert_eq!(a, b),
            _ => panic!("variant mismatch"),
        }
    }

    #[test]
    fn roundtrip_seal_complete() {
        let id = HandoffId::new();
        let msg = Message::SealComplete {
            handoff_id: id,
            last_revision_per_shard: vec![10, 20, 30],
            data_dir_fingerprint: [7u8; 32],
        };
        let decoded = roundtrip(msg);
        match decoded {
            Message::SealComplete {
                handoff_id,
                last_revision_per_shard,
                data_dir_fingerprint,
            } => {
                assert_eq!(handoff_id, id);
                assert_eq!(last_revision_per_shard, vec![10, 20, 30]);
                assert_eq!(data_dir_fingerprint, [7u8; 32]);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[test]
    fn rejects_oversize_frame_on_read() {
        // Forge a length prefix of MAX+1.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_message(&mut cursor),
            Err(Error::FrameTooLarge(_))
        ));
    }

    #[test]
    fn rejects_undersize_frame_on_read() {
        // frame_len = 1 < VERSION_FIELD
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_message(&mut cursor),
            Err(Error::FrameMalformed(_))
        ));
    }
}
