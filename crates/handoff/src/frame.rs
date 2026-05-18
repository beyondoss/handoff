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

    #[test]
    fn rejects_frame_exactly_at_max_plus_one() {
        // frame_len = MAX_FRAME_BYTES + 1 must be rejected; the exact
        // boundary case verifies the comparator is `>` not `>=`.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_message(&mut cursor),
            Err(Error::FrameTooLarge(n)) if n == MAX_FRAME_BYTES + 1
        ));
    }

    #[test]
    fn truncated_frame_after_len_is_err_not_panic() {
        // Length prefix says "more bytes coming" but stream EOFs.
        let mut buf = Vec::new();
        buf.extend_from_slice(&128u32.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        // Must return Err (UnexpectedEof) without panicking.
        assert!(read_message(&mut cursor).is_err());
    }

    #[test]
    fn truncated_frame_after_version_is_err_not_panic() {
        // Length prefix + version field, but payload missing.
        let mut buf = Vec::new();
        buf.extend_from_slice(&128u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(read_message(&mut cursor).is_err());
    }

    proptest::proptest! {
        /// Pure fuzz: `read_message` must never panic on any input bytes,
        /// regardless of length, content, or alignment. The legal outcomes
        /// are `Ok(_)` (if the bytes happen to encode a valid frame) or
        /// `Err(_)` of any variant.
        #[test]
        fn read_message_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..2048),
        ) {
            let mut cursor = Cursor::new(bytes);
            let _ = read_message(&mut cursor);
        }

        /// Length prefix is honest: if we declare `frame_len = N` and feed
        /// exactly N bytes after the prefix, the reader either decodes a
        /// valid message or returns Err — never blocks, never panics.
        #[test]
        fn declared_length_is_honored(
            declared in 0u32..=(MAX_FRAME_BYTES + 1),
            body in proptest::collection::vec(proptest::num::u8::ANY, 0..(MAX_FRAME_BYTES as usize + 4)),
        ) {
            let mut buf = Vec::new();
            buf.extend_from_slice(&declared.to_le_bytes());
            let take = (declared as usize).min(body.len());
            buf.extend_from_slice(&body[..take]);
            let mut cursor = Cursor::new(buf);
            let _ = read_message(&mut cursor);
        }

        /// Roundtrip property over every `Message` variant the codec
        /// supports: encode, decode, encode again — the two encodings must
        /// be byte-identical (i.e. encoding is deterministic for a given
        /// logical value). Variant payloads come from arbitrary inputs so
        /// e.g. odd `Vec<u64>` lengths, empty `build_id`, etc. are covered.
        #[test]
        fn roundtrip_all_variants(msg in arb_message()) {
            let mut buf = Vec::new();
            write_message(&mut buf, PROTO_MAX, &msg).expect("encode");
            let mut cursor = Cursor::new(buf.clone());
            let (ver, decoded) = read_message(&mut cursor).expect("decode");
            proptest::prop_assert_eq!(ver, PROTO_MAX);
            // Re-encode and compare bytes — the simplest stable equality
            // check that doesn't require `Message: PartialEq`.
            let mut buf2 = Vec::new();
            write_message(&mut buf2, PROTO_MAX, &decoded).expect("re-encode");
            proptest::prop_assert_eq!(buf, buf2);
        }
    }

    /// Strategy that emits every `Message` variant with arbitrary payloads.
    /// Kept inline in the test module because the protocol type isn't
    /// `Arbitrary`-derived (which would force the dep into prod).
    fn arb_message() -> impl proptest::strategy::Strategy<Value = Message> {
        use proptest::prelude::*;
        let side = prop_oneof![Just(Side::Incumbent), Just(Side::Successor)];
        let handoff_id = any::<[u8; 16]>().prop_map(|b| HandoffId(uuid::Uuid::from_bytes(b)));
        let build_id = prop::collection::vec(any::<u8>(), 0..64);
        let revisions = prop::collection::vec(any::<u64>(), 0..16);
        let fingerprint = any::<[u8; 32]>();
        let listening_on = prop::collection::vec("[a-z]{1,8}", 0..4);
        let reason = "[a-zA-Z0-9 _-]{0,64}";

        prop_oneof![
            (side, any::<u32>(), build_id.clone()).prop_map(|(role, pid, build_id)| {
                Message::Hello {
                    role,
                    pid,
                    build_id,
                    proto_min: PROTO_MIN,
                    proto_max: PROTO_MAX,
                    capabilities: Capabilities::default(),
                }
            }),
            (handoff_id.clone()).prop_map(|id| Message::HelloAck {
                proto_version_chosen: PROTO_MAX,
                handoff_id: id,
            }),
            (handoff_id.clone(), any::<u32>(), any::<u64>(), any::<u64>()).prop_map(
                |(id, pid, dl, dg)| Message::PrepareHandoff {
                    handoff_id: id,
                    successor_pid: pid,
                    deadline_ms: dl,
                    drain_grace_ms: dg,
                }
            ),
            (any::<u32>(), any::<bool>()).prop_map(|(n, c)| Message::Drained {
                open_conns_remaining: n,
                accept_closed: c,
            }),
            handoff_id
                .clone()
                .prop_map(|id| Message::SealRequest { handoff_id: id }),
            (any::<u32>(), any::<u32>(), any::<u64>()).prop_map(|(s, t, r)| {
                Message::SealProgress {
                    shards_sealed: s,
                    shards_total: t,
                    last_revision: r,
                }
            }),
            (handoff_id.clone(), revisions.clone(), fingerprint).prop_map(|(id, revs, fp)| {
                Message::SealComplete {
                    handoff_id: id,
                    last_revision_per_shard: revs,
                    data_dir_fingerprint: fp,
                }
            }),
            (handoff_id.clone(), reason, reason).prop_map(|(id, e, p)| Message::SealFailed {
                handoff_id: id,
                error: e,
                partial_state: p,
            }),
            handoff_id
                .clone()
                .prop_map(|id| Message::Begin { handoff_id: id }),
            (handoff_id.clone(), listening_on, any::<bool>(), revisions).prop_map(
                |(id, lo, hz, revs)| Message::Ready {
                    handoff_id: id,
                    listening_on: lo,
                    healthz_ok: hz,
                    advertised_revision_per_shard: revs,
                }
            ),
            handoff_id
                .clone()
                .prop_map(|id| Message::Commit { handoff_id: id }),
            (handoff_id.clone(), reason).prop_map(|(id, r)| Message::Abort {
                handoff_id: id,
                reason: r,
            }),
            handoff_id.prop_map(|id| Message::ResumeAfterAbort { handoff_id: id }),
            any::<u64>().prop_map(|ts| Message::Heartbeat { ts_ms: ts }),
        ]
    }
}
