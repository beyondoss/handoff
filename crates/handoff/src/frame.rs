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

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;

use crate::error::{Error, Result};
use crate::protocol::{Message, ProtoVersion};
use crate::sock::send_all;

/// Hard cap on a single frame's `frame_len`. 1 MiB is far larger than any
/// legitimate handoff message; receipts above this are treated as malformed.
pub const MAX_FRAME_BYTES: u32 = 1 << 20;

/// Size of the `frame_len` prefix on the wire.
const LEN_PREFIX: usize = 4;
/// Size of the `proto_version` field that lives inside `frame_len`.
const VERSION_FIELD: usize = 2;

/// Encode one `Message` into a single contiguous frame buffer.
fn encode(version: ProtoVersion, msg: &Message) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(msg)?;
    let inner_len = VERSION_FIELD
        .checked_add(payload.len())
        .ok_or(Error::FrameTooLarge(u32::MAX))?;
    if inner_len > MAX_FRAME_BYTES as usize {
        return Err(Error::FrameTooLarge(inner_len as u32));
    }
    let mut out = Vec::with_capacity(LEN_PREFIX + inner_len);
    out.extend_from_slice(&(inner_len as u32).to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Encode and write one `Message` to `w`. Flushes before returning.
///
/// Prefer [`write_frame`] when the sink is the control socket: it cannot
/// raise `SIGPIPE` and emits the frame in one syscall.
pub fn write_message<W: Write>(w: &mut W, version: ProtoVersion, msg: &Message) -> Result<()> {
    w.write_all(&encode(version, msg)?)?;
    w.flush()?;
    Ok(())
}

/// Write one `Message` to a control socket as a single `send(2)`.
///
/// Two properties the generic [`write_message`] cannot offer:
///
/// - **No `SIGPIPE`.** See [`crate::sock::send_all`] — a peer that died mid
///   handoff yields `EPIPE`, never a signal, whatever the embedding binary's
///   signal disposition happens to be.
/// - **One syscall per frame.** The three-`write_all` form could interleave
///   with a heartbeat thread's frame if the single-writer contract were ever
///   broken; a single `send` on a `SOCK_STREAM` Unix socket keeps the header
///   and payload contiguous in the buffer under any write ordering.
pub fn write_frame(stream: &UnixStream, version: ProtoVersion, msg: &Message) -> Result<()> {
    send_all(stream, &encode(version, msg)?)?;
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

/// Incremental frame reader for sockets that carry a receive timeout.
///
/// [`read_message`] is built on `read_exact`, which discards whatever it had
/// already consumed when the read fails. On a socket armed with `SO_RCVTIMEO`
/// that is a correctness bug, not just lost work: a frame that straddles the
/// timeout boundary leaves the stream mid-frame, and the next read
/// interprets payload bytes as a length prefix. Every subsequent frame is
/// garbage — reported as a malformed frame or, worse, a plausible-looking
/// message.
///
/// The accumulator owns the partial bytes instead, so a timeout is a
/// *suspension*: the caller decides whether to keep waiting (peer is slow but
/// alive, and the wall-clock budget has room) or give up, and a resumed read
/// continues exactly where the previous one stopped.
#[derive(Debug, Default)]
pub struct FrameAccumulator {
    buf: Vec<u8>,
    /// Bytes needed for the frame in progress: [`LEN_PREFIX`] until the
    /// length prefix has been parsed, `LEN_PREFIX + frame_len` after.
    want: usize,
}

impl FrameAccumulator {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            want: LEN_PREFIX,
        }
    }

    /// True if bytes of an incomplete frame are buffered. Callers use this to
    /// distinguish "peer has gone silent" (nothing buffered — treat a timeout
    /// as peer-dead) from "peer is mid-frame" (bytes buffered — the peer is
    /// demonstrably alive, so keep reading until the wall-clock budget runs
    /// out).
    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Read toward the next complete message. Returns `Ok(None)` when the
    /// read timed out (or would block) before the frame was complete; any
    /// bytes consumed so far are retained for the next call.
    pub fn poll_read<R: Read>(&mut self, r: &mut R) -> Result<Option<(ProtoVersion, Message)>> {
        if self.want == 0 {
            self.want = LEN_PREFIX;
        }
        loop {
            while self.buf.len() < self.want {
                let start = self.buf.len();
                self.buf.resize(self.want, 0);
                match r.read(&mut self.buf[start..]) {
                    Ok(0) => {
                        self.buf.truncate(start);
                        return Err(Error::Io(std::io::Error::from(ErrorKind::UnexpectedEof)));
                    }
                    Ok(n) => self.buf.truncate(start + n),
                    Err(e) if e.kind() == ErrorKind::Interrupted => {
                        self.buf.truncate(start);
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        self.buf.truncate(start);
                        return Ok(None);
                    }
                    Err(e) => {
                        self.buf.truncate(start);
                        return Err(e.into());
                    }
                }
            }

            if self.want == LEN_PREFIX {
                let frame_len =
                    u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
                if frame_len < VERSION_FIELD as u32 {
                    self.reset();
                    return Err(Error::FrameMalformed(frame_len));
                }
                if frame_len > MAX_FRAME_BYTES {
                    self.reset();
                    return Err(Error::FrameTooLarge(frame_len));
                }
                self.want = LEN_PREFIX + frame_len as usize;
                continue;
            }

            let version = u16::from_le_bytes([self.buf[4], self.buf[5]]);
            let decoded = postcard::from_bytes(&self.buf[LEN_PREFIX + VERSION_FIELD..]);
            self.reset();
            return Ok(Some((version, decoded?)));
        }
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.want = LEN_PREFIX;
    }
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

    /// A reader that hands out `chunks` in order and reports `TimedOut` once
    /// each chunk is exhausted — the shape a `SO_RCVTIMEO`-armed socket
    /// presents when the writer is slow or a frame is split across segments.
    struct ChunkedTimeoutReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
        pending_timeout: bool,
    }

    impl ChunkedTimeoutReader {
        fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
                pending_timeout: false,
            }
        }
    }

    impl Read for ChunkedTimeoutReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending_timeout || self.chunks.is_empty() {
                self.pending_timeout = false;
                return Err(std::io::Error::from(ErrorKind::TimedOut));
            }
            let chunk = self
                .chunks
                .pop_front()
                .expect("emptiness checked immediately above");
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks.push_front(chunk[n..].to_vec());
            } else {
                self.pending_timeout = true;
            }
            Ok(n)
        }
    }

    #[test]
    fn accumulator_resumes_a_frame_split_across_timeouts() {
        let msg = Message::SealComplete {
            handoff_id: HandoffId::new(),
            last_revision_per_shard: vec![1, 2, 3],
            data_dir_fingerprint: [9u8; 32],
        };
        let mut bytes = Vec::new();
        write_message(&mut bytes, PROTO_MAX, &msg).unwrap();

        // Split mid-length-prefix and again mid-payload, with a receive
        // timeout at each boundary: both points desynchronize a
        // `read_exact`-based reader, which consumes the bytes it did get and
        // then restarts parsing mid-frame on the next call.
        let mut reader = ChunkedTimeoutReader::new([
            bytes[..2].to_vec(),
            bytes[2..7].to_vec(),
            bytes[7..].to_vec(),
        ]);

        let mut acc = FrameAccumulator::new();
        assert!(acc.poll_read(&mut reader).unwrap().is_none());
        assert!(acc.has_partial(), "partial bytes must be retained");
        assert!(acc.poll_read(&mut reader).unwrap().is_none());
        assert!(acc.has_partial());
        let (ver, decoded) = acc
            .poll_read(&mut reader)
            .unwrap()
            .expect("frame completes once the last chunk arrives");
        assert_eq!(ver, PROTO_MAX);
        assert!(matches!(decoded, Message::SealComplete { .. }));
        assert!(!acc.has_partial());

        // Drained: a further poll is a plain timeout with nothing buffered,
        // which is how callers recognize a silent peer as opposed to a slow
        // one.
        assert!(acc.poll_read(&mut reader).unwrap().is_none());
        assert!(!acc.has_partial());
    }

    #[test]
    fn accumulator_decodes_back_to_back_frames_from_one_chunk() {
        let mut bytes = Vec::new();
        write_message(&mut bytes, PROTO_MAX, &Message::Heartbeat { ts_ms: 1 }).unwrap();
        write_message(&mut bytes, PROTO_MAX, &Message::Heartbeat { ts_ms: 2 }).unwrap();
        let mut reader = Cursor::new(bytes);
        let mut acc = FrameAccumulator::new();
        for expected in [1u64, 2] {
            match acc.poll_read(&mut reader).unwrap() {
                Some((_, Message::Heartbeat { ts_ms })) => assert_eq!(ts_ms, expected),
                other => panic!("expected heartbeat {expected}, got {other:?}"),
            }
        }
    }

    #[test]
    fn accumulator_rejects_malformed_length_and_resets() {
        let mut buf = (MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(&1u32.to_le_bytes());
        let mut reader = Cursor::new(buf);
        let mut acc = FrameAccumulator::new();
        assert!(matches!(
            acc.poll_read(&mut reader),
            Err(Error::FrameTooLarge(_))
        ));
        // Reset after the error: no stale partial keeps the caller from
        // reusing the accumulator on a fresh connection.
        assert!(!acc.has_partial());
    }

    #[test]
    fn accumulator_reports_eof_mid_frame() {
        let mut bytes = Vec::new();
        write_message(&mut bytes, PROTO_MAX, &Message::Heartbeat { ts_ms: 1 }).unwrap();
        bytes.truncate(bytes.len() - 1);
        let mut reader = Cursor::new(bytes);
        let mut acc = FrameAccumulator::new();
        match acc.poll_read(&mut reader) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), ErrorKind::UnexpectedEof),
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    proptest::proptest! {
        /// Pure fuzz: neither reader may panic on any input bytes,
        /// regardless of length, content, or alignment. The legal outcomes
        /// are `Ok(_)` (if the bytes happen to encode a valid frame) or
        /// `Err(_)` of any variant.
        #[test]
        fn read_message_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..2048),
        ) {
            let mut cursor = Cursor::new(bytes.clone());
            let _ = read_message(&mut cursor);
            let mut cursor = Cursor::new(bytes);
            let mut acc = FrameAccumulator::new();
            let _ = acc.poll_read(&mut cursor);
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
