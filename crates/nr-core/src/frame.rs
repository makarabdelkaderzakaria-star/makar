//! Frame construction helpers.
//!
//! Two audiences:
//!
//! * **Tests and benchmarks** — build synthetic IPv4/IPv6 TCP/UDP frames with
//!   correct header fields so the parser is exercised for real.
//! * **The simulator transport** — a length-prefixed batch wire format that
//!   mimics one `WinDivertRecvEx` call, because in a real batch the packets are
//!   packed back-to-back with *no* per-packet length in `WINDIVERT_ADDRESS`.
//!   We derive each boundary from the IP `TotalLength`, which is exactly what
//!   the production reader does (see `docs/ARCHITECTURE.md`, "batch framing").

use crate::packet::{PacketView, TcpFlags};

/// Build an IPv4 TCP frame including a 0x1234 payload pattern.
#[must_use]
pub fn tcp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    tcp_v4_flags(src, sport, dst, dport, payload, TcpFlags::ACK)
}

/// Build an IPv4 TCP frame with explicit flags.
#[must_use]
pub fn tcp_v4_flags(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    payload: &[u8],
    flags: u8,
) -> Vec<u8> {
    build_v4(src, dst, 6, sport, dport, payload, flags)
}

/// Build an IPv4 UDP frame.
#[must_use]
pub fn udp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    build_v4(src, dst, 17, sport, dport, payload, 0)
}

/// Build an IPv6 TCP frame.
#[must_use]
pub fn tcp_v6(src: [u8; 16], sport: u16, dst: [u8; 16], dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + 20 + payload.len());
    out.push(0x60);
    // Traffic class + flow label: three more bytes. Getting this off by one
    // shifts PayloadLength and every field after it.
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    out.push(6); // next header
    out.push(64); // hop limit
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    let l4 = out.len();
    push_tcp(&mut out, sport, dport, payload, TcpFlags::ACK);
    debug_assert_eq!(out.len(), l4 + 20 + payload.len());
    out
}

fn build_v4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    payload: &[u8],
    tcp_flags: u8,
) -> Vec<u8> {
    let l4_len = if proto == 6 { 20 } else { 8 } + payload.len();
    let total = 20 + l4_len;
    let mut out = Vec::with_capacity(total);
    out.push(0x45); // version 4, IHL 5
    out.push(0); // DSCP/ECN
    out.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    out.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    out.push(64); // TTL
    out.push(proto);
    out.extend_from_slice(&[0, 0]); // checksum (unused by the parser)
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    if proto == 6 {
        push_tcp(&mut out, sport, dport, payload, tcp_flags);
    } else {
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&[0, 0]); // checksum
        out.extend_from_slice(payload);
    }
    out
}

fn push_tcp(out: &mut Vec<u8>, sport: u16, dport: u16, payload: &[u8], flags: u8) {
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes()); // seq
    out.extend_from_slice(&1u32.to_be_bytes()); // ack
    out.push(5 << 4); // data offset 20 bytes, no options
    out.push(flags);
    out.extend_from_slice(&64240u16.to_be_bytes()); // window
    out.extend_from_slice(&[0, 0]); // checksum
    out.extend_from_slice(&[0, 0]); // urgent
    out.extend_from_slice(payload);
}

/// A batch of frames exactly as one `WinDivertRecvEx` call would hand them to
/// us: concatenated, with boundaries derived from each IP header.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    /// Concatenated IP datagrams.
    pub data: Vec<u8>,
    /// Number of datagrams present.
    pub count: usize,
}

impl Batch {
    /// Empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one frame.
    pub fn push(&mut self, frame: &[u8]) {
        self.data.extend_from_slice(frame);
        self.count += 1;
    }

    /// Split the concatenated buffer on IP `TotalLength` boundaries.
    ///
    /// This is the *only* correct way to iterate a WinDivert batch without
    /// calling `WinDivertHelperParsePacket` for every packet, and it is what
    /// `nr-divert::batch::iter_frames` does in production.
    pub fn iter_frames(&self) -> impl Iterator<Item = &[u8]> {
        let mut pos = 0usize;
        let buf = self.data.as_slice();
        core::iter::from_fn(move || {
            if pos >= buf.len() {
                return None;
            }
            let len = frame_len(&buf[pos..]).unwrap_or(buf.len() - pos);
            let end = (pos + len).min(buf.len());
            let frame = &buf[pos..end];
            pos = end;
            Some(frame)
        })
    }

    /// Clear for reuse without freeing (the fast path in the reader thread).
    pub fn clear(&mut self) {
        self.data.clear();
        self.count = 0;
    }
}

/// Declared on-wire length of the datagram starting at `buf[0]`.
///
/// * IPv4: `TotalLength` from the header.
/// * IPv6: 40 + `PayloadLength`.
///
/// Returns `None` if the header is truncated or the version is unknown; the
/// caller then treats the remainder of the buffer as one frame (fail-closed:
/// a single oversized frame is better than silently dropping bytes).
#[must_use]
pub fn frame_len(buf: &[u8]) -> Option<usize> {
    match buf.first()? >> 4 {
        4 => {
            if buf.len() < 4 {
                return None;
            }
            Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
        6 => {
            if buf.len() < 6 {
                return None;
            }
            Some(40 + u16::from_be_bytes([buf[4], buf[5]]) as usize)
        }
        _ => None,
    }
}

/// Iterate frames in a concatenated batch buffer.
pub fn iter_frames(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        if pos >= buf.len() {
            return None;
        }
        let len = frame_len(&buf[pos..]).unwrap_or(buf.len() - pos).max(1);
        let end = (pos + len).min(buf.len());
        let frame = &buf[pos..end];
        pos = end;
        Some(frame)
    })
}

/// Parse every frame in a batch, skipping malformed ones, and return the views.
///
/// Used by the simulator and tests; the production hot path parses lazily.
pub fn parses(buf: &[u8]) -> impl Iterator<Item = PacketView<'_>> {
    iter_frames(buf).filter_map(|f| PacketView::parse(f).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Protocol;

    #[test]
    fn parses_ipv4_tcp_header_fields() {
        let f = tcp_v4([10, 0, 0, 1], 51515, [93, 184, 216, 34], 443, &[0xAB; 100]);
        let v = PacketView::parse(&f).unwrap();
        assert_eq!(v.ip_version, 4);
        assert_eq!(v.protocol, Protocol::Tcp);
        assert_eq!(v.src_port, 51515);
        assert_eq!(v.dst_port, 443);
        assert_eq!(v.payload_len, 100);
        assert_eq!(v.wire_len as usize, f.len());
        assert_eq!(&v.src[..4], &[10, 0, 0, 1]);
        assert!(v.flags.has(TcpFlags::ACK));
        assert!(v.is_delayable());
    }

    #[test]
    fn syn_is_not_delayable() {
        let f = tcp_v4_flags([10, 0, 0, 1], 1234, [1, 1, 1, 1], 80, &[], TcpFlags::SYN);
        assert!(!PacketView::parse(&f).unwrap().is_delayable());
    }

    #[test]
    fn parses_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let f = tcp_v6(src, 5555, src, 443, &[7; 40]);
        let v = PacketView::parse(&f).unwrap();
        assert_eq!(v.ip_version, 6);
        assert_eq!(v.payload_len, 40);
        assert_eq!(v.wire_len as usize, f.len());
    }

    #[test]
    fn batch_boundaries_follow_total_length() {
        let mut b = Batch::new();
        b.push(&tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, &[0; 10]));
        b.push(&udp_v4([10, 0, 0, 1], 3, [1, 1, 1, 1], 53, &[0; 200]));
        b.push(&tcp_v6([0; 16], 4, [0; 16], 5, &[0; 5]));
        let lens: Vec<usize> = b.iter_frames().map(<[u8]>::len).collect();
        assert_eq!(lens, vec![20 + 20 + 10, 20 + 8 + 200, 40 + 20 + 5]);
        assert_eq!(b.iter_frames().count(), 3);
    }

    #[test]
    fn truncated_packet_is_rejected() {
        let f = tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, &[0; 10]);
        assert!(PacketView::parse(&f[..10]).is_err());
    }
}
