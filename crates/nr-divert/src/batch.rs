//! Frame boundaries inside a WinDivert batch.
//!
//! ## The subtle part of the API
//!
//! In a batched `WinDivertRecvEx` call the driver writes
//! `pAddrLen / sizeof(WINDIVERT_ADDRESS)` addresses and the packets themselves
//! back-to-back into one buffer. `WINDIVERT_ADDRESS` contains **no packet
//! length** (see the struct in `windivert.h`: timestamp, layer, event, flags,
//! and a 64-byte union of network/flow/socket data — nothing about size). The
//! only two ways to find the end of a packet are:
//!
//! 1. read the IP header's length field (IPv4 `TotalLength`, IPv6
//!    `PayloadLength + 40`), or
//! 2. call `WinDivertHelperParsePacket(..., ppNext, pNextLen)` for each packet,
//!    which is a function call per packet and therefore the slow option.
//!
//! We do (1). It is two loads and a byte-swap: no call, no allocation, and it
//! works for the truncated frames WinDivert hands us (`WINDIVERT_MTU_MAX` is
//! `40 + 0xFFFF`, so the buffer must be sized for that, not for 1500).

use nr_core::frame::frame_len;

/// Iterate `(frame, index)` pairs over a concatenated batch buffer.
///
/// `count` is the number of addresses the driver reported. Iteration stops at
/// `count` frames *or* at the end of the buffer, whichever comes first — if the
/// two disagree, the buffer wins, because a wrong frame boundary would corrupt
/// every subsequent packet.
pub fn iter_frames(buf: &[u8], count: usize) -> impl Iterator<Item = (usize, &[u8])> {
    let mut pos = 0usize;
    let mut idx = 0usize;
    core::iter::from_fn(move || {
        if pos >= buf.len() || idx >= count {
            return None;
        }
        let len = frame_len(&buf[pos..]).unwrap_or(buf.len() - pos).max(1);
        let end = (pos + len).min(buf.len());
        let frame = &buf[pos..end];
        pos = end;
        idx += 1;
        Some((idx - 1, frame))
    })
}

/// A reusable receive buffer sized for the worst case WinDivert can hand us.
///
/// `WINDIVERT_MTU_MAX` is `40 + 0xFFFF`; times 255 batched packets that is
/// ~16 MiB, which is why the buffer is allocated **once** and reused. The
/// original allocated a fresh buffer (twice: once for recv, once for the send
/// copy) for every single packet.
#[derive(Debug)]
pub struct BatchReader {
    buf: Vec<u8>,
    /// Maximum number of packets we ask the driver for.
    batch_max: usize,
}

/// Worst-case single frame the driver can produce (`40 + 0xFFFF`).
pub const MTU_MAX: usize = 40 + 0xFFFF;

impl BatchReader {
    /// Allocate one buffer for `batch_max` frames.
    #[must_use]
    pub fn new(batch_max: usize) -> Self {
        let batch_max = batch_max.clamp(1, 255);
        Self {
            buf: vec![0u8; MTU_MAX * batch_max],
            batch_max,
        }
    }

    /// Usable buffer.
    #[must_use]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Batches we will ask for.
    #[must_use]
    pub const fn batch_max(&self) -> usize {
        self.batch_max
    }

    /// Interpret `len` received bytes as `count` frames.
    pub fn frames(&self, len: usize, count: usize) -> impl Iterator<Item = (usize, &[u8])> {
        iter_frames(&self.buf[..len.min(self.buf.len())], count)
    }

    /// Interpret `len` received bytes as a single frame (sync path).
    #[must_use]
    pub fn single(&self, len: usize) -> &[u8] {
        &self.buf[..len.min(self.buf.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nr_core::frame::{tcp_v4, udp_v4};

    #[test]
    fn splits_on_ip_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, &[0; 10]));
        buf.extend_from_slice(&udp_v4([10, 0, 0, 1], 3, [1, 1, 1, 1], 53, &[0; 200]));
        let frames: Vec<usize> = iter_frames(&buf, 2).map(|(_, f)| f.len()).collect();
        assert_eq!(frames, vec![50, 228]);
        assert_eq!(iter_frames(&buf, 2).count(), 2);
    }

    #[test]
    fn stops_at_count_even_if_more_bytes_are_present() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, &[0; 10]));
        buf.extend_from_slice(&tcp_v4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, &[0; 10]));
        assert_eq!(iter_frames(&buf, 1).count(), 1);
    }

    #[test]
    fn buffer_is_sized_for_the_worst_case() {
        let mut r = BatchReader::new(64);
        assert_eq!(r.buffer_mut().len(), MTU_MAX * 64);
        assert_eq!(r.batch_max(), 64);
    }
}
