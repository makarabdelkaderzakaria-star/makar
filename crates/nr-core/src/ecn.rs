//! ECN marking: tell the peer to slow down instead of dropping the packet.
//!
//! When a limit is exceeded and the packet belongs to an ECN-capable transport
//! (both ends negotiated ECT in the IP header), the right answer is neither
//! "delay it" nor "throw it away": set the CE codepoint and forward it. The
//! receiver echoes that back to the sender, and TCP halves its window — the
//! congestion signal arrives without a retransmission, so the bandwidth is not
//! spent twice.
//!
//! This module only rewrites headers. It is deliberately a pure function over a
//! mutable frame, for three reasons:
//!
//! 1. The engine's hot path is immutable and returns a *decision*; the I/O
//!    layer owns the bytes and is the only place a writeback can happen.
//! 2. Rewriting IPv4 means fixing the header checksum, and that arithmetic is
//!    worth testing on its own, on every platform, without a network.
//! 3. A frame we do not fully understand must be left exactly as it was. Refusing
//!    to mark is always safe; corrupting a checksum is not.
//!
//! Two things a caller has to get right, and this module cannot enforce:
//!
//! * Only mark packets whose transport negotiated ECN. `Not-ECT` (both bits
//!   zero) means the receiver will not echo anything, so marking it would just
//!   corrupt an unrelated field's meaning: [`mark_ce`] refuses, and the caller
//!   falls back to its normal over-limit policy.
//! * Do not mark twice. A packet that already carries CE is already signalling;
//!   [`mark_ce`] reports that instead of recomputing a checksum for nothing.

/// ECN codepoints, as they appear in the two low bits of the IPv4 TOS byte or
/// the IPv6 traffic class.
pub mod codepoint {
    /// Not ECN-capable: the transport never negotiated it.
    pub const NOT_ECT: u8 = 0b00;
    /// ECT(1): ECN-capable, from a transport using the 1 codepoint.
    pub const ECT1: u8 = 0b01;
    /// ECT(0): ECN-capable, the codepoint almost everything uses.
    pub const ECT0: u8 = 0b10;
    /// Congestion experienced: what a queue sets to tell the sender to slow.
    pub const CE: u8 = 0b11;
}

/// What [`mark_ce`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// The packet was ECT(0) or ECT(1) and now carries CE.
    Marked,
    /// It already carried CE; nothing was changed.
    AlreadyCe,
    /// It is not ECN-capable, or it is not a header this module can rewrite.
    NotEcnCapable,
}

impl Mark {
    /// Did this call change the frame?
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Marked)
    }
}

/// ECN codepoint of a frame, `None` if the header is not one we parse.
///
/// Handles IPv4 (any header length, options included) and IPv6. Anything else —
/// ARP, a truncated frame, an unknown version — is `None`, and every caller
/// treats `None` as "do not touch".
#[must_use]
pub fn ecn_codepoint(frame: &[u8]) -> Option<u8> {
    match frame.first().map(|b| b >> 4) {
        Some(4) => {
            let header = ipv4_header_len(frame)?;
            if frame.len() < header {
                return None;
            }
            Some(frame[1] & 0b11)
        }
        Some(6) => {
            if frame.len() < 40 {
                return None;
            }
            // Traffic class spans bits 4..12; the ECN bits are its low two, which
            // is exactly the top two bits of the second byte.
            Some((frame[1] >> 4) & 0b11)
        }
        _ => None,
    }
}

/// Is this packet allowed to receive a CE mark?
///
/// Only ECT(0) and ECT(1) qualify: marking a `Not-ECT` packet would tell a
/// sender that never asked for ECN that the network is congested, and nothing
/// would deliver that message.
#[must_use]
pub fn is_ecn_capable(frame: &[u8]) -> bool {
    matches!(
        ecn_codepoint(frame),
        Some(codepoint::ECT0 | codepoint::ECT1)
    )
}

/// Set the CE codepoint on an ECN-capable frame, fixing what that breaks.
///
/// For IPv4 the header checksum is updated incrementally (RFC 1624): only one
/// 16-bit word changed, so a full recalculation is unnecessary and would have to
/// be careful about options. For IPv6 the traffic class lives outside any
/// checksum, so only the bits move.
pub fn mark_ce(frame: &mut [u8]) -> Mark {
    match ecn_codepoint(frame) {
        Some(codepoint::CE) => Mark::AlreadyCe,
        Some(codepoint::ECT0 | codepoint::ECT1) => {
            if frame[0] >> 4 == 4 {
                mark_ipv4_ce(frame);
            } else {
                // IPv6: the traffic class spans bytes 0 and 1, and its low two
                // bits (the codepoint) are the top two bits of byte 1.
                frame[1] |= 0b1100_0000;
            }
            Mark::Marked
        }
        _ => Mark::NotEcnCapable,
    }
}

/// Header length of an IPv4 frame in bytes, if it declares a sane one.
fn ipv4_header_len(frame: &[u8]) -> Option<usize> {
    let ihl = usize::from(frame[0] & 0x0F) * 4;
    // The fixed header is 20 bytes; a shorter one is malformed and a longer one
    // must still fit in the frame.
    if ihl < 20 || frame.len() < ihl {
        return None;
    }
    Some(ihl)
}

/// Set CE on IPv4 and patch the header checksum.
fn mark_ipv4_ce(frame: &mut [u8]) {
    let old_tos = frame[1];
    let new_tos = old_tos | 0b11;
    frame[1] = new_tos;

    // RFC 1624, equation 3: HC' = ~(~HC + ~m + m'), where m and m' are the
    // 16-bit words that changed. The first word is `version/ihl` in the high
    // byte and TOS in the low one, so only the low byte differs.
    let m = (u16::from(frame[0]) << 8) | u16::from(old_tos);
    let m_prime = (u16::from(frame[0]) << 8) | u16::from(new_tos);
    let hc = (u16::from(frame[10]) << 8) | u16::from(frame[11]);
    let fixed = !((!hc)
        .wrapping_add(!m)
        .wrapping_add(m_prime));
    frame[10] = (fixed >> 8) as u8;
    frame[11] = fixed as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 header with a *valid* checksum, `ihl` in 32-bit words.
    fn ipv4(ecn: u8, ihl_words: u8) -> Vec<u8> {
        let header = usize::from(ihl_words) * 4;
        let mut f = vec![0u8; header];
        f[0] = 0x40 | (ihl_words & 0x0F);
        f[1] = 0x00 | ecn;
        f[8] = 64; // TTL
        f[9] = 6; // TCP
        f[12..16].copy_from_slice(&[10, 0, 0, 1]);
        f[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let sum = checksum(&f);
        f[10] = (sum >> 8) as u8;
        f[11] = sum as u8;
        f
    }

    /// One's-complement sum of the header, as the receiver computes it.
    fn checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            i += 2;
        }
        if i < header.len() {
            sum += u32::from(header[i]) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A receiver validates a header by summing it to 0xFFFF.
    fn validates(frame: &[u8]) -> bool {
        let ihl = usize::from(frame[0] & 0x0F) * 4;
        let mut sum = 0u32;
        for i in (0..ihl).step_by(2) {
            sum += u32::from(u16::from_be_bytes([frame[i], frame[i + 1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16 == 0xFFFF
    }

    fn ipv6(ecn: u8) -> Vec<u8> {
        // Traffic class = DSCP (0x14) << 2 | codepoint, so the DSCP part can be
        // checked for survival after marking.
        let tc: u8 = 0x50 | ecn;
        let mut f = vec![0u8; 40];
        f[0] = 0x60 | (tc >> 4);
        f[1] = (tc & 0x0F) << 4; // flow label stays zero
        f
    }

    #[test]
    fn reads_the_codepoint_of_both_versions() {
        for ecn in 0..4u8 {
            assert_eq!(ecn_codepoint(&ipv4(ecn, 5)), Some(ecn));
            assert_eq!(ecn_codepoint(&ipv6(ecn)), Some(ecn));
        }
    }

    #[test]
    fn marks_ect0_and_keeps_the_ipv4_checksum_valid() {
        let mut f = ipv4(codepoint::ECT0, 5);
        assert!(validates(&f), "the fixture must start valid");
        assert_eq!(mark_ce(&mut f), Mark::Marked);
        assert_eq!(f[1] & 0b11, codepoint::CE);
        assert!(
            validates(&f),
            "the header checksum must still pass after marking"
        );
    }

    #[test]
    fn marks_ect1_and_an_ipv4_header_with_options() {
        let mut f = ipv4(codepoint::ECT1, 8); // 12 bytes of options
        assert!(validates(&f));
        assert_eq!(mark_ce(&mut f), Mark::Marked);
        assert_eq!(f[1] & 0b11, codepoint::CE);
        assert!(
            validates(&f),
            "options must not disturb the incremental fix"
        );
    }

    #[test]
    fn a_not_ect_packet_is_left_exactly_as_it_was() {
        let mut f = ipv4(codepoint::NOT_ECT, 5);
        let before = f.clone();
        assert_eq!(mark_ce(&mut f), Mark::NotEcnCapable);
        assert_eq!(f, before, "not one byte may change");
        assert!(!is_ecn_capable(&f));
    }

    #[test]
    fn an_already_marked_packet_is_not_recomputed() {
        let mut f = ipv4(codepoint::CE, 5);
        let before = f.clone();
        assert_eq!(mark_ce(&mut f), Mark::AlreadyCe);
        assert_eq!(f, before);
        assert!(!Mark::AlreadyCe.changed());
    }

    #[test]
    fn marks_ipv6_where_there_is_no_checksum_to_fix() {
        let mut f = ipv6(codepoint::ECT0);
        assert!(is_ecn_capable(&f));
        assert_eq!(mark_ce(&mut f), Mark::Marked);
        assert_eq!(ecn_codepoint(&f), Some(codepoint::CE));
        // The DSCP part of the traffic class must survive.
        assert_eq!(f[0] & 0x0F, 0x05, "the high nibble of the class is DSCP");
        assert_eq!((f[1] >> 4) & 0b1100, 0b0100, "the DSCP low bits are intact");
    }

    #[test]
    fn refuses_frames_it_cannot_rewrite() {
        let mut empty: [u8; 0] = [];
        assert_eq!(mark_ce(&mut empty), Mark::NotEcnCapable);
        assert_eq!(mark_ce(&mut [0x45; 10]), Mark::NotEcnCapable, "truncated");
        let mut arp = [0u8; 28];
        assert_eq!(mark_ce(&mut arp), Mark::NotEcnCapable);
        // IPv4 that claims a header shorter than the fixed 20 bytes.
        let mut bad_ihl = ipv4(codepoint::ECT0, 5);
        bad_ihl[0] = 0x43;
        assert_eq!(mark_ce(&mut bad_ihl), Mark::NotEcnCapable);
        assert_eq!(ecn_codepoint(&bad_ihl), None);
        // Version 4 but the buffer is shorter than the header it declares.
        let mut short = ipv4(codepoint::ECT0, 5);
        short.truncate(18);
        assert_eq!(ecn_codepoint(&short), None);
        assert_eq!(mark_ce(&mut short), Mark::NotEcnCapable);
    }

    #[test]
    fn only_ect_packets_are_capable() {
        assert!(!is_ecn_capable(&ipv4(codepoint::NOT_ECT, 5)));
        assert!(is_ecn_capable(&ipv4(codepoint::ECT0, 5)));
        assert!(is_ecn_capable(&ipv4(codepoint::ECT1, 5)));
        // CE is a packet already signalling congestion: not a candidate for a
        // fresh mark, and `mark_ce` says so rather than recomputing anything.
        assert!(!is_ecn_capable(&ipv4(codepoint::CE, 5)));
    }
}
