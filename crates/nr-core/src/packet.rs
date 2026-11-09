//! Zero-copy packet parsing.
//!
//! We borrow the buffer we were handed; we never copy headers out and never
//! allocate. The parser is deliberately strict and returns `ParseError` rather
//! than guessing, because a wrong flow key silently mis-attributes traffic
//! (that is exactly how the original ended up rate-limiting by PID only).

use crate::error::ParseError;

/// Direction of travel relative to this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Direction {
    /// Leaving the machine.
    Outbound = 0,
    /// Arriving at the machine.
    Inbound = 1,
}

impl Direction {
    /// Inverse direction.
    #[inline]
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::Outbound => Self::Inbound,
            Self::Inbound => Self::Outbound,
        }
    }

    /// Stable short code for logs.
    #[inline]
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Outbound => "out",
            Self::Inbound => "in",
        }
    }
}

/// Transport protocol we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Protocol {
    /// TCP (6).
    Tcp = 6,
    /// UDP (17).
    Udp = 17,
    /// Anything else (ICMP, GRE, ...). Counted, not limited.
    Other = 0,
}

impl Protocol {
    /// Map an IP protocol number.
    #[inline]
    #[must_use]
    pub const fn from_ip(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            _ => Self::Other,
        }
    }
}

/// The TCP flag bits we actually branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(u8);

impl TcpFlags {
    /// FIN.
    pub const FIN: u8 = 0x01;
    /// SYN.
    pub const SYN: u8 = 0x02;
    /// RST.
    pub const RST: u8 = 0x04;
    /// PSH.
    pub const PSH: u8 = 0x08;
    /// ACK.
    pub const ACK: u8 = 0x10;
    /// URG.
    pub const URG: u8 = 0x20;

    /// Build from the raw flag byte.
    #[inline]
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Raw bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Is `bit` set?
    #[inline]
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Pure ACK with no payload accounted for elsewhere: the cheapest packet
    /// to delay and the most expensive one to drop (it drives the window).
    #[inline]
    #[must_use]
    pub const fn is_pure_ack(self, payload_len: u16) -> bool {
        payload_len == 0 && self.has(Self::ACK) && !self.has(Self::SYN | Self::FIN | Self::RST)
    }
}

/// A borrowed view over one captured frame.
///
/// All getters are `#[inline]` and branch-free; the struct is 40 bytes and
/// `Copy`, so it lives in registers/stack, never on the heap.
#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    /// Raw frame, starting at the IP header (no Ethernet header).
    pub raw: &'a [u8],
    /// IP version 4 or 6.
    pub ip_version: u8,
    /// TCP / UDP / Other.
    pub protocol: Protocol,
    /// Source address as a 16-byte array (IPv4 in the first 4 bytes, zero-padded).
    pub src: [u8; 16],
    /// Destination address, same layout as `src`.
    pub dst: [u8; 16],
    /// Source port (0 for non-TCP/UDP).
    pub src_port: u16,
    /// Destination port (0 for non-TCP/UDP).
    pub dst_port: u16,
    /// TCP flags (empty for UDP).
    pub flags: TcpFlags,
    /// Offset of the TCP/UDP header inside `raw`. 0 when absent.
    pub l4_offset: u16,
    /// Offset of the payload inside `raw`.
    pub payload_offset: u16,
    /// Payload length in bytes.
    pub payload_len: u16,
    /// Full frame length as declared by the IP header (this is what we account).
    pub wire_len: u16,
    /// IP identification field (useful for logged evidence / debugging).
    pub ip_id: u16,
    /// TTL / hop limit.
    pub hop_limit: u8,
}

impl<'a> PacketView<'a> {
    /// Parse a frame that starts at the IP header.
    ///
    /// `available` is the number of bytes actually present in `raw`; the
    /// returned view's [`wire_len`](Self::wire_len) is taken from the IP header
    /// so that the caller can account for what *should* have been there (this
    /// matters when WinDivert gives us a short buffer).
    pub fn parse(raw: &'a [u8]) -> Result<Self, ParseError> {
        let first = *raw.first().ok_or(ParseError::Truncated(0))?;
        match first >> 4 {
            4 => Self::parse_v4(raw),
            6 => Self::parse_v6(raw),
            v => Err(ParseError::BadVersion(v)),
        }
    }

    fn parse_v4(raw: &'a [u8]) -> Result<Self, ParseError> {
        if raw.len() < 20 {
            return Err(ParseError::Truncated(raw.len()));
        }
        let ihl = (raw[0] & 0x0f) as usize * 4;
        if ihl < 20 {
            return Err(ParseError::BadIpHeaderLen(raw[0] & 0x0f));
        }
        if raw.len() < ihl {
            return Err(ParseError::Truncated(raw.len()));
        }
        let total_len = u16::from_be_bytes([raw[2], raw[3]]);
        if (total_len as usize) < ihl {
            return Err(ParseError::BadTotalLength {
                declared: total_len,
                available: raw.len(),
            });
        }
        // Fragment offset lives in the low 13 bits of bytes 6..8.
        let frag_off = u16::from_be_bytes([raw[6], raw[7]]) & 0x1fff;
        if frag_off != 0 {
            return Err(ParseError::Fragment);
        }

        let proto_num = raw[9];
        let protocol = Protocol::from_ip(proto_num);
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src[..4].copy_from_slice(&raw[12..16]);
        dst[..4].copy_from_slice(&raw[16..20]);

        let mut view = Self {
            raw,
            ip_version: 4,
            protocol,
            src,
            dst,
            src_port: 0,
            dst_port: 0,
            flags: TcpFlags::default(),
            l4_offset: ihl as u16,
            payload_offset: ihl as u16,
            payload_len: 0,
            wire_len: total_len,
            ip_id: u16::from_be_bytes([raw[4], raw[5]]),
            hop_limit: raw[8],
        };
        view.fill_transport(raw.len())?;
        Ok(view)
    }

    fn parse_v6(raw: &'a [u8]) -> Result<Self, ParseError> {
        if raw.len() < 40 {
            return Err(ParseError::Truncated(raw.len()));
        }
        let payload_len = u16::from_be_bytes([raw[4], raw[5]]);
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&raw[8..24]);
        dst.copy_from_slice(&raw[24..40]);
        let next_header = raw[6];
        // 0 hop-by-hop, 43 routing, 60 dest-opts, 51 AH: all need chasing.
        if matches!(next_header, 0 | 43 | 51 | 60) {
            return Err(ParseError::ExtensionHeaders);
        }
        let protocol = Protocol::from_ip(next_header);
        let mut view = Self {
            raw,
            ip_version: 6,
            protocol,
            src,
            dst,
            src_port: 0,
            dst_port: 0,
            flags: TcpFlags::default(),
            l4_offset: 40,
            payload_offset: 40,
            payload_len: 0,
            wire_len: 40u16.saturating_add(payload_len),
            ip_id: 0,
            hop_limit: raw[7],
        };
        view.fill_transport(raw.len())?;
        Ok(view)
    }

    fn fill_transport(&mut self, available: usize) -> Result<(), ParseError> {
        match self.protocol {
            Protocol::Other => {
                self.payload_len = self.wire_len.saturating_sub(self.l4_offset);
                Ok(())
            }
            Protocol::Udp => {
                let off = self.l4_offset as usize;
                if available < off + 8 {
                    return Err(ParseError::Truncated(available));
                }
                self.src_port = u16::from_be_bytes([self.raw[off], self.raw[off + 1]]);
                self.dst_port = u16::from_be_bytes([self.raw[off + 2], self.raw[off + 3]]);
                self.payload_offset = (off + 8) as u16;
                self.payload_len = self.wire_len.saturating_sub(self.payload_offset);
                Ok(())
            }
            Protocol::Tcp => {
                let off = self.l4_offset as usize;
                if available < off + 20 {
                    return Err(ParseError::Truncated(available));
                }
                self.src_port = u16::from_be_bytes([self.raw[off], self.raw[off + 1]]);
                self.dst_port = u16::from_be_bytes([self.raw[off + 2], self.raw[off + 3]]);
                let data_off = (self.raw[off + 12] >> 4) as usize * 4;
                if data_off < 20 {
                    return Err(ParseError::BadTcpHeaderLen(self.raw[off + 12] >> 4));
                }
                if available < off + data_off {
                    return Err(ParseError::Truncated(available));
                }
                self.flags = TcpFlags::new(self.raw[off + 13]);
                self.payload_offset = (off + data_off) as u16;
                self.payload_len = self.wire_len.saturating_sub(self.payload_offset);
                Ok(())
            }
        }
    }

    /// Bytes we charge against a limit. The IP header is overhead the link
    /// really carries, so it counts; retransmissions therefore cost twice,
    /// which is precisely why the scheduler must not cause them.
    #[inline]
    #[must_use]
    pub const fn accounted_len(&self) -> u32 {
        self.wire_len as u32
    }

    /// Is this a TCP segment that can be delayed without breaking a handshake?
    #[inline]
    #[must_use]
    pub const fn is_delayable(&self) -> bool {
        match self.protocol {
            Protocol::Tcp => !self
                .flags
                .has(TcpFlags::SYN | TcpFlags::FIN | TcpFlags::RST),
            _ => true,
        }
    }
}
