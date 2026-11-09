//! Pure, cross-platform WinDivert ABI types.
//!
//! Everything in this module is plain data and pure functions: the
//! `WINDIVERT_LAYER`/`WINDIVERT_PARAM`/`WINDIVERT_FLAG_*` constants, the
//! 80-byte [`Address`] struct with its compile-time size and offset assertions,
//! the `WINDIVERT_DATA_FLOW` offsets, and the deferred-reinjection wire format
//! ([`pack`]).
//!
//! # Why this lives outside `win`
//!
//! It used to live inside [`crate::win`], which is `cfg(windows)`, so none of it
//! was compiled — let alone tested — on the Linux machine it was written on.
//! The ABI map was therefore a claim nobody checked, and it shipped one real
//! defect: [`pack::InjectContext::unpack`] sign-extended the priority field from
//! the wrong bit, so a retained packet re-injected with `i16::MAX` priority came
//! back as `-1`. Both the fix and its regression test now run in CI on every
//! push, on Linux and Windows.
//!
//! Nothing here links against the driver: no `extern` block, no `unsafe`. The
//! `win` module keeps every call that touches the OS.

// ---------------------------------------------------------------------------
// Layer / param / flag constants (windivert.h)
// ---------------------------------------------------------------------------

/// `WINDIVERT_LAYER`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Network layer: packets, both directions.
    Network = 0,
    /// Network layer, forwarded packets only.
    NetworkForward = 1,
    /// Flow layer: establishment/deletion events with a PID.
    Flow = 2,
    /// Socket layer: bind/connect/listen/accept/close with a PID.
    Socket = 3,
    /// Reflect layer: handle open/close events.
    Reflect = 4,
}

/// `WINDIVERT_PARAM`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    /// Queue length in packets (32..=16384).
    QueueLength = 0,
    /// Queue time in milliseconds (100..=16000).
    QueueTime = 1,
    /// Queue size in bytes (65535..=33554432).
    QueueSize = 2,
}

/// `WINDIVERT_FLAG_*`.
pub mod flags {
    /// Receive a copy instead of diverting.
    pub const SNIFF: u64 = 0x0001;
    /// Drop matching packets by default.
    pub const DROP: u64 = 0x0002;
    /// Receive only: the handle may not inject.
    pub const RECV_ONLY: u64 = 0x0004;
    /// Send only: the handle may not receive.
    pub const SEND_ONLY: u64 = 0x0008;
    /// Fail instead of installing the driver.
    pub const NO_INSTALL: u64 = 0x0010;
    /// Divert IP fragments too (2.2+).
    pub const FRAGMENTS: u64 = 0x0020;
}

/// `WINDIVERT_SHUTDOWN`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Stop receiving.
    Recv = 1,
    /// Stop sending.
    Send = 2,
    /// Both.
    Both = 3,
}

/// `WINDIVERT_BATCH_MAX`.
pub const BATCH_MAX: usize = 0xFF;
/// `WINDIVERT_MTU_MAX` = `40 + 0xFFFF`: the largest frame the driver reports.
pub const MTU_MAX: usize = 40 + 0xFFFF;

// ---------------------------------------------------------------------------
// Pure, cross-platform types. Nothing here touches the OS.
// ---------------------------------------------------------------------------

pub mod types {
    use nr_core::Direction;

    /// `WINDIVERT_ADDRESS`: 80 bytes, `#[repr(C)]`.
    ///
    /// From the header:
    ///
    /// ```c
    /// typedef struct {
    ///     INT64  Timestamp;
    ///     UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1,
    ///            Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1,
    ///            UDPChecksum:1, Reserved1:8;
    ///     UINT32 Reserved2;
    ///     union { WINDIVERT_DATA_NETWORK Network; WINDIVERT_DATA_FLOW Flow;
    ///             WINDIVERT_DATA_SOCKET Socket; WINDIVERT_DATA_REFLECT Reflect;
    ///             UINT8 Reserved3[64]; };
    /// } WINDIVERT_ADDRESS;
    /// ```
    ///
    /// Nine bitfields pack into one `u32` in declaration order (LSB first on
    /// Windows/MSVC, which is what `_WIN32` on x86-64 means), so:
    ///
    /// | field | bits |
    /// |---|---|
    /// | `Layer` | 0–7 |
    /// | `Event` | 8–15 |
    /// | `Sniffed` | 16 |
    /// | `Outbound` | 17 |
    /// | `Loopback` | 18 |
    /// | `Impostor` | 19 |
    /// | `IPv6` | 20 |
    /// | `IPChecksum` | 21 |
    /// | `TCPChecksum` | 22 |
    /// | `UDPChecksum` | 23 |
    /// | `Reserved1` | 24–31 |
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Address {
        /// Driver timestamp.
        pub timestamp: i64,
        /// The packed bitfield word described above.
        pub bits: u32,
        /// `Reserved2`.
        pub reserved2: u32,
        /// The 64-byte union (`Network`/`Flow`/`Socket`/`Reflect`).
        pub data: [u8; 64],
    }

    impl Default for Address {
        fn default() -> Self {
            Self {
                timestamp: 0,
                bits: 0,
                reserved2: 0,
                data: [0; 64],
            }
        }
    }

    // Compile-time ABI assertions. If a future compiler or platform changes
    // either of these, the build fails instead of corrupting packets.
    const _: () = {
        assert!(core::mem::size_of::<Address>() == 80);
        assert!(core::mem::offset_of!(Address, data) == 16);
        assert!(core::mem::offset_of!(Address, bits) == 8);
    };

    /// Bit positions in [`Address::bits`].
    pub mod bit {
        /// `Sniffed`.
        pub const SNIFFED: u32 = 1 << 16;
        /// `Outbound`.
        pub const OUTBOUND: u32 = 1 << 17;
        /// `Loopback`.
        pub const LOOPBACK: u32 = 1 << 18;
        /// `IPv6`.
        pub const IPV6: u32 = 1 << 20;
        /// `IPChecksum` (driver says the IPv4 checksum is valid).
        pub const IP_CHECKSUM: u32 = 1 << 21;
        /// `TCPChecksum`.
        pub const TCP_CHECKSUM: u32 = 1 << 22;
        /// `UDPChecksum`.
        pub const UDP_CHECKSUM: u32 = 1 << 23;
        /// All three checksum-valid flags, cleared before a modified packet is
        /// injected so the driver does not trust a stale checksum.
        pub const ALL_CHECKSUMS: u32 = IP_CHECKSUM | TCP_CHECKSUM | UDP_CHECKSUM;
    }

    /// `WINDIVERT_EVENT_*`.
    pub mod event {
        /// A network packet.
        pub const NETWORK_PACKET: u8 = 0;
        /// FLOW_ESTABLISHED.
        pub const FLOW_ESTABLISHED: u8 = 1;
        /// FLOW_DELETED.
        pub const FLOW_DELETED: u8 = 2;
        /// SOCKET_BIND.
        pub const SOCKET_BIND: u8 = 3;
        /// SOCKET_CONNECT.
        pub const SOCKET_CONNECT: u8 = 4;
        /// SOCKET_LISTEN.
        pub const SOCKET_LISTEN: u8 = 5;
        /// SOCKET_ACCEPT.
        pub const SOCKET_ACCEPT: u8 = 6;
        /// SOCKET_CLOSE.
        pub const SOCKET_CLOSE: u8 = 7;
    }

    impl Address {
        /// `Layer` (bits 0–7).
        #[must_use]
        pub const fn layer(&self) -> u8 {
            (self.bits & 0xFF) as u8
        }

        /// `Event` (bits 8–15).
        #[must_use]
        pub const fn event(&self) -> u8 {
            ((self.bits >> 8) & 0xFF) as u8
        }

        /// Was this a sniffed copy rather than a diverted packet?
        #[must_use]
        pub const fn sniffed(&self) -> bool {
            self.bits & bit::SNIFFED != 0
        }

        /// Direction bit.
        #[must_use]
        pub const fn is_outbound(&self) -> bool {
            self.bits & bit::OUTBOUND != 0
        }

        /// Direction as a core enum.
        #[must_use]
        pub const fn direction(&self) -> Direction {
            if self.is_outbound() {
                Direction::Outbound
            } else {
                Direction::Inbound
            }
        }

        /// Is this an IPv6 packet?
        #[must_use]
        pub const fn is_ipv6(&self) -> bool {
            self.bits & bit::IPV6 != 0
        }

        /// `WINDIVERT_DATA_FLOW.ProcessId` — offset 16 in the union (after two
        /// `UINT64` endpoint ids).
        #[must_use]
        pub fn flow_process_id(&self) -> u32 {
            u32::from_le_bytes([self.data[16], self.data[17], self.data[18], self.data[19]])
        }

        /// `WINDIVERT_DATA_FLOW.EndpointId` — offset 0.
        #[must_use]
        pub fn flow_endpoint_id(&self) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.data[0..8]);
            u64::from_le_bytes(b)
        }

        /// Build an address for injecting a packet in `direction`.
        ///
        /// Used by the `SEND_ONLY` handle: no address from a previous receive is
        /// needed, which is why deferred re-injection cannot mix up packets.
        #[must_use]
        pub const fn for_injection(direction: Direction, layer: u8) -> Self {
            let outbound = match direction {
                Direction::Outbound => bit::OUTBOUND,
                Direction::Inbound => 0,
            };
            Self {
                timestamp: 0,
                bits: layer as u32 | outbound,
                reserved2: 0,
                data: [0; 64],
            }
        }

        /// Clear the checksum-valid flags (call before injecting a modified
        /// packet).
        pub fn invalidate_checksums(&mut self) {
            self.bits &= !bit::ALL_CHECKSUMS;
        }
    }
}

pub use types::Address;

// ---------------------------------------------------------------------------
// pack / unpack: the deferred re-injection wire format (cross-platform)
// ---------------------------------------------------------------------------

/// Wire format for a packet that is held and later re-injected.
///
/// Because the interceptor uses a separate `SEND_ONLY` handle, the only things a
/// retained packet must remember are its **direction** and **priority**. Those
/// fit in one `u16`, which is the whole token the engine retains per packet,
/// instead of an 80-byte `WINDIVERT_ADDRESS` plus the risk of reusing a stale
/// one.
///
/// One of the sixteen bits is the direction, so the packed priority field is
/// **15-bit signed**, not the full `i16` range: see [`PRIORITY_MIN`] and
/// [`PRIORITY_MAX`]. A `WINDIVERT_ADDRESS` carries no priority field of its
/// own in WinDivert 2.x (it was removed after 1.x), so there is nowhere else to
/// put it; the values that do not fit are clamped rather than wrapped, because
/// wrapping would silently turn "highest priority" into "lowest".
///
/// [`PRIORITY_MIN`]: InjectContext::PRIORITY_MIN
/// [`PRIORITY_MAX`]: InjectContext::PRIORITY_MAX
pub mod pack {
    use nr_core::Direction;

    /// Packed injection context.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InjectContext {
        /// Direction the packet travels.
        pub direction: Direction,
        /// Handle priority, always within
        /// [`PRIORITY_MIN`](Self::PRIORITY_MIN)..=[`PRIORITY_MAX`](Self::PRIORITY_MAX).
        pub priority: i16,
    }

    impl Default for InjectContext {
        fn default() -> Self {
            Self {
                direction: Direction::Inbound,
                priority: 0,
            }
        }
    }

    impl InjectContext {
        /// Lowest priority the packed form can represent (`-2^14`).
        pub const PRIORITY_MIN: i16 = -16_384;
        /// Highest priority the packed form can represent (`2^14 - 1`).
        pub const PRIORITY_MAX: i16 = 16_383;

        /// Build a context.
        ///
        /// `priority` is clamped into the representable range, so a caller that
        /// passes `i16::MAX` gets [`PRIORITY_MAX`](Self::PRIORITY_MAX) — the
        /// highest priority — and never a wrapped-around negative one.
        #[must_use]
        pub const fn new(direction: Direction, priority: i16) -> Self {
            Self {
                direction,
                priority: Self::clamp(priority),
            }
        }

        /// Clamp into the packed priority range.
        #[must_use]
        pub const fn clamp(priority: i16) -> i16 {
            if priority > Self::PRIORITY_MAX {
                Self::PRIORITY_MAX
            } else if priority < Self::PRIORITY_MIN {
                Self::PRIORITY_MIN
            } else {
                priority
            }
        }

        /// Pack into the 16 bits a token slab entry needs.
        #[must_use]
        pub const fn pack(self) -> u16 {
            let dir = match self.direction {
                Direction::Outbound => 1u16,
                Direction::Inbound => 0,
            };
            // `priority` is clamped by `new`; masking keeps the packing exact
            // even for a value built through struct literal syntax.
            (dir << 15) | (Self::clamp(self.priority) as u16 & 0x7FFF)
        }

        /// Unpack.
        #[must_use]
        pub const fn unpack(bits: u16) -> Self {
            let direction = if bits & 0x8000 != 0 {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            // Sign-extend the 15-bit priority field: shift the sign bit into
            // bit 15, then shift it back arithmetically. Doing it this way
            // avoids the classic `| !0x3FFF` mistake of extending from the
            // wrong bit (which turns any positive priority whose bit 14 is set
            // into a negative one).
            let raw = (bits & 0x7FFF) as i16;
            let priority = (raw << 1) >> 1;
            Self {
                direction,
                priority,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_direction_and_priority() {
            for (dir, prio) in [
                (Direction::Outbound, 0i16),
                (Direction::Inbound, 0),
                (Direction::Outbound, 10),
                (Direction::Inbound, -10),
                (Direction::Outbound, InjectContext::PRIORITY_MAX),
                (Direction::Inbound, InjectContext::PRIORITY_MIN),
                (Direction::Outbound, 1),
                (Direction::Inbound, -1),
            ] {
                let ctx = InjectContext::new(dir, prio);
                let back = InjectContext::unpack(ctx.pack());
                assert_eq!(back.direction, dir, "direction lost (prio {prio})");
                assert_eq!(back.priority, prio, "priority lost (dir {dir:?})");
            }
        }

        /// The bug this test exists for: the old `unpack` sign-extended from bit
        /// 16 instead of bit 15, so `i16::MAX` came back as `-1` and `i16::MIN`
        /// came back as `0`. Both would have re-injected a retained packet with
        /// the wrong scheduling priority, silently.
        #[test]
        fn out_of_range_priority_clamps_instead_of_wrapping() {
            let hi_ctx = InjectContext::new(Direction::Outbound, i16::MAX);
            let high = InjectContext::unpack(hi_ctx.pack());
            assert_eq!(high.priority, InjectContext::PRIORITY_MAX);
            assert_eq!(high.direction, Direction::Outbound);

            let lo_ctx = InjectContext::new(Direction::Inbound, i16::MIN);
            let low = InjectContext::unpack(lo_ctx.pack());
            assert_eq!(low.priority, InjectContext::PRIORITY_MIN);
            assert_eq!(low.direction, Direction::Inbound);

            // The struct is `pub`, so `pack` must be exact even for a value that
            // skipped the clamping constructor.
            let sneaky = InjectContext {
                direction: Direction::Outbound,
                priority: i16::MAX,
            };
            assert_eq!(
                InjectContext::unpack(sneaky.pack()).priority,
                InjectContext::PRIORITY_MAX
            );
        }

        /// Direction and priority must not alias: every bit of the packed word
        /// below bit 15 belongs to the priority.
        #[test]
        fn direction_bit_is_independent_of_priority() {
            for prio in [
                InjectContext::PRIORITY_MIN,
                -1,
                0,
                1,
                InjectContext::PRIORITY_MAX,
            ] {
                let inbound = InjectContext::new(Direction::Inbound, prio).pack();
                let outbound = InjectContext::new(Direction::Outbound, prio).pack();
                assert_eq!(inbound & 0x8000, 0, "inbound must not set bit 15");
                assert_eq!(outbound & 0x8000, 0x8000, "outbound must set bit 15");
                assert_eq!(
                    inbound & 0x7FFF,
                    outbound & 0x7FFF,
                    "priority bits differ between directions (prio {prio})"
                );
            }
        }
    }
}
