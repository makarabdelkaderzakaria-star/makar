//! Start-up endpoint snapshot: the fix for the attribution blind spot.
//!
//! A WinDivert FLOW handle only reports flows created **after** it is opened
//! (`docs/RESEARCH.md` §1). Traffic that existed when NetRocket started is
//! therefore invisible unless we ask the operating system what is already
//! connected.
//!
//! On Windows that is `GetExtendedTcpTable` / `GetExtendedUdpTable`, which
//! return the same endpoint table `netstat -ano` shows. This module is split
//! exactly like [`crate::win`] so that the *decoding* is testable on Linux:
//!
//! * [`parse`] — turns raw table bytes into [`nr_core::SnapshotEntry`] values.
//!   Pure, no `unsafe`, compiled and unit-tested on **every** platform.
//! * [`win::read_tcp`] / [`win::read_udp`] — the two FFI calls that produce
//!   those bytes. `cfg(windows)` only.
//!
//! # What the layout actually is
//!
//! For `AF_INET` (`TCP_TABLE_OWNER_PID_ALL` = 5, `UDP_TABLE_OWNER_PID` = 1) the
//! returned buffer is:
//!
//! ```c
//! DWORD dwNumEntries;
//! MIB_TCPROW_OWNER_PID table[dwNumEntries];   // 4-byte aligned after the DWORD
//! ```
//!
//! with, for TCP:
//!
//! ```c
//! DWORD dwState;        // 0..12, MIB_TCP_STATE_*
//! DWORD dwLocalAddr;    // network byte order, 4 bytes
//! DWORD dwLocalPort;    // network byte order in the low 16 bits
//! DWORD dwRemoteAddr;
//! DWORD dwRemotePort;
//! DWORD dwOwningPid;
//! ```
//!
//! and for UDP the same without `dwState`, plus `dwLocalPort`/`dwRemotePort`
//! present but zero for an unconnected socket.
//!
//! Two classic footguns, both handled here and both unit-tested:
//!
//! 1. `dwLocalPort` is a `DWORD` holding a **big-endian 16-bit** port in its low
//!    half. Reading it as a native `u16` byte-swaps it, so port 443 becomes
//!    47873. This is the single most common bug in code that reads these tables.
//! 2. `*_EX` variants add `ScopeId`/`InterfaceLuid` fields for IPv6, so the row
//!    sizes differ between `AF_INET` and `AF_INET6`. Row size is a parameter,
//!    never a constant.

use nr_core::attribution::SnapshotEntry;
use nr_core::flow::Endpoint;
use nr_core::ProcKey;

/// `MIB_TCP_STATE_LISTEN`.
pub const TCP_STATE_LISTEN: u32 = 2;

/// Which address family a buffer contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `AF_INET`, 4-byte addresses.
    V4,
    /// `AF_INET6`, 16-byte addresses.
    V6,
}

impl Family {
    /// Address bytes per field.
    #[must_use]
    pub const fn addr_len(self) -> usize {
        match self {
            Self::V4 => 4,
            Self::V6 => 16,
        }
    }
}

/// Layout parameters for one table flavour. Never hard-code these: the IPv6
/// `_EX` rows carry two extra 4-byte fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// IPv4 or IPv6.
    pub family: Family,
    /// Bytes per row.
    pub row_size: usize,
    /// Byte offset of the local address inside a row.
    pub local_addr: usize,
    /// Byte offset of the local port (`DWORD`, big-endian in the low half).
    pub local_port: usize,
    /// Byte offset of the remote address, or `None` for UDP.
    pub remote_addr: Option<usize>,
    /// Byte offset of the remote port, or `None` for UDP.
    pub remote_port: Option<usize>,
    /// Byte offset of the owning PID.
    pub pid: usize,
    /// Byte offset of the state (`None` for UDP).
    pub state: Option<usize>,
    /// Protocol number to report (6 TCP, 17 UDP).
    pub protocol: u8,
}

impl Layout {
    /// `MIB_TCPROW_OWNER_PID`, IPv4: 6 DWORDs, 24 bytes.
    pub const TCP_V4: Self = Self {
        family: Family::V4,
        row_size: 24,
        local_addr: 4,
        local_port: 8,
        remote_addr: Some(12),
        remote_port: Some(16),
        pid: 20,
        state: Some(0),
        protocol: 6,
    };

    /// `MIB_TCP6ROW_OWNER_PID`, IPv6: 16 + 4 + 16 + 4 + 4 + 4 + 4 bytes = 56.
    pub const TCP_V6: Self = Self {
        family: Family::V6,
        row_size: 56,
        local_addr: 0,
        local_port: 16,
        remote_addr: Some(20),
        remote_port: Some(36),
        pid: 52,
        state: Some(48),
        protocol: 6,
    };

    /// `MIB_UDPROW_OWNER_PID`, IPv4: 4 DWORDs, 16 bytes.
    pub const UDP_V4: Self = Self {
        family: Family::V4,
        row_size: 16,
        local_addr: 0,
        local_port: 4,
        remote_addr: None,
        remote_port: None,
        pid: 12,
        state: None,
        protocol: 17,
    };

    /// `MIB_UDP6ROW_OWNER_PID`, IPv6: 16 + 4 + 4 + 4 = 28 bytes.
    pub const UDP_V6: Self = Self {
        family: Family::V6,
        row_size: 28,
        local_addr: 0,
        local_port: 16,
        remote_addr: None,
        remote_port: None,
        pid: 20,
        state: None,
        protocol: 17,
    };
}

/// Read a `DWORD` from `buf[at..at+4]`.
#[inline]
fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let slice = buf.get(at..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read an address field of `family.addr_len()` bytes, zero-extended to 16.
#[inline]
fn addr_at(buf: &[u8], at: usize, family: Family) -> Option<[u8; 16]> {
    let len = family.addr_len();
    let slice = buf.get(at..at.checked_add(len)?)?;
    let mut out = [0u8; 16];
    out[..len].copy_from_slice(slice);
    Some(out)
}

/// Decode a Windows port field: **big-endian 16-bit value inside a `DWORD`**.
///
/// `dwLocalPort` is documented as network byte order in the low half. Taking
/// `raw as u16` on a little-endian machine byte-swaps it; taking the low half
/// and reading *it* as big-endian (as here) is correct on any host.
#[inline]
#[must_use]
pub fn decode_port(raw: u32) -> u16 {
    let low = (raw & 0xFFFF) as u16;
    u16::from_be(low)
}

/// Decode one table buffer into snapshot entries.
///
/// `start_time_for` supplies the process creation time, which the endpoint
/// tables do not carry; it is what makes a recycled PID a different identity.
/// `want_listeners` controls whether listening TCP endpoints are returned (they
/// become PID-only hints in the attribution table).
pub fn parse<F>(
    buf: &[u8],
    layout: Layout,
    mut start_time_for: F,
    want_listeners: bool,
) -> Vec<SnapshotEntry>
where
    F: FnMut(u32) -> u64,
{
    let mut out = Vec::new();
    let Some(count) = u32_at(buf, 0) else {
        return out;
    };
    // The row array starts right after the DWORD. The structure is naturally
    // 8-byte aligned in practice; `GetExtendedTcpTable` returns a buffer that
    // is already aligned for the row type, so offset 4 is correct here (and is
    // asserted by the tests against real-shaped buffers).
    let base = 4usize;
    for i in 0..count as usize {
        let start = match base.checked_add(i.saturating_mul(layout.row_size)) {
            Some(s) => s,
            None => break,
        };
        let end = match start.checked_add(layout.row_size) {
            Some(e) => e,
            None => break,
        };
        let Some(row) = buf.get(start..end) else {
            break; // truncated buffer: stop rather than read garbage
        };
        let Some(pid) = u32_at(row, layout.pid) else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Some(local_addr) = addr_at(row, layout.local_addr, layout.family) else {
            continue;
        };
        let Some(local_port_raw) = u32_at(row, layout.local_port) else {
            continue;
        };
        let local = Endpoint {
            addr: local_addr,
            port: decode_port(local_port_raw),
        };

        let (remote, state) = match (layout.remote_addr, layout.remote_port) {
            (Some(ra), Some(rp)) => {
                let Some(raddr) = addr_at(row, ra, layout.family) else {
                    continue;
                };
                let Some(rport_raw) = u32_at(row, rp) else {
                    continue;
                };
                (
                    Endpoint {
                        addr: raddr,
                        port: decode_port(rport_raw),
                    },
                    layout.state.and_then(|s| u32_at(row, s)),
                )
            }
            // UDP rows carry no remote: an unconnected socket has no peer.
            _ => (Endpoint::unspecified(), None),
        };

        let key = ProcKey::new(pid, start_time_for(pid));

        if layout.remote_addr.is_none() {
            // UDP: the table has no peer address, so the only honest use of the
            // row is a PID hint. Filtering these out (as the TCP listener rule
            // below does) would throw away every UDP endpoint we see.
            out.push(SnapshotEntry::listening(key, layout.protocol, local));
        } else if remote.port == 0 {
            if !want_listeners {
                continue;
            }
            out.push(SnapshotEntry::listening(key, layout.protocol, local));
        } else if state == Some(TCP_STATE_LISTEN) {
            // A TCP row in LISTEN with a non-zero remote should not exist; if it
            // does, treat it as a listener rather than inventing a flow.
            out.push(SnapshotEntry::listening(key, layout.protocol, local));
        } else {
            out.push(SnapshotEntry::connected(
                key,
                layout.protocol,
                local,
                remote,
            ));
        }
    }
    out
}

/// Build the `MIB_*` bytes for tests. Kept here (not in `#[cfg(test)]`) so the
/// Windows-only code can be exercised by an integration test too.
pub mod builder {
    use super::{encode_port_for_test, Family, Layout};

    /// Encode one row of a table.
    ///
    /// Addresses are given as 16 bytes so IPv6 rows are realistic; the low 4
    /// bytes are used for `AF_INET` rows.
    #[must_use]
    pub fn row(
        layout: Layout,
        local: ([u8; 16], u16),
        remote: Option<([u8; 16], u16)>,
        pid: u32,
    ) -> Vec<u8> {
        let mut r = vec![0u8; layout.row_size];
        if let Some(state) = layout.state {
            r[state..state + 4].copy_from_slice(&super::TCP_STATE_LISTEN_ESTABLISHED.to_le_bytes());
        }
        write_addr(&mut r, layout.local_addr, layout.family, local.0);
        r[layout.local_port..layout.local_port + 4]
            .copy_from_slice(&encode_port_for_test(local.1).to_le_bytes());
        if let (Some(ra), Some(rp), Some((raddr, rport))) =
            (layout.remote_addr, layout.remote_port, remote)
        {
            write_addr(&mut r, ra, layout.family, raddr);
            r[rp..rp + 4].copy_from_slice(&encode_port_for_test(rport).to_le_bytes());
        }
        r[layout.pid..layout.pid + 4].copy_from_slice(&pid.to_le_bytes());
        r
    }

    fn write_addr(buf: &mut [u8], at: usize, family: Family, addr: [u8; 16]) {
        match family {
            Family::V4 => buf[at..at + 4].copy_from_slice(&addr[..4]),
            Family::V6 => buf[at..at + 16].copy_from_slice(&addr),
        }
    }

    /// Wrap rows in the `dwNumEntries` header the API returns.
    #[must_use]
    pub fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        for r in rows {
            out.extend_from_slice(r);
        }
        out
    }
}

/// `MIB_TCP_STATE_ESTAB` — the state value used when building test rows.
pub const TCP_STATE_LISTEN_ESTABLISHED: u32 = 5;

/// Encode a host-order port into the `DWORD` form Windows uses.
///
/// Exposed so tests can build buffers that are byte-identical to what the API
/// produces; the inverse of [`decode_port`].
#[must_use]
pub fn encode_port_for_test(port: u16) -> u32 {
    u32::from(port.to_be())
}

// ---------------------------------------------------------------------------
// Windows: the two FFI calls that produce those buffers
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub mod win {
    use super::{parse, Layout};
    use nr_core::attribution::SnapshotEntry;
    use std::ffi::c_void;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    /// `TCP_TABLE_OWNER_PID_ALL`.
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    /// `UDP_TABLE_OWNER_PID`.
    const UDP_TABLE_OWNER_PID: u32 = 1;
    /// `ERROR_INSUFFICIENT_BUFFER`.
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const NO_ERROR: u32 = 0;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }

    /// Outcome of a snapshot attempt.
    #[derive(Debug, Default)]
    pub struct Snapshot {
        /// Entries discovered.
        pub entries: Vec<SnapshotEntry>,
        /// Tables that could not be read, with a reason.
        pub errors: Vec<String>,
    }

    fn read_table<F>(mut call: F) -> Result<Vec<u8>, u32>
    where
        F: FnMut(*mut c_void, *mut u32) -> u32,
    {
        // Two-phase: ask for the size, then read. A single fixed buffer would be
        // a silent truncation bug on a busy machine.
        let mut size: u32 = 0;
        let first = call(std::ptr::null_mut(), &mut size);
        if first != NO_ERROR && first != ERROR_INSUFFICIENT_BUFFER {
            return Err(first);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        // Pad: the table can grow between the two calls.
        size = size.saturating_add(16 * 1024);
        let mut buf = vec![0u8; size as usize];
        let rc = call(buf.as_mut_ptr().cast(), &mut size);
        if rc != NO_ERROR {
            return Err(rc);
        }
        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Read every TCP and UDP endpoint, IPv4 and IPv6.
    ///
    /// `start_time_for` supplies process creation times so recycled PIDs are
    /// distinct identities.
    pub fn read_all<F>(mut start_time_for: F) -> Snapshot
    where
        F: FnMut(u32) -> u64,
    {
        let mut snap = Snapshot::default();

        // SAFETY: `call` receives a null pointer only in the size-query phase
        // (documented as valid) and otherwise a buffer of the size it reported.
        let tcp4 = read_table(|b, s| unsafe {
            GetExtendedTcpTable(b, s, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        });
        match tcp4 {
            Ok(buf) => snap
                .entries
                .extend(parse(&buf, Layout::TCP_V4, &mut start_time_for, true)),
            Err(code) => snap
                .errors
                .push(format!("GetExtendedTcpTable(AF_INET) failed: {code}")),
        }

        let tcp6 = read_table(|b, s| unsafe {
            GetExtendedTcpTable(b, s, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
        });
        match tcp6 {
            Ok(buf) => snap
                .entries
                .extend(parse(&buf, Layout::TCP_V6, &mut start_time_for, true)),
            Err(code) => snap
                .errors
                .push(format!("GetExtendedTcpTable(AF_INET6) failed: {code}")),
        }

        let udp4 = read_table(|b, s| unsafe {
            GetExtendedUdpTable(b, s, 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
        });
        match udp4 {
            Ok(buf) => snap
                .entries
                .extend(parse(&buf, Layout::UDP_V4, &mut start_time_for, false)),
            Err(code) => snap
                .errors
                .push(format!("GetExtendedUdpTable(AF_INET) failed: {code}")),
        }

        let udp6 = read_table(|b, s| unsafe {
            GetExtendedUdpTable(b, s, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)
        });
        match udp6 {
            Ok(buf) => snap
                .entries
                .extend(parse(&buf, Layout::UDP_V6, &mut start_time_for, false)),
            Err(code) => snap
                .errors
                .push(format!("GetExtendedUdpTable(AF_INET6) failed: {code}")),
        }

        snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_start_time(_pid: u32) -> u64 {
        0
    }

    /// Build a 16-byte address from four IPv4 octets.
    fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&[a, b, c, d]);
        out
    }

    #[test]
    fn port_decoding_is_big_endian_in_the_low_half() {
        // Port 443 encoded the way Windows stores it: 0x0000BB01.
        let raw = encode_port_for_test(443);
        assert_eq!(decode_port(raw), 443);
        // The classic bug: taking the low half as a native u16 gives 47873.
        assert_eq!((raw & 0xFFFF) as u16, 47873);
        assert_eq!(decode_port(encode_port_for_test(80)), 80);
        assert_eq!(decode_port(encode_port_for_test(65535)), 65535);
        assert_eq!(decode_port(0), 0);
    }

    #[test]
    fn parses_tcpv4_rows() {
        let rows = vec![
            builder::row(
                Layout::TCP_V4,
                (v4(10, 0, 0, 1), 51515),
                Some((v4(1, 1, 1, 1), 443)),
                4242,
            ),
            builder::row(
                Layout::TCP_V4,
                (v4(10, 0, 0, 2), 80),
                Some((v4(93, 184, 216, 34), 50000)),
                5150,
            ),
        ];
        let buf = builder::table(&rows);
        let entries = parse(&buf, Layout::TCP_V4, no_start_time, true);
        assert_eq!(entries.len(), 2);

        let first = entries[0];
        assert_eq!(first.key.pid, 4242);
        assert_eq!(first.local.port, 51515);
        assert_eq!(first.remote.port, 443);
        assert_eq!(&first.local.addr[..4], &[10, 0, 0, 1]);
        assert_eq!(&first.remote.addr[..4], &[1, 1, 1, 1]);
        assert_eq!(first.protocol, 6);
        assert!(!first.is_listener());
    }

    #[test]
    fn snapshots_match_packet_path_keys() {
        // The whole point: a packet arriving from 10.0.0.1:51515 to 1.1.1.1:443
        // must resolve to the same canonical key the snapshot inserted.
        let rows = vec![builder::row(
            Layout::TCP_V4,
            (v4(10, 0, 0, 1), 51515),
            Some((v4(1, 1, 1, 1), 443)),
            4242,
        )];
        let buf = builder::table(&rows);
        let entries = parse(&buf, Layout::TCP_V4, no_start_time, true);

        let mut table = nr_core::FlowAttribution::new(64, 60_000);
        let report = table.seed(entries, 0);
        assert_eq!(report.connected, 1);

        let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 51515, [1, 1, 1, 1], 443, &[0; 100]);
        let view = nr_core::PacketView::parse(&frame).unwrap();
        let key = nr_core::FlowKey::from_packet(&view, nr_core::Direction::Outbound, 0);
        let owner = table.get(&key, 10).expect("snapshot must attribute it");
        assert_eq!(owner.pid, 4242);
    }

    #[test]
    fn listeners_become_pid_hints_not_flows() {
        let rows = vec![builder::row(
            Layout::TCP_V4,
            (v4(0, 0, 0, 0), 8080),
            Some((v4(0, 0, 0, 0), 0)),
            777,
        )];
        let buf = builder::table(&rows);
        let entries = parse(&buf, Layout::TCP_V4, no_start_time, true);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_listener());

        let mut table = nr_core::FlowAttribution::new(64, 60_000);
        let report = table.seed(entries, 0);
        assert_eq!(report.listeners, 1);
        assert_eq!(report.connected, 0);
        // The PID hint is what makes an inbound connection attributable.
        assert_eq!(table.by_pid(777, 10).map(|k| k.pid), Some(777));
    }

    #[test]
    fn listeners_can_be_filtered_out() {
        let rows = vec![builder::row(
            Layout::TCP_V4,
            (v4(0, 0, 0, 0), 8080),
            Some((v4(0, 0, 0, 0), 0)),
            777,
        )];
        let buf = builder::table(&rows);
        assert!(parse(&buf, Layout::TCP_V4, no_start_time, false).is_empty());
    }

    #[test]
    fn parses_udpv4_rows() {
        let rows = vec![builder::row(
            Layout::UDP_V4,
            (v4(10, 0, 0, 1), 5353),
            None,
            900,
        )];
        let buf = builder::table(&rows);
        let entries = parse(&buf, Layout::UDP_V4, no_start_time, false);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, 17);
        assert_eq!(entries[0].local.port, 5353);
        // No remote: it is treated as a listener/PID hint, never as a flow.
        assert!(entries[0].is_listener());
    }

    #[test]
    fn parses_tcpv6_rows() {
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[2] = 0x0d;
        src[3] = 0xb8;
        let mut dst = [0u8; 16];
        dst[10] = 0xFF;
        dst[11] = 0xFF;
        dst[12..16].copy_from_slice(&[1, 1, 1, 1]);
        let rows = vec![builder::row(
            Layout::TCP_V6,
            (src, 5000),
            Some((dst, 443)),
            1234,
        )];
        let buf = builder::table(&rows);
        let entries = parse(&buf, Layout::TCP_V6, no_start_time, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local.port, 5000);
        assert_eq!(entries[0].remote.port, 443);
        assert_eq!(entries[0].local.addr[0], 0x20);
        assert_eq!(entries[0].local.addr[1], 0x01);
        // v4-mapped tail must survive the 16-byte read.
        assert_eq!(entries[0].remote.addr[12..16], [1, 1, 1, 1]);
    }

    #[test]
    fn a_truncated_buffer_stops_instead_of_reading_garbage() {
        let one = builder::row(
            Layout::TCP_V4,
            (v4(10, 0, 0, 1), 1000),
            Some((v4(1, 1, 1, 1), 443)),
            1,
        );
        let mut buf = builder::table(&[one.clone(), one.clone()]);
        // Claim two rows but truncate the second one half-way.
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf.truncate(4 + one.len() + one.len() / 2);
        let entries = parse(&buf, Layout::TCP_V4, no_start_time, true);
        assert_eq!(
            entries.len(),
            1,
            "must not invent a row from a short buffer"
        );
    }

    #[test]
    fn an_empty_table_is_not_an_error() {
        let buf = builder::table(&[]);
        assert!(parse(&buf, Layout::TCP_V4, no_start_time, true).is_empty());
        assert!(parse(&[], Layout::TCP_V4, no_start_time, true).is_empty());
    }

    #[test]
    fn pid_zero_rows_are_skipped() {
        let rows = vec![builder::row(
            Layout::TCP_V4,
            (v4(10, 0, 0, 1), 1000),
            Some((v4(1, 1, 1, 1), 443)),
            0,
        )];
        let buf = builder::table(&rows);
        assert!(parse(&buf, Layout::TCP_V4, no_start_time, true).is_empty());
    }

    #[test]
    fn layout_sizes_match_the_windows_structures() {
        assert_eq!(Layout::TCP_V4.row_size, 6 * 4);
        assert_eq!(Layout::TCP_V6.row_size, 56);
        assert_eq!(Layout::UDP_V4.row_size, 4 * 4);
        assert_eq!(Layout::UDP_V6.row_size, 28);
    }
}
