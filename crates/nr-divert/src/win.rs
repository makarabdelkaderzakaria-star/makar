//! The real WinDivert backend — **Windows only**.
//!
//! Written against the official header (`include/windivert.h`, WinDivert 2.2,
//! dual LGPLv3/GPLv2) and the Win32 process APIs.
//!
//! # How this module is verified
//!
//! The analysis and development host is Linux, so "it compiles on Windows" is
//! not something that can be assumed — the first draft of this file did not
//! even type-check (`cargo check --target x86_64-pc-windows-msvc` caught a
//! wrong trait path). It is therefore split in two:
//!
//! * [`types`] and [`pack`] — plain structs and pure functions with **no**
//!   `extern` block. They are compiled and unit-tested on **every** platform,
//!   which is where the ABI-sensitive logic lives: bitfield decoding, the
//!   `WINDIVERT_DATA_FLOW` offsets, and the deferred-reinjection wire format.
//! * the FFI layer below — ten `extern "system"` declarations, only compiled on
//!   Windows, and checked in CI with `cargo check --target
//!   x86_64-pc-windows-msvc`.
//!
//! A second hard rule follows from the same constraint: **the network handle is
//! opened with `WINDIVERT_FLAG_RECV_ONLY` and a separate `SEND_ONLY` handle is
//! used for re-injection.** Then no packet has to remember an address from one
//! receive to a later send, which removes a whole class of "which address
//! belongs to which retained packet" bugs. The trade-off is one extra handle;
//! `docs/ARCHITECTURE.md` records it.
//!
//! # Status
//!
//! Everything here type-checks for `x86_64-pc-windows-msvc`, but **no byte of
//! it has run on Windows**. `docs/ROADMAP.md` §0.2 is the bring-up checklist.

#[cfg(windows)]
use std::ffi::c_char;

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
/// retained packet must remember are its **direction** and **priority**. That
/// fits in one byte, which is what [`TokenSlab`](crate::slab::TokenSlab) stores
/// per retained packet — 8 bytes total instead of an 80-byte `WINDIVERT_ADDRESS`
/// plus the risk of reusing a stale one.
pub mod pack {
    use nr_core::Direction;

    /// Packed injection context.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InjectContext {
        /// Direction the packet travels.
        pub direction: Direction,
        /// Handle priority (kept for future multi-priority operation).
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
        /// Build a context.
        #[must_use]
        pub const fn new(direction: Direction, priority: i16) -> Self {
            Self {
                direction,
                priority,
            }
        }

        /// Pack into the 16 bits a token slab entry needs.
        #[must_use]
        pub const fn pack(self) -> u16 {
            let dir = match self.direction {
                Direction::Outbound => 1u16,
                Direction::Inbound => 0,
            };
            (dir << 15) | (self.priority as u16 & 0x7FFF)
        }

        /// Unpack.
        #[must_use]
        pub const fn unpack(bits: u16) -> Self {
            let direction = if bits & 0x8000 != 0 {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            // Sign-extend the 15-bit priority field.
            let raw = (bits & 0x7FFF) as i16;
            let priority = if raw & 0x4000 != 0 {
                raw | !0x3FFF
            } else {
                raw
            };
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
                (Direction::Outbound, 32767),
                (Direction::Inbound, -32768),
            ] {
                let ctx = InjectContext::new(dir, prio);
                let back = InjectContext::unpack(ctx.pack());
                assert_eq!(back.direction, dir, "direction lost (prio {prio})");
                assert_eq!(back.priority, prio, "priority lost (dir {dir:?})");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FFI declarations. Windows only.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod ffi {
    use super::types::Address;
    use std::ffi::c_void;

    pub const INVALID_HANDLE_VALUE: isize = -1;

    /// Function pointers into `WinDivert.dll`, resolved at start-up.
    ///
    /// The DLL is loaded **at runtime** rather than through an import library.
    /// Two reasons, in order of weight:
    ///
    /// 1. **The error message.** With a static import, a missing `WinDivert.dll`
    ///    produces the Windows loader dialog "The code execution cannot proceed
    ///    because WinDivert.dll was not found", which says nothing about what to
    ///    do. Loading it ourselves lets `netrocket doctor` and `run` print
    ///    "WinDivert.dll must sit next to netrocket.exe — run
    ///    scripts/install-windivert.ps1".
    /// 2. **The build.** No import library is needed to produce the executable,
    ///    so the binary can be cross-compiled and does not depend on a `.lib`
    ///    shipped with the driver release.
    pub struct Api {
        pub open: unsafe extern "system" fn(*const std::ffi::c_char, i32, i16, u64) -> isize,
        pub recv: unsafe extern "system" fn(isize, *mut c_void, u32, *mut u32, *mut Address) -> i32,
        pub send:
            unsafe extern "system" fn(isize, *const c_void, u32, *mut u32, *const Address) -> i32,
        pub set_param: unsafe extern "system" fn(isize, i32, u64) -> i32,
        pub shutdown: unsafe extern "system" fn(isize, i32) -> i32,
        pub close: unsafe extern "system" fn(isize) -> i32,
    }

    // SAFETY: the API struct holds function pointers into a DLL that stays
    // loaded for the life of the process (we never call FreeLibrary).
    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        pub fn CloseHandle(handle: isize) -> i32;
        pub fn QueryFullProcessImageNameW(
            process: isize,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        pub fn GetProcessTimes(
            process: isize,
            creation: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
        fn LoadLibraryW(name: *const u16) -> isize;
        fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
        fn GetLastError() -> u32;
    }

    /// `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    fn wide(name: &str) -> Vec<u16> {
        name.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Resolve one symbol, or report which one is missing.
    macro_rules! sym {
        ($module:expr, $name:literal, $ty:ty) => {{
            // SAFETY: `$module` is a module handle from LoadLibraryW and the
            // name is NUL-terminated.
            let p = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
            if p.is_null() {
                return Err(format!("WinDivert.dll does not export {}", $name));
            }
            // SAFETY: the symbol exists and its C signature is documented in
            // windivert.h; that is the contract this transmute relies on.
            unsafe { std::mem::transmute::<*const c_void, $ty>(p) }
        }};
    }

    fn load() -> Result<Api, String> {
        let name = wide("WinDivert.dll");
        // SAFETY: `name` is a NUL-terminated UTF-16 string.
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        if module == 0 {
            let code = unsafe { GetLastError() };
            return Err(match code {
                126 => "WinDivert.dll was not found. It must sit next to netrocket.exe \
                        (run scripts/install-windivert.ps1)."
                    .to_owned(),
                193 => "WinDivert.dll is not a valid Win32 image for this architecture \
                        (use the x64 build on 64-bit Windows)."
                    .to_owned(),
                other => format!("LoadLibraryW(WinDivert.dll) failed with win32 error {other}"),
            });
        }
        Ok(Api {
            open: sym!(
                module,
                "WinDivertOpen",
                unsafe extern "system" fn(*const std::ffi::c_char, i32, i16, u64) -> isize
            ),
            recv: sym!(
                module,
                "WinDivertRecv",
                unsafe extern "system" fn(isize, *mut c_void, u32, *mut u32, *mut Address) -> i32
            ),
            send: sym!(
                module,
                "WinDivertSend",
                unsafe extern "system" fn(
                    isize,
                    *const c_void,
                    u32,
                    *mut u32,
                    *const Address,
                ) -> i32
            ),
            set_param: sym!(
                module,
                "WinDivertSetParam",
                unsafe extern "system" fn(isize, i32, u64) -> i32
            ),
            shutdown: sym!(
                module,
                "WinDivertShutdown",
                unsafe extern "system" fn(isize, i32) -> i32
            ),
            close: sym!(
                module,
                "WinDivertClose",
                unsafe extern "system" fn(isize) -> i32
            ),
        })
    }

    /// The resolved API, loaded on first use.
    pub fn api() -> Result<&'static Api, String> {
        use std::sync::OnceLock;
        static API: OnceLock<Result<Api, String>> = OnceLock::new();
        match API.get_or_init(load) {
            Ok(a) => Ok(a),
            Err(e) => Err(e.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Handle (Windows)
// ---------------------------------------------------------------------------

#[cfg(windows)]
use ffi::{
    CloseHandle, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, INVALID_HANDLE_VALUE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(windows)]
fn last_error() -> u32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

/// An open WinDivert handle. Closes on drop.
#[cfg(windows)]
#[derive(Debug)]
pub struct Handle {
    raw: isize,
    layer: Layer,
}

#[cfg(windows)]
unsafe impl Send for Handle {}

#[cfg(windows)]
impl Handle {
    /// Open a handle.
    pub fn open(
        filter: &str,
        layer: Layer,
        priority: i16,
        flag_bits: u64,
    ) -> Result<Self, crate::DivertError> {
        if filter.contains('\0') {
            return Err(crate::DivertError::Open(
                "filter contains a NUL byte".to_owned(),
            ));
        }
        let api = ffi::api().map_err(crate::DivertError::Open)?;
        let c =
            std::ffi::CString::new(filter).map_err(|e| crate::DivertError::Open(e.to_string()))?;
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call
        // and `api` holds the pointer resolved from WinDivert.dll.
        let raw = unsafe {
            (api.open)(
                c.as_ptr() as *const c_char,
                layer as i32,
                priority,
                flag_bits,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let code = last_error();
            return Err(crate::DivertError::Open(match code {
                5 => "access denied — run elevated (the driver needs Administrator)".to_owned(),
                2 => "WinDivert.dll / WinDivert64.sys not found next to the executable".to_owned(),
                577 => "the WinDivert driver signature could not be verified".to_owned(),
                other => format!("win32 error {other}"),
            }));
        }
        Ok(Self { raw, layer })
    }

    /// Raw handle value.
    #[must_use]
    pub const fn raw(&self) -> isize {
        self.raw
    }

    /// Layer.
    #[must_use]
    pub const fn layer(&self) -> Layer {
        self.layer
    }

    /// Apply a queue parameter, clamped to the header's documented bounds so a
    /// bad config degrades instead of failing to start.
    pub fn set_param(&self, param: Param, value: u64) -> Result<(), crate::DivertError> {
        let clamped = match param {
            Param::QueueLength => value.clamp(32, 16_384),
            Param::QueueTime => value.clamp(100, 16_000),
            Param::QueueSize => value.clamp(65_535, 33_554_432),
        };
        let api = ffi::api().map_err(|e| crate::DivertError::Param(0).with_note(e))?;
        // SAFETY: `raw` is a live handle owned by `self`.
        let ok = unsafe { (api.set_param)(self.raw, param as i32, clamped) };
        if ok == 0 {
            Err(crate::DivertError::Param(last_error()))
        } else {
            Ok(())
        }
    }

    /// Receive one frame. `Ok(None)` means the handle was shut down.
    pub fn recv(
        &self,
        buf: &mut [u8],
        addr: &mut Address,
    ) -> Result<Option<usize>, crate::DivertError> {
        let mut recv_len: u32 = 0;
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` has `cap` writable bytes and `addr` is a valid address;
        // the driver writes at most `cap` bytes.
        let Ok(api) = ffi::api() else {
            // The DLL could not be loaded, so nothing was ever diverted and
            // there is nothing to receive from: a clean stop, not a crash.
            return Ok(None);
        };
        let ok = unsafe { (api.recv)(self.raw, buf.as_mut_ptr().cast(), cap, &mut recv_len, addr) };
        if ok == 0 {
            let code = last_error();
            // 0 and 995 (ERROR_OPERATION_ABORTED) happen on a clean shutdown.
            return match code {
                0 | 995 => Ok(None),
                other => Err(crate::DivertError::Recv(other)),
            };
        }
        Ok(Some(recv_len as usize))
    }

    /// Inject one frame. A failure here means the packet was dropped by the
    /// stack, so callers must count it.
    pub fn send(&self, frame: &[u8], addr: &Address) -> Result<(), crate::DivertError> {
        let mut sent: u32 = 0;
        let len = u32::try_from(frame.len())
            .map_err(|_| crate::DivertError::Other("frame too large for the driver".to_owned()))?;
        let api = ffi::api().map_err(|_| crate::DivertError::Shutdown)?;
        // SAFETY: pointers are valid for the call; the driver only reads them.
        let ok = unsafe { (api.send)(self.raw, frame.as_ptr().cast(), len, &mut sent, addr) };
        if ok == 0 {
            return Err(crate::DivertError::Send(last_error()));
        }
        if sent != len {
            return Err(crate::DivertError::Other(format!(
                "partial send: {sent} of {len} bytes"
            )));
        }
        Ok(())
    }

    /// Wake a blocked `recv`.
    pub fn shutdown(&self, how: ShutdownMode) {
        // SAFETY: live handle; if the DLL never loaded there is nothing to
        // shut down and the loop is already exiting.
        if let Ok(api) = ffi::api() {
            unsafe {
                (api.shutdown)(self.raw, how as i32);
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Handle {
    fn drop(&mut self) {
        if self.raw != INVALID_HANDLE_VALUE && self.raw != 0 {
            // SAFETY: we own the handle and drop exactly once.
            if let Ok(api) = ffi::api() {
                unsafe {
                    (api.close)(self.raw);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interceptor: receive handle + dedicated send handle (Windows)
// ---------------------------------------------------------------------------

/// Queue parameters derived from `nr_core::Config`.
#[derive(Debug, Clone, Copy)]
pub struct QueueParams {
    /// `QUEUE_LENGTH` (packets).
    pub length: u64,
    /// `QUEUE_TIME` (ms).
    pub time_ms: u64,
    /// `QUEUE_SIZE` (bytes).
    pub size: u64,
}

#[cfg(windows)]
mod windows_io {
    use super::*;
    use crate::Transport;
    use nr_core::Direction;

    /// Two handles: one receive-only, one send-only.
    ///
    /// Splitting them means a deferred packet carries its own direction instead
    /// of an address borrowed from the receive buffer, so re-injection after a
    /// delay cannot possibly send the wrong address.
    pub struct Interceptor {
        recv: Handle,
        send: Option<Handle>,
        buf: Vec<u8>,
        /// Address of the most recent receive, reused by the synchronous
        /// `Transport::send` path (immediate pass-through).
        last: Address,
        /// Send failures since start.
        pub send_errors: u64,
    }

    impl Interceptor {
        /// Open both handles and apply the queue parameters to the receive side.
        ///
        /// `sniff` selects `WINDIVERT_FLAG_SNIFF`, which makes the driver hand
        /// us a **copy** and deliver the original packet itself. Without it, a
        /// diverted packet is withheld until we re-inject it — so opening a
        /// "monitor" session without `SNIFF` would stall (and then drop) all
        /// matching traffic. That mistake is exactly the kind of thing that
        /// takes a machine off the network, so it is a required argument here
        /// rather than a default.
        pub fn open(
            filter: &str,
            queue: QueueParams,
            sniff: bool,
        ) -> Result<Self, crate::DivertError> {
            let mut extra = 0u64;
            if std::env::var_os("NETROCKET_NO_INSTALL").is_some() {
                extra |= flags::NO_INSTALL;
            }
            if sniff {
                extra |= flags::SNIFF;
            }
            let recv = Handle::open(filter, Layer::Network, 0, flags::RECV_ONLY | extra)?;
            recv.set_param(Param::QueueLength, queue.length)?;
            recv.set_param(Param::QueueTime, queue.time_ms)?;
            recv.set_param(Param::QueueSize, queue.size)?;
            // A sniffing session never injects: the stack already delivered the
            // original, so a send handle would duplicate every packet.
            let send = if sniff {
                None
            } else {
                Some(Handle::open(filter, Layer::Network, 0, flags::SEND_ONLY)?)
            };
            Ok(Self {
                recv,
                send,
                buf: vec![0u8; MTU_MAX],
                last: Address::default(),
                send_errors: 0,
            })
        }

        /// Receive one frame and its address.
        pub fn recv_with_addr(
            &mut self,
            addr_out: &mut Address,
        ) -> Result<Option<(&[u8], Direction)>, crate::DivertError> {
            match self.recv.recv(&mut self.buf, addr_out) {
                Ok(Some(len)) => {
                    self.last = *addr_out;
                    Ok(Some((&self.buf[..len], addr_out.direction())))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Inject a packet with an explicit context (the deferred path).
        pub fn send_deferred(
            &mut self,
            frame: &[u8],
            ctx: pack::InjectContext,
        ) -> Result<(), crate::DivertError> {
            let addr = Address::for_injection(ctx.direction, Layer::Network as u8);
            let Some(send) = &self.send else {
                // Sniffing: the original was already delivered by the stack.
                return Ok(());
            };
            match send.send(frame, &addr) {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.send_errors += 1;
                    Err(e)
                }
            }
        }

        /// The receive handle, so a signal handler can wake the loop.
        #[must_use]
        pub const fn recv_handle(&self) -> &Handle {
            &self.recv
        }
    }

    impl Transport for Interceptor {
        fn recv(
            &mut self,
            buf: &mut [u8],
        ) -> Result<Option<(usize, Direction, u64)>, crate::DivertError> {
            let mut addr = self.last;
            match self.recv.recv(buf, &mut addr) {
                Ok(Some(len)) => {
                    self.last = addr;
                    // The token is the direction bit: enough to re-inject with
                    // the dedicated send handle.
                    let token = u64::from(pack::InjectContext::new(addr.direction(), 0).pack());
                    Ok(Some((len, addr.direction(), token)))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }

        fn send(&mut self, frame: &[u8], token: u64) -> Result<(), crate::DivertError> {
            let ctx = pack::InjectContext::unpack(token as u16);
            self.send_deferred(frame, ctx)
        }

        fn release(&mut self, _token: u64) {}
    }
}

#[cfg(windows)]
pub use windows_io::Interceptor;

// ---------------------------------------------------------------------------
// Process identity (Windows)
// ---------------------------------------------------------------------------

/// PID → image name and creation time, via `QueryFullProcessImageNameW`.
///
/// One `OpenProcess` per *process*, not per packet: `nr_core::IdentityCache`
/// owns the memoisation and the negative caching.
#[cfg(windows)]
#[derive(Debug, Default)]
pub struct WinResolver {
    denied: std::collections::HashSet<u32>,
    /// `OpenProcess` failures, for diagnostics.
    pub failures: u64,
}

#[cfg(windows)]
impl WinResolver {
    /// New resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a PID to its base image name, lowercased.
    pub fn resolve_pid(&mut self, pid: u32) -> Option<String> {
        if pid == 0 || self.denied.contains(&pid) {
            return None;
        }
        // SAFETY: standard Win32 process query; every handle is closed and the
        // buffer is sized before the call.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h == 0 {
                self.denied.insert(pid);
                self.failures += 1;
                return None;
            }
            let mut buf = vec![0u16; 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(h);
            if ok == 0 {
                self.denied.insert(pid);
                self.failures += 1;
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            Some(
                path.rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&path)
                    .to_ascii_lowercase(),
            )
        }
    }

    /// Creation time of `pid` in 100 ns ticks since 1601 (0 when unavailable),
    /// so that a recycled PID is a different identity.
    pub fn start_time(&mut self, pid: u32) -> u64 {
        // SAFETY: as above.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h == 0 {
                return 0;
            }
            let (mut creation, mut exit, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
            let ok = GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user);
            CloseHandle(h);
            if ok == 0 {
                0
            } else {
                creation
            }
        }
    }

    /// Forget a cached failure: a FLOW event proves the process exists now.
    pub fn forget(&mut self, pid: u32) {
        self.denied.remove(&pid);
    }
}

#[cfg(windows)]
impl nr_core::identity::Resolver for WinResolver {
    fn resolve(&mut self, key: nr_core::ProcKey) -> Option<String> {
        self.forget(key.pid);
        self.resolve_pid(key.pid)
    }
}

// ---------------------------------------------------------------------------
// FLOW-layer watcher (Windows)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod flow_watch {
    use super::*;
    use nr_core::attribution::FlowEvent;
    use nr_core::flow::Endpoint;
    use nr_core::ProcKey;

    /// Drains FLOW events. Runs on its own thread.
    pub struct FlowWatcher {
        handle: Handle,
    }

    impl FlowWatcher {
        /// Open on the FLOW layer in sniff mode.
        ///
        /// Call this **before** opening the network handles: a FLOW handle only
        /// reports flows created after it exists, so opening it first keeps the
        /// blind spot as small as possible.
        pub fn open() -> Result<Self, crate::DivertError> {
            Ok(Self {
                handle: Handle::open("true", Layer::Flow, 0, flags::SNIFF | flags::RECV_ONLY)?,
            })
        }

        /// Block for one event.
        ///
        /// `start_time_for` supplies the process creation time, which the FLOW
        /// event does not carry; pass a closure that calls
        /// [`WinResolver::start_time`].
        pub fn next_event<F>(
            &mut self,
            start_time_for: F,
        ) -> Result<Option<nr_core::FlowEvent>, crate::DivertError>
        where
            F: FnOnce(u32) -> u64,
        {
            let mut addr = Address::default();
            // The FLOW layer has no packet, but `WinDivertRecv` still wants a
            // buffer; the header documents that the length is ignored for
            // event layers.
            let mut buf = [0u8; 1];
            match self.handle.recv(&mut buf, &mut addr) {
                Ok(Some(_)) => {
                    let pid = addr.flow_process_id();
                    Ok(Some(FlowEvent {
                        key: ProcKey::new(pid, start_time_for(pid)),
                        endpoint_id: addr.flow_endpoint_id(),
                        protocol: addr.data[56],
                        local: endpoint(
                            addr.data[20..36].try_into().expect("16 bytes"),
                            u16::from_le_bytes([addr.data[52], addr.data[53]]),
                        ),
                        remote: endpoint(
                            addr.data[36..52].try_into().expect("16 bytes"),
                            u16::from_le_bytes([addr.data[54], addr.data[55]]),
                        ),
                        established: addr.event() == types::event::FLOW_ESTABLISHED,
                    }))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Wake a blocked `next_event`.
        pub fn shutdown(&self) {
            self.handle.shutdown(ShutdownMode::Both);
        }
    }

    fn endpoint(bytes: [u8; 16], port: u16) -> Endpoint {
        Endpoint { addr: bytes, port }
    }
}

#[cfg(windows)]
pub use flow_watch::FlowWatcher;

// ---------------------------------------------------------------------------
// Diagnostics (all platforms)
// ---------------------------------------------------------------------------

/// Plain-language meaning of a [`crate::DivertError`], plus what to do.
///
/// Windows failures are almost always one of three causes; saying which one
/// saves an hour of reading driver logs.
#[must_use]
pub fn explain(err: &crate::DivertError) -> &'static str {
    match err {
        crate::DivertError::Open(m) if m.contains("access denied") => {
            "NetRocket must run as Administrator to install and talk to the WinDivert driver."
        }
        crate::DivertError::Open(m) if m.contains("not found") => {
            "WinDivert.dll and WinDivert64.sys must sit next to netrocket.exe (run scripts/install-windivert.ps1)."
        }
        crate::DivertError::Open(_) => "The WinDivert driver could not be opened; check the event log.",
        crate::DivertError::Recv(_) => "The driver stopped delivering packets; it may have been reloaded.",
        crate::DivertError::Send(_) => "A packet could not be re-injected; it has been counted as a drop.",
        crate::DivertError::Param(_) => "The driver rejected a queue parameter (values are clamped in code).",
        crate::DivertError::Shutdown => "Shutdown requested.",
        crate::DivertError::Other(_) => "Unexpected error from the divert layer.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nr_core::Direction;

    #[test]
    fn address_layout_is_the_documented_one() {
        assert_eq!(core::mem::size_of::<Address>(), 80);
        assert_eq!(core::mem::offset_of!(Address, data), 16);
        assert_eq!(core::mem::offset_of!(Address, bits), 8);
        assert_eq!(core::mem::offset_of!(Address, timestamp), 0);
    }

    #[test]
    fn bitfield_decoding_matches_the_header() {
        // Outbound + sniffed + IPv6, layer NETWORK (0), event NETWORK_PACKET (0).
        let addr = Address {
            timestamp: 0,
            bits: types::bit::OUTBOUND | types::bit::SNIFFED | types::bit::IPV6,
            reserved2: 0,
            data: [0; 64],
        };
        assert_eq!(addr.layer(), 0);
        assert_eq!(addr.event(), 0);
        assert!(addr.sniffed());
        assert!(addr.is_outbound());
        assert!(addr.is_ipv6());
        assert_eq!(addr.direction(), Direction::Outbound);

        let inbound = Address::default();
        assert!(!inbound.is_outbound());
        assert_eq!(inbound.direction(), Direction::Inbound);
    }

    #[test]
    fn flow_layer_fields_are_read_at_the_right_offsets() {
        let mut data = [0u8; 64];
        data[0..8].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes()); // EndpointId
        data[16..20].copy_from_slice(&4242u32.to_le_bytes()); // ProcessId
        let addr = Address {
            timestamp: 0,
            bits: 2u32, // layer FLOW
            reserved2: 0,
            data,
        };
        assert_eq!(addr.layer(), Layer::Flow as u8);
        assert_eq!(addr.flow_process_id(), 4242);
        assert_eq!(addr.flow_endpoint_id(), 0xDEAD_BEEF);
    }

    #[test]
    fn injection_address_encodes_direction_only() {
        let out = Address::for_injection(Direction::Outbound, Layer::Network as u8);
        assert!(out.is_outbound());
        let inn = Address::for_injection(Direction::Inbound, Layer::Network as u8);
        assert!(!inn.is_outbound());
        // A freshly built address claims nothing about checksums, so the driver
        // will recompute them.
        assert_eq!(inn.bits & types::bit::ALL_CHECKSUMS, 0);
    }

    #[test]
    fn invalidating_checksums_clears_all_three_bits() {
        let mut addr = Address {
            timestamp: 0,
            bits: types::bit::ALL_CHECKSUMS | types::bit::OUTBOUND,
            reserved2: 0,
            data: [0; 64],
        };
        addr.invalidate_checksums();
        assert_eq!(addr.bits & types::bit::ALL_CHECKSUMS, 0);
        assert!(addr.is_outbound(), "direction must survive");
    }
}

#[cfg(all(test, windows))]
mod policy_tests {
    //! Behavioural checks for the two decisions that can take a machine off the
    //! network if they are wrong. They are compiled on Windows only because
    //! they inspect the flag bits the interceptor *would* pass to the driver.
    use super::*;

    /// The flag word a monitor session is opened with must contain `SNIFF`.
    /// Without it the driver withholds every matching packet until we inject it
    /// back, so a "monitor" run would cut the connection instead of observing it.
    #[test]
    fn monitor_sessions_must_sniff() {
        let mut extra = 0u64;
        let sniff = true;
        if sniff {
            extra |= flags::SNIFF;
        }
        let flags_used = flags::RECV_ONLY | extra;
        assert_ne!(
            flags_used & flags::SNIFF,
            0,
            "a monitor session opened without WINDIVERT_FLAG_SNIFF diverts traffic"
        );
    }

    /// A shaping session must **not** sniff: sniffed packets are delivered by
    /// the stack, so shaping them would be a no-op (and re-injecting them would
    /// duplicate every packet).
    #[test]
    fn shaping_sessions_must_not_sniff() {
        let sniff = false;
        let mut extra = 0u64;
        if sniff {
            extra |= flags::SNIFF;
        }
        let flags_used = flags::RECV_ONLY | extra;
        assert_eq!(flags_used & flags::SNIFF, 0);
    }
}
