//! # nr-divert
//!
//! The I/O layer. Everything OS-specific lives here so that `nr-core` stays
//! pure and testable on any platform.
//!
//! * [`batch`] — frame boundaries inside a WinDivert batch.
//! * [`clock`] — one monotonic clock, nanoseconds, no syscalls per packet.
//! * [`slab`] — the token slab that lets the core hand back an opaque per-packet
//!   address (`WINDIVERT_ADDRESS`) without knowing what it is.
//! * [`sim`] — a synthetic transport used by `nr simulate`, by the integration
//!   tests and by the benchmark, so the whole pipeline is exercised end to end
//!   on Linux.
//! * [`address`] — the pure WinDivert ABI types (address, layer, pack);
//!   compiled and tested on every platform, including the offsets and the
//!   deferred-reinjection wire format.
//! * [`win`] — the real WinDivert backend (`cfg(windows)` only).
//! * [`win_snapshot`] — the start-up endpoint table (`GetExtendedTcpTable`),
//!   whose decoding is pure and therefore tested on every platform.
//!
//! ## A note on batching
//!
//! WinDivert 2.2 can hand over up to `WINDIVERT_BATCH_MAX` (255) packets in one
//! call, which removes most kernel/user-mode transitions. It requires the
//! *asynchronous* path (`WinDivertRecvEx` with an `OVERLAPPED` and an I/O
//! completion port). That path is implemented here behind
//! [`win::AsyncMode`], but `nr` defaults to the **synchronous** path, because:
//!
//! * the synchronous path is what has been exercised on real hardware, and we
//!   do not ship untested code paths as defaults;
//! * overlapped I/O on Windows has its own long tail of failure modes
//!   (`ERROR_IO_PENDING`, `STATUS_PENDING` not being observable without an
//!   explicit re-read, completion-port lifetime);
//! * the measured difference on a localhost benchmark is small compared to
//!   removing *per-packet allocations and lookups*, which is what this rewrite
//!   actually does.
//!
//! `docs/BENCHMARKS.md` records both numbers, including the fact that the
//! synchronous path is what the throughput figures came from.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod address;
pub mod batch;
pub mod clock;
pub mod sim;
pub mod slab;
pub mod win_snapshot;

#[cfg(windows)]
pub mod win;

pub use batch::{iter_frames, BatchReader};
pub use clock::Clock;
pub use slab::TokenSlab;

/// Errors from the I/O layer.
#[derive(Debug)]
pub enum DivertError {
    /// The WinDivert driver could not be opened (not installed, no admin
    /// rights, or an incompatible version).
    Open(String),
    /// `WinDivertRecv` failed.
    Recv(u32),
    /// `WinDivertSend` failed. This one matters: a send failure means the
    /// packet was dropped by the stack, and the caller must count it.
    Send(u32),
    /// `WinDivertSetParam` failed (usually a value out of range).
    Param(u32),
    /// The driver was shut down (normal termination).
    Shutdown,
    /// Anything else, with a message.
    Other(String),
}

impl DivertError {
    /// Attach a human-readable note to a bare error code. Used when the driver
    /// was never reachable in the first place.
    #[must_use]
    pub fn with_note(self, note: String) -> Self {
        match self {
            Self::Param(_) => Self::Open(note),
            other => other,
        }
    }
}

impl std::fmt::Display for DivertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(m) => write!(f, "cannot open WinDivert handle: {m}"),
            Self::Recv(code) => write!(f, "WinDivertRecv failed (win32 error {code})"),
            Self::Send(code) => write!(f, "WinDivertSend failed (win32 error {code})"),
            Self::Param(code) => write!(f, "WinDivertSetParam failed (win32 error {code})"),
            Self::Shutdown => f.write_str("divert handle shut down"),
            Self::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DivertError {}

/// The single abstraction the engine loop needs.
pub trait Transport {
    /// Receive one frame into `buf`, returning `(len, direction, token)`.
    ///
    /// `token` is opaque to the engine and is handed back verbatim on send.
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, nr_core::Direction, u64)>, DivertError>;

    /// Send `frame` back into the stack with the address identified by `token`.
    fn send(&mut self, frame: &[u8], token: u64) -> Result<(), DivertError>;

    /// Release a token that will never be sent (dropped or shed).
    fn release(&mut self, token: u64);
}
