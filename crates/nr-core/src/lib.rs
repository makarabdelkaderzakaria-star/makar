//! # nr-core
//!
//! The pure, testable heart of NetRocket.
//!
//! Design rules that exist specifically to be *faster and lighter* than the
//! .NET original (`SysAdminDoc/OpenNetLimit`, MIT, commit f26b46c):
//!
//! 1. **Zero allocation on the packet path.** No `String`, no `Vec`, no
//!    `IPAddress`, no LINQ. Everything is a `Copy` struct in a fixed-size array
//!    or a stack buffer.
//! 2. **One rate-control state per flow.** A single `u64` theoretical arrival
//!    time (GCRA). The original used `lock` + `double` + two non-atomic methods
//!    (`GetDelay` then `TryConsume`) which is both slow and racy.
//! 3. **Carry across batches.** WinDivert hands us up to 255 packets per
//!    `RecvEx`. Anything we cannot send yet is retained and re-offered on the
//!    next batch in *original order* — never re-queued through a 1 ms timer.
//! 4. **Admission control instead of 512-packet drop-tail.** Bounded byte
//!    budget, and over budget we shed *inbound* (in-window) segments, which TCP
//!    recovers with a zero-window / ACK rather than a retransmission storm.
//!
//! Nothing here does I/O; `nr-divert` and `nr-app` wrap it.
//!
//! ```
//! use nr_core::{Config, Engine, Limits, PacketView, Direction, Protocol};
//!
//! let mut config = Config::default();
//! config.upsert(Limits::new("browser.exe").bits(8_000_000)).unwrap();
//! let mut engine = Engine::<1024>::new(config);
//!
//! let frame = nr_core::frame::tcp_v4([10, 0, 0, 1], 50000, [1, 1, 1, 1], 443, &[0; 100]);
//! let view = PacketView::parse(&frame).unwrap();
//! assert_eq!(view.dst_port, 443);
//! assert_eq!(Direction::Outbound.flip(), Direction::Inbound);
//! assert_eq!(Protocol::from_ip(6), Protocol::Tcp);
//! let outcome = engine.process(&frame, Direction::Outbound, 0, u32::MAX, 0, 0, 0);
//! assert!(outcome.is_send_now());
//! ```

#![forbid(unsafe_code)]

pub mod attribution;
pub mod config;
pub mod error;
pub mod flow;
pub mod frame;
pub mod gcra;
pub mod identity;
pub mod packet;
pub mod pipeline;
pub mod rules;
pub mod scheduler;
pub mod stats;

pub use attribution::{FlowAttribution, FlowEvent, SeedReport, SnapshotEntry};
pub use config::{Config, Limits, OverLimitPolicy};
pub use error::{ConfigError, ParseError, RuleError};
pub use flow::{Endpoint, FlowKey, FlowTable};
pub use gcra::Gcra;
pub use identity::{IdentityCache, ProcIdentity, ProcKey};
pub use packet::{Direction, PacketView, Protocol, TcpFlags};
pub use pipeline::{Decision, DropReason, Engine, Outcome};
pub use rules::{Action, CompiledRules, RuleSet};
pub use scheduler::{Admit, Scheduler, Shed};
pub use stats::{Counters, Snapshot};

/// Version string, also used by the CLI `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name used in logs, pipes and docs.
pub const APP_NAME: &str = "netrocket";
