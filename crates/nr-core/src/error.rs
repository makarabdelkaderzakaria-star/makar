//! Typed errors. No `anyhow` in the core: the hot path never formats strings,
//! and callers can match on these exhaustively.

use core::fmt;

/// Malformed / truncated packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer shorter than the fixed IPv4/IPv6 header.
    Truncated(usize),
    /// Version nibble is neither 4 nor 6.
    BadVersion(u8),
    /// `IHL` < 5 or header extends past the end of the buffer.
    BadIpHeaderLen(u8),
    /// TCP data offset < 5 or extends past the end of the buffer.
    BadTcpHeaderLen(u8),
    /// IPv4 `TotalLength` disagrees with the buffer.
    BadTotalLength { declared: u16, available: usize },
    /// Fragment with non-zero offset: transport header not present.
    Fragment,
    /// IPv6 extension headers were present; not handled on the fast path.
    ExtensionHeaders,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(n) => write!(f, "truncated packet ({n} bytes)"),
            Self::BadVersion(v) => write!(f, "unsupported IP version {v}"),
            Self::BadIpHeaderLen(l) => write!(f, "bad IP header length word {l}"),
            Self::BadTcpHeaderLen(l) => write!(f, "bad TCP data offset {l}"),
            Self::BadTotalLength {
                declared,
                available,
            } => write!(
                f,
                "declared total length {declared} exceeds {available} available bytes"
            ),
            Self::Fragment => f.write_str("IP fragment without transport header"),
            Self::ExtensionHeaders => f.write_str("IPv6 extension headers not supported"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Invalid configuration value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A rate of `0` is meaningless; use `Action::Allow` or drop the limit.
    ZeroRate,
    /// Burst smaller than one maximum-size packet.
    BurstTooSmall { burst: u64 },
    /// Byte budget below a single MTU.
    BudgetTooSmall { bytes: u64 },
    /// A data cap of zero bytes would drop everything forever.
    ZeroCap,
    /// Name of the limit is empty.
    EmptyName,
    /// Unknown `key=value` on the command line / config file.
    UnknownParam(String),
    /// Value failed to parse.
    BadValue { key: String, value: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRate => f.write_str("rate must be > 0"),
            Self::BurstTooSmall { burst } => write!(f, "burst {burst} is below one MTU"),
            Self::ZeroCap => f.write_str("cap must be > 0 bytes"),
            Self::BudgetTooSmall { bytes } => write!(f, "budget {bytes} is below one MTU"),
            Self::EmptyName => f.write_str("limit name must not be empty"),
            Self::UnknownParam(k) => write!(f, "unknown parameter `{k}`"),
            Self::BadValue { key, value } => write!(f, "bad value for `{key}`: {value}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Malformed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// Missing `:` separator.
    Syntax,
    /// Unknown action keyword.
    UnknownAction(String),
    /// Nothing after the action keyword.
    EmptyMatch,
    /// Limit refers to a name that is not defined.
    UnknownLimit(String),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax => f.write_str("rule must be `<action>:<match>`"),
            Self::UnknownAction(a) => write!(f, "unknown action `{a}`"),
            Self::EmptyMatch => f.write_str("rule has an empty match expression"),
            Self::UnknownLimit(n) => write!(f, "unknown limit `{n}`"),
        }
    }
}

impl std::error::Error for RuleError {}
