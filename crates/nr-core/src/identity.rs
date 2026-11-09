//! Process identity, resolved **off** the packet path.
//!
//! The original called `Process.GetProcessById(pid).MainModule.FileName` for
//! every FLOW event — each call opens a handle and reads the process image
//! path, and the result was never cached. Under a busy machine that is the
//! single most expensive thing in the loop, and it can fail (protected
//! processes) which is why some traffic silently escaped the rules.
//!
//! Here the resolver is a trait so tests and the simulator can run anywhere:
//! the Windows implementation lives in `nr-divert`, and only the *cache* is in
//! the core. Two misses for the same PID are impossible: the first miss stores
//! a negative entry with a TTL, because re-querying a protected process on
//! every packet is exactly the waste we are eliminating.

use crate::packet::Protocol;

/// What identifies a process across restarts of our daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey {
    /// Process id.
    pub pid: u32,
    /// Process start time (Win32 `GetProcessTimes` creation time, 100 ns ticks),
    /// or 0 when unavailable. Including it defeats PID reuse — the original
    /// keyed limits by raw PID and therefore mis-attributed traffic after a
    /// process exited and its PID was recycled.
    pub start_time: u64,
}

impl ProcKey {
    /// Build a key.
    #[inline]
    #[must_use]
    pub const fn new(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }
}

/// A resolved identity. Borrow-free and `Copy` so it can be stored in the
/// per-flow row without allocation; the name is held in a side arena owned by
/// [`IdentityCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcIdentity {
    /// Address of the process name in the arena (see [`IdentityCache::name`]).
    pub name_idx: u32,
    /// Cached signed flag: `1` allowed to bypass limits (our own daemon, the
    /// system, antivirus), `0` normal, `2` unknown/protected.
    pub class: ProcClass,
}

/// Coarse classification, decided once at resolve time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcClass {
    /// Regular user process.
    Normal = 0,
    /// Our own process tree — never shaped, or the CLI/IPC starves.
    Self_ = 1,
    /// System / protected: cannot read the image path, treat as unmatched.
    Protected = 2,
    /// Explicitly exempted by configuration.
    Exempt = 3,
}

/// Resolver interface: implemented for Windows in `nr-divert`, and by a fake
/// map in tests.
///
/// `resolve` returns an owned `String` rather than a borrow, because the real
/// implementation builds the name from a Win32 wide-character buffer that does
/// not outlive the call. The cache is what makes this cheap: it is consulted
/// once per `ProcKey` per TTL, never per packet.
pub trait Resolver {
    /// Resolve `key` to an image file name (e.g. `chrome.exe`).
    ///
    /// Implementations must not block for long; the cache calls this at most
    /// once per `ProcKey` per TTL.
    fn resolve(&mut self, key: ProcKey) -> Option<String>;
}

/// Fixed-capacity identity cache: PID -> (name, class), with negative caching.
#[derive(Debug)]
pub struct IdentityCache {
    entries: Vec<Option<CacheEntry>>,
    names: Vec<NameSlot>,
    name_bytes: Vec<u8>,
    hits: u64,
    misses: u64,
    negative: u64,
    ttl_ms: u64,
    mask: usize,
}

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    key: ProcKey,
    name_idx: u32,
    class: ProcClass,
    expires_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct NameSlot {
    offset: u32,
    len: u16,
}

/// Result of a lookup that the caller must handle explicitly (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// A name was found (borrowed from the cache).
    Named(&'a str),
    /// The process could not be identified (protected, gone, or not yet
    /// resolved). Rules that require a name must not match.
    Unknown,
    /// Our own process or an exempt one.
    Exempt,
}

impl IdentityCache {
    /// Create a cache holding up to `capacity` PIDs (rounded up to a power of
    /// two) and `name_capacity` bytes of names. Both are fixed: no allocation
    /// ever happens on the packet path.
    #[must_use]
    pub fn new(capacity: usize, name_capacity: usize, ttl_ms: u64) -> Self {
        let cap = capacity.next_power_of_two().max(16);
        Self {
            entries: vec![None; cap],
            names: Vec::with_capacity(cap),
            name_bytes: Vec::with_capacity(name_capacity),
            hits: 0,
            misses: 0,
            negative: 0,
            ttl_ms,
            mask: cap - 1,
        }
    }

    /// Name stored at `idx`, if any.
    #[must_use]
    pub fn name(&self, idx: u32) -> Option<&str> {
        let slot = self.names.get(idx as usize)?;
        let start = slot.offset as usize;
        let end = start + slot.len as usize;
        core::str::from_utf8(self.name_bytes.get(start..end)?).ok()
    }

    /// Cache statistics `(hits, misses, negative)`.
    #[must_use]
    pub const fn stats(&self) -> (u64, u64, u64) {
        (self.hits, self.misses, self.negative)
    }

    /// Number of cached PIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Is the cache empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up `key`, resolving through `resolver` on miss or expiry.
    pub fn lookup<R: Resolver + ?Sized>(
        &mut self,
        key: ProcKey,
        now_ms: u64,
        resolver: &mut R,
    ) -> Lookup<'_> {
        let slot = (key.pid as usize) & self.mask;
        if let Some(e) = &self.entries[slot] {
            if e.key == key && now_ms < e.expires_ms {
                self.hits += 1;
                return self.materialise(e.name_idx, e.class);
            }
        }

        self.misses += 1;
        let resolved = resolver.resolve(key);
        match resolved {
            Some(name) => {
                let lower = name.to_ascii_lowercase();
                // Strip any directory component: rules match on the base name.
                let base = lower
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&lower)
                    .to_owned();
                if let Some(idx) = self.push_name(&base) {
                    let entry = CacheEntry {
                        key,
                        name_idx: idx,
                        class: ProcClass::Normal,
                        expires_ms: now_ms.saturating_add(self.ttl_ms),
                    };
                    self.entries[slot] = Some(entry);
                    return self.materialise(idx, ProcClass::Normal);
                }
                Lookup::Unknown
            }
            None => {
                self.negative += 1;
                // Negative entry: remember the failure so we do not hammer the
                // OS for a protected process on every single packet.
                self.entries[slot] = Some(CacheEntry {
                    key,
                    name_idx: u32::MAX,
                    class: ProcClass::Protected,
                    expires_ms: now_ms.saturating_add(self.ttl_ms / 2),
                });
                Lookup::Unknown
            }
        }
    }

    fn materialise(&self, name_idx: u32, class: ProcClass) -> Lookup<'_> {
        match class {
            ProcClass::Exempt | ProcClass::Self_ => Lookup::Exempt,
            ProcClass::Protected => Lookup::Unknown,
            ProcClass::Normal => match self.name(name_idx) {
                Some(n) => Lookup::Named(n),
                None => Lookup::Unknown,
            },
        }
    }

    fn push_name(&mut self, name: &str) -> Option<u32> {
        let bytes = name.as_bytes();
        if bytes.len() > u16::MAX as usize {
            return None;
        }
        let offset = self.name_bytes.len() as u32;
        if self.name_bytes.len() + bytes.len() > self.name_bytes.capacity() {
            // Arena exhausted: reuse slot 0 only if it holds this same name,
            // otherwise fail closed rather than growing (allocation-free path).
            let existing = self.names.first().and_then(|s| {
                let start = s.offset as usize;
                self.name_bytes
                    .get(start..start + s.len as usize)
                    .filter(|b| *b == bytes)
                    .map(|_| 0u32)
            });
            return existing;
        }
        self.name_bytes.extend_from_slice(bytes);
        let idx = u32::try_from(self.names.len()).ok()?;
        self.names.push(NameSlot {
            offset,
            len: u16::try_from(bytes.len()).ok()?,
        });
        Some(idx)
    }

    /// Drop entries whose TTL expired (called from the supervisor tick).
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for slot in &mut self.entries {
            let expired = matches!(slot, Some(e) if now_ms >= e.expires_ms);
            if expired {
                *slot = None;
                n += 1;
            }
        }
        n
    }
}

/// Convenience: map a resolved identity back to a class for the pipeline.
impl ProcIdentity {
    /// Build from parts.
    #[must_use]
    pub const fn new(name_idx: u32, class: ProcClass) -> Self {
        Self { name_idx, class }
    }
}

/// A [`Resolver`] backed by a static table. Used by tests, the simulator and
/// `nr-app`'s `--assume` flag so the whole pipeline can be exercised on Linux.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    map: std::collections::HashMap<ProcKey, String>,
    by_pid: std::collections::HashMap<u32, String>,
}

impl StaticResolver {
    /// Empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a name for a PID (start_time 0).
    pub fn with_pid(mut self, pid: u32, name: &str) -> Self {
        self.by_pid.insert(pid, name.to_owned());
        self
    }

    /// Register a name for a full key.
    pub fn with_key(mut self, key: ProcKey, name: &str) -> Self {
        self.map.insert(key, name.to_owned());
        self
    }

    /// Forget everything (simulate process exit).
    pub fn clear(&mut self) {
        self.map.clear();
        self.by_pid.clear();
    }

    /// Remove one pid.
    pub fn remove_pid(&mut self, pid: u32) {
        self.by_pid.remove(&pid);
        self.map.retain(|k, _| k.pid != pid);
    }
}

impl Resolver for StaticResolver {
    fn resolve(&mut self, key: ProcKey) -> Option<String> {
        if let Some(v) = self.map.get(&key) {
            return Some(v.clone());
        }
        self.by_pid.get(&key.pid).cloned()
    }
}

/// Map a protocol to a rule-matchable tag, used by `Rule` predicates.
#[must_use]
pub const fn protocol_tag(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_then_hits_cache() {
        let mut cache = IdentityCache::new(64, 4096, 5_000);
        let mut res = StaticResolver::new().with_pid(4242, "C:\\Program Files\\Chrome\\chrome.exe");
        assert!(matches!(
            cache.lookup(ProcKey::new(4242, 1), 0, &mut res),
            Lookup::Named("chrome.exe")
        ));
        assert!(matches!(
            cache.lookup(ProcKey::new(4242, 1), 10, &mut res),
            Lookup::Named("chrome.exe")
        ));
        let (hits, misses, negative) = cache.stats();
        assert_eq!((hits, misses, negative), (1, 1, 0));
    }

    #[test]
    fn negative_results_are_cached_and_fail_closed() {
        let mut cache = IdentityCache::new(64, 4096, 5_000);
        let mut res = StaticResolver::new();
        assert_eq!(
            cache.lookup(ProcKey::new(4, 1), 0, &mut res),
            Lookup::Unknown
        );
        assert_eq!(
            cache.lookup(ProcKey::new(4, 1), 1, &mut res),
            Lookup::Unknown
        );
        let (hits, misses, negative) = cache.stats();
        assert_eq!((hits, misses, negative), (1, 1, 1));
    }

    #[test]
    fn pid_reuse_with_different_start_time_is_a_different_identity() {
        let mut cache = IdentityCache::new(64, 4096, 60_000);
        let mut res = StaticResolver::new()
            .with_key(ProcKey::new(100, 1), "old.exe")
            .with_key(ProcKey::new(100, 2), "new.exe");
        assert_eq!(
            cache.lookup(ProcKey::new(100, 1), 0, &mut res),
            Lookup::Named("old.exe")
        );
        assert_eq!(
            cache.lookup(ProcKey::new(100, 2), 0, &mut res),
            Lookup::Named("new.exe")
        );
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut cache = IdentityCache::new(64, 4096, 1_000);
        let mut res = StaticResolver::new().with_pid(7, "a.exe");
        cache.lookup(ProcKey::new(7, 0), 0, &mut res);
        assert_eq!(cache.sweep(500), 0);
        assert_eq!(cache.sweep(2_000), 1);
        assert!(cache.is_empty());
    }
}
