//! Token slab: opaque per-packet handles, preallocated.
//!
//! The engine's retention buffer stores a `u64` token per retained packet. On
//! Windows that token is an index into this slab, which holds the 80-byte
//! `WINDIVERT_ADDRESS` that must be handed back verbatim on send. Allocating a
//! `Vec` per packet (as the original did with its `PacketWrapper` class) means
//! one allocation per packet and one GC object per packet; a free-list in a
//! fixed array means none.
//!
//! `T: Copy + Default` keeps this usable in tests with `()`.

/// Fixed-capacity index allocator over `T`.
#[derive(Debug)]
pub struct TokenSlab<T: Copy + Default> {
    slots: Vec<T>,
    used: Vec<bool>,
    free_head: Option<u32>,
    len: usize,
    exhausted: u64,
}

impl<T: Copy + Default> TokenSlab<T> {
    /// Create a slab holding `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(16);
        let mut used = vec![false; capacity];
        // Link the free list: slot i points at i+1 (implicit) so we can walk it.
        used.shrink_to_fit();
        Self {
            slots: vec![T::default(); capacity],
            used,
            free_head: Some(0),
            len: 0,
            exhausted: 0,
        }
    }

    /// Capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Entries currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Nothing held?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Times an allocation failed because the slab was full.
    #[must_use]
    pub const fn exhausted(&self) -> u64 {
        self.exhausted
    }

    /// Store `value`, returning its token (`u64::MAX` when full).
    pub fn alloc(&mut self, value: T) -> u64 {
        let Some(idx) = self.free_head else {
            self.exhausted += 1;
            return u64::MAX;
        };
        // Find the next free slot. `step` runs *past* the slot table so that a
        // slab with exactly one free slot (this one) correctly reports "full"
        // rather than handing out the same index twice.
        let n = self.slots.len();
        let mut next = None;
        for step in 1..=n {
            if step == n {
                break;
            }
            let cand = (idx as usize + step) % n;
            if !self.used[cand] {
                next = Some(cand as u32);
                break;
            }
        }
        self.used[idx as usize] = true;
        self.slots[idx as usize] = value;
        self.len += 1;
        self.free_head = next;
        idx as u64
    }

    /// Borrow a stored value.
    #[must_use]
    pub fn get(&self, token: u64) -> Option<&T> {
        let idx = token as usize;
        if idx < self.slots.len() && self.used[idx] {
            Some(&self.slots[idx])
        } else {
            None
        }
    }

    /// Free `token`; returns the stored value.
    pub fn free(&mut self, token: u64) -> Option<T> {
        let idx = token as usize;
        if idx >= self.slots.len() || !self.used[idx] {
            return None;
        }
        self.used[idx] = false;
        self.len -= 1;
        // Push onto the free list lazily: any free slot works, so the head can
        // simply be this one when the list is empty.
        if self.free_head.is_none() {
            self.free_head = Some(idx as u32);
        }
        Some(self.slots[idx])
    }

    /// Drop everything (shutdown).
    pub fn clear(&mut self) {
        self.used.iter_mut().for_each(|u| *u = false);
        self.len = 0;
        self.free_head = Some(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_reuse() {
        let mut slab: TokenSlab<[u8; 4]> = TokenSlab::new(4);
        let a = slab.alloc([1, 2, 3, 4]);
        let b = slab.alloc([5, 6, 7, 8]);
        assert_ne!(a, b);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.get(a), Some(&[1, 2, 3, 4]));
        assert_eq!(slab.free(a), Some([1, 2, 3, 4]));
        assert_eq!(slab.len(), 1);
        let c = slab.alloc([9, 9, 9, 9]);
        assert!(c != u64::MAX);
        assert_eq!(slab.get(c), Some(&[9, 9, 9, 9]));
    }

    #[test]
    fn exhaustion_is_reported_not_panicked() {
        let mut slab: TokenSlab<u8> = TokenSlab::new(16);
        let n = slab.capacity();
        for i in 0..n {
            assert_ne!(slab.alloc(i as u8), u64::MAX);
        }
        assert_eq!(slab.alloc(1), u64::MAX);
        assert_eq!(slab.exhausted(), 1);
        assert_eq!(slab.len(), n);
    }

    #[test]
    fn double_free_is_ignored() {
        let mut slab: TokenSlab<u8> = TokenSlab::new(16);
        let t = slab.alloc(3);
        assert!(slab.free(t).is_some());
        assert!(slab.free(t).is_none());
        assert_eq!(slab.len(), 0);
    }

    #[test]
    fn churn_keeps_working() {
        let mut slab: TokenSlab<u32> = TokenSlab::new(32);
        for round in 0..1000u32 {
            let t1 = slab.alloc(round);
            let t2 = slab.alloc(round + 1);
            if t1 != u64::MAX {
                slab.free(t1);
            }
            if t2 != u64::MAX {
                slab.free(t2);
            }
        }
        assert!(slab.is_empty());
        assert_eq!(slab.exhausted(), 0);
    }
}
