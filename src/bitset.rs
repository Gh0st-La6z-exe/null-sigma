// =============================================================================
// Sigma Rule Engine — Dense Rule Bitset for Zero-Allocation Dispatch
// =============================================================================
// Provides a cache-friendly dense bitset for tracking candidate rule sets.
//
// At 64 rules per `u64` word, a corpus of 1,200 rules occupies only 19 words
// (152 bytes) — fitting entirely within 2.3 CPU L1 cachelines.
//
// Bitwise unions (`|`) and intersections (`& !`) execute directly in CPU registers,
// eliminating slice deduplication, duplicate rule evaluations, and memory scattering.
// =============================================================================

/// A dense bitset indexed by rule identifier position (`0..rule_count`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleBitSet {
    words: Vec<u64>,
}

impl RuleBitSet {
    /// Create a new bitset pre-allocated to hold up to `num_rules` rules.
    #[must_use]
    pub fn with_capacity_rules(num_rules: usize) -> Self {
        let num_words = num_rules.div_ceil(64);
        Self {
            words: vec![0u64; num_words],
        }
    }

    /// Mark rule `rule_idx` as present in the bitset.
    #[inline]
    pub fn set(&mut self, rule_idx: usize) {
        let word_idx = rule_idx / 64;
        let bit_idx = rule_idx % 64;
        if word_idx >= self.words.len() {
            self.words.resize(word_idx + 1, 0);
        }
        self.words[word_idx] |= 1u64 << bit_idx;
    }

    /// Check if rule `rule_idx` is set in this bitset.
    #[inline]
    #[must_use]
    pub fn contains(&self, rule_idx: usize) -> bool {
        let word_idx = rule_idx / 64;
        let bit_idx = rule_idx % 64;
        if word_idx < self.words.len() {
            (self.words[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// In-place bitwise union: `self = self | other`.
    #[inline]
    pub fn union_with(&mut self, other: &RuleBitSet) {
        if other.words.len() > self.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (w1, w2) in self.words.iter_mut().zip(&other.words) {
            *w1 |= *w2;
        }
    }

    /// In-place bitwise difference: `self = self & !other`.
    ///
    /// Clears any bits in `self` that are set in `other`.
    #[inline]
    pub fn intersect_not(&mut self, other: &RuleBitSet) {
        let len = self.words.len().min(other.words.len());
        for (w1, w2) in self.words[..len].iter_mut().zip(&other.words[..len]) {
            *w1 &= !*w2;
        }
    }

    /// Reset all bits to 0 without freeing the allocated word storage.
    #[inline]
    pub fn clear(&mut self) {
        self.words.fill(0);
    }

    /// Overwrite this bitset's contents with `other`, reusing existing word capacity.
    #[inline]
    pub fn copy_from(&mut self, other: &RuleBitSet) {
        self.words.clone_from(&other.words);
    }

    /// Returns a slice of the underlying 64-bit words.
    #[inline]
    #[must_use]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Returns true if no bits are set in the bitset.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Returns the number of set bits (rules) in this bitset.
    #[inline]
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Iterate over the indices of all set bits in ascending order.
    ///
    /// Uses CPU intrinsic `trailing_zeros` (`TZCNT`) and `w &= w - 1` (`BLSR`)
    /// to jump directly to set bits in $O(K)$ time where $K$ is the number of set bits.
    #[inline]
    #[must_use]
    pub fn iter_set_bits(&self) -> SetBitIter<'_> {
        SetBitIter {
            words: &self.words,
            word_idx: 0,
            current_word: self.words.first().copied().unwrap_or(0),
        }
    }
}

/// Zero-allocation iterator over set bit indices of a [`RuleBitSet`].
pub struct SetBitIter<'a> {
    words: &'a [u64],
    word_idx: usize,
    current_word: u64,
}

impl Iterator for SetBitIter<'_> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.current_word == 0 {
            self.word_idx += 1;
            if self.word_idx >= self.words.len() {
                return None;
            }
            self.current_word = self.words[self.word_idx];
        }

        let bit = self.current_word.trailing_zeros();
        let idx = self.word_idx * 64 + bit as usize;
        self.current_word &= self.current_word - 1; // BLSR: reset lowest set bit
        Some(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_contains() {
        let mut bs = RuleBitSet::default();
        assert!(!bs.contains(0));
        assert!(!bs.contains(63));
        assert!(!bs.contains(64));
        assert!(!bs.contains(1200));

        bs.set(0);
        bs.set(63);
        bs.set(64);
        bs.set(1200);

        assert!(bs.contains(0));
        assert!(bs.contains(63));
        assert!(bs.contains(64));
        assert!(bs.contains(1200));
        assert!(!bs.contains(1));
        assert!(!bs.contains(65));
    }

    #[test]
    fn test_iter_set_bits() {
        let mut bs = RuleBitSet::with_capacity_rules(200);
        let indices = vec![0, 1, 5, 63, 64, 65, 127, 128, 199];
        for &idx in &indices {
            bs.set(idx);
        }

        let collected: Vec<usize> = bs.iter_set_bits().collect();
        assert_eq!(collected, indices);
    }

    #[test]
    fn test_union_with() {
        let mut a = RuleBitSet::default();
        let mut b = RuleBitSet::default();

        a.set(1);
        a.set(100);
        b.set(2);
        b.set(100);
        b.set(200);

        a.union_with(&b);

        let collected: Vec<usize> = a.iter_set_bits().collect();
        assert_eq!(collected, vec![1, 2, 100, 200]);
    }

    #[test]
    fn test_intersect_not() {
        let mut a = RuleBitSet::default();
        let mut b = RuleBitSet::default();

        a.set(1);
        a.set(2);
        a.set(3);
        a.set(100);

        b.set(2);
        b.set(100);
        b.set(200);

        a.intersect_not(&b);

        let collected: Vec<usize> = a.iter_set_bits().collect();
        assert_eq!(collected, vec![1, 3]);
    }

    #[test]
    fn test_count_ones_and_empty() {
        let mut bs = RuleBitSet::default();
        assert!(bs.is_empty());
        assert_eq!(bs.count_ones(), 0);

        bs.set(5);
        bs.set(150);
        assert!(!bs.is_empty());
        assert_eq!(bs.count_ones(), 2);

        let mut copied = RuleBitSet::default();
        copied.copy_from(&bs);
        assert_eq!(copied.count_ones(), 2);
        assert!(copied.contains(5));
        assert!(copied.contains(150));

        bs.clear();
        assert!(bs.is_empty());
        assert_eq!(bs.count_ones(), 0);
    }
}
