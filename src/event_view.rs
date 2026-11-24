use crate::fold::fold_key;
use std::collections::HashMap;
use std::hash::BuildHasher;

/// Maximum number of event fields stored on the stack without heap allocation.
pub(crate) const STACK_VALUES_CAPACITY: usize = 48;

/// Reusable thread-local scratchpad for [`EventView`] to eliminate per-event allocations.
#[derive(Debug, Default)]
pub struct EventScratch {
    /// Pooled key string allocations to avoid reallocating during key folding
    pub(crate) key_pool: Vec<String>,
    /// Pooled index vectors
    pub(crate) vec_pool: Vec<Vec<usize>>,
    /// Reusable index mapping folded key -> list of value indices in this event
    pub(crate) index: HashMap<String, Vec<usize>>,
    /// Pooled string allocations for folded values
    pub(crate) value_string_pool: Vec<String>,
    /// Reusable storage for cached folded values (Strings)
    pub(crate) value_folded: Vec<Option<String>>,
    /// Pooled char vector allocations
    pub(crate) char_vec_pool: Vec<Vec<char>>,
    /// Reusable storage for cached char vectors
    pub(crate) value_chars: Vec<Option<Vec<char>>>,
    /// Reusable storage for cached Bloom filters
    pub(crate) value_bloom: Vec<Option<crate::bloom::Bloom256>>,
}

impl EventScratch {
    /// Create a new empty [`EventScratch`].
    #[allow(dead_code)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset and recycle all event data into pools without dropping heap capacity.
    pub(crate) fn reset(&mut self) {
        for (k, mut v) in self.index.drain() {
            v.clear();
            self.vec_pool.push(v);
            self.key_pool.push(k);
        }
        for mut s in self.value_folded.drain(..).flatten() {
            s.clear();
            self.value_string_pool.push(s);
        }
        for mut v in self.value_chars.drain(..).flatten() {
            v.clear();
            self.char_vec_pool.push(v);
        }
        self.value_bloom.clear();
    }
}

/// Indirection for borrowed vs owned [`EventScratch`] references.
pub(crate) enum ScratchRef<'s> {
    Borrowed(&'s mut EventScratch),
    Owned(Box<EventScratch>),
}

impl<'s> std::ops::Deref for ScratchRef<'s> {
    type Target = EventScratch;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            ScratchRef::Borrowed(s) => s,
            ScratchRef::Owned(s) => s,
        }
    }
}

impl<'s> std::ops::DerefMut for ScratchRef<'s> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            ScratchRef::Borrowed(s) => s,
            ScratchRef::Owned(s) => s,
        }
    }
}

/// Case-insensitive borrowed view over one event.
///
/// Field names are indexed by folded key at construction. Field *values* are
/// folded (and optionally char-tokenized for wildcards) lazily on first use
/// and cached for the lifetime of the view — typically one event evaluation
/// across all rules.
pub(crate) struct EventView<'a, 's> {
    scratch: ScratchRef<'s>,
    stack_values: [&'a str; STACK_VALUES_CAPACITY],
    heap_values: Vec<&'a str>,
    total_values: usize,
    canonical_slots: [u32; 64],
    present_fields_mask: u64,
}

/// Borrowed representations of an event field value prepared for matching.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FieldInputs<'f> {
    pub(crate) raw: &'f str,
    pub(crate) folded: &'f str,
    pub(crate) chars: Option<&'f [char]>,
    pub(crate) bloom: crate::bloom::Bloom256,
}

impl<'a> EventView<'a, 'static> {
    /// Build a one-pass case-insensitive index over event keys (allocates standalone scratch).
    #[must_use]
    pub(crate) fn from_map<S: BuildHasher>(event: &'a HashMap<String, String, S>) -> Self {
        let scratch = Box::new(EventScratch::default());
        Self::build_view(ScratchRef::Owned(scratch), event)
    }
}

impl<'a, 's> EventView<'a, 's> {
    /// Build a one-pass case-insensitive index using thread-local pooled scratch (zero-allocation).
    #[must_use]
    pub(crate) fn from_scratch_and_map<S: BuildHasher>(
        scratch: &'s mut EventScratch,
        event: &'a HashMap<String, String, S>,
    ) -> Self {
        Self::build_view(ScratchRef::Borrowed(scratch), event)
    }

    fn build_view<S: BuildHasher>(
        mut scratch_ref: ScratchRef<'s>,
        event: &'a HashMap<String, String, S>,
    ) -> Self {
        scratch_ref.reset();
        let num_fields = event.len();
        scratch_ref.value_folded.resize_with(num_fields, || None);
        scratch_ref.value_chars.resize_with(num_fields, || None);
        scratch_ref.value_bloom.resize_with(num_fields, || None);

        let mut stack_values = [""; STACK_VALUES_CAPACITY];
        let mut heap_values = if num_fields > STACK_VALUES_CAPACITY {
            Vec::with_capacity(num_fields - STACK_VALUES_CAPACITY)
        } else {
            Vec::new()
        };
        let mut canonical_slots = [u32::MAX; 64];
        let mut present_fields_mask: u64 = 0;
        let mut total_values = 0;

        let mut key_buf = [0u8; 64];

        for (key, value) in event {
            let idx = total_values;
            total_values += 1;
            if idx < STACK_VALUES_CAPACITY {
                stack_values[idx] = value.as_str();
            } else {
                heap_values.push(value.as_str());
            }

            if key.len() <= 64 && key.is_ascii() {
                let kbytes = key.as_bytes();
                for (dst, &src) in key_buf[..key.len()].iter_mut().zip(kbytes) {
                    *dst = src.to_ascii_lowercase();
                }
                let folded_str = match std::str::from_utf8(&key_buf[..key.len()]) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if let Some(bit) = crate::field_mask::field_bit(folded_str) {
                    let b = bit as usize;
                    if (present_fields_mask & (1u64 << bit)) == 0 {
                        canonical_slots[b] = idx as u32;
                    } else {
                        canonical_slots[b] = u32::MAX;
                    }
                    present_fields_mask |= 1u64 << bit;
                }

                if let Some(entry) = scratch_ref.index.get_mut(folded_str) {
                    entry.push(idx);
                } else {
                    let mut k = scratch_ref.key_pool.pop().unwrap_or_default();
                    k.clear();
                    k.push_str(folded_str);
                    let mut v = scratch_ref.vec_pool.pop().unwrap_or_default();
                    v.clear();
                    v.push(idx);
                    scratch_ref.index.insert(k, v);
                }
            } else {
                let folded = fold_key(key);
                if let Some(bit) = crate::field_mask::field_bit(&folded) {
                    let b = bit as usize;
                    if (present_fields_mask & (1u64 << bit)) == 0 {
                        canonical_slots[b] = idx as u32;
                    } else {
                        canonical_slots[b] = u32::MAX;
                    }
                    present_fields_mask |= 1u64 << bit;
                }
                if let Some(entry) = scratch_ref.index.get_mut(&folded) {
                    entry.push(idx);
                } else {
                    let mut v = scratch_ref.vec_pool.pop().unwrap_or_default();
                    v.clear();
                    v.push(idx);
                    scratch_ref.index.insert(folded, v);
                }
            }
        }

        Self {
            scratch: scratch_ref,
            stack_values,
            heap_values,
            total_values,
            canonical_slots,
            present_fields_mask,
        }
    }

    /// 64-bit mask of canonical fields present in this event.
    #[inline]
    #[must_use]
    pub(crate) fn present_fields_mask(&self) -> u64 {
        self.present_fields_mask
    }

    /// Return the single value index for a canonical field bit, or `u32::MAX` if multi-value / absent.
    #[inline]
    #[must_use]
    pub(crate) fn canonical_slot(&self, bit: u8) -> u32 {
        self.canonical_slots[bit as usize]
    }

    /// Return the indices slice for a folded field, or None if absent.
    #[inline]
    #[must_use]
    pub(crate) fn field_indices(&self, field_folded: &str) -> Option<&[usize]> {
        self.scratch.index.get(field_folded).map(Vec::as_slice)
    }

    /// Total number of raw values stored in this event view.
    #[inline]
    #[must_use]
    pub(crate) fn total_values(&self) -> usize {
        self.total_values
    }

    /// Iterate values whose field name folds to `field_folded`.
    #[cfg(test)]
    pub(crate) fn values_for_field<'m>(
        &'m self,
        field_folded: &'m str,
    ) -> impl Iterator<Item = (usize, &'a str)> + 'm {
        self.scratch
            .index
            .get(field_folded)
            .into_iter()
            .flat_map(move |indices| indices.iter().copied().map(|idx| (idx, self.raw_at(idx))))
    }

    /// Copy field indices into `out` (avoids a fresh Vec alloc per condition).
    #[allow(dead_code)]
    pub(crate) fn collect_indices_for_field(&self, field_folded: &str, out: &mut Vec<usize>) {
        out.clear();
        if let Some(indices) = self.scratch.index.get(field_folded) {
            out.extend_from_slice(indices);
        }
    }

    /// Copy all value indices into `out`.
    #[allow(dead_code)]
    pub(crate) fn collect_indices_all(&self, out: &mut Vec<usize>) {
        out.clear();
        out.extend(0..self.total_values);
    }

    /// Iterate all values with stable per-event indices.
    #[cfg(test)]
    pub(crate) fn values_all(&self) -> impl Iterator<Item = (usize, &'a str)> + '_ {
        (0..self.total_values).map(|idx| (idx, self.raw_at(idx)))
    }

    /// Does at least one field with this folded name exist?
    #[must_use]
    pub(crate) fn has_field_folded(&self, field_folded: &str) -> bool {
        if let Some(bit) = crate::field_mask::field_bit(field_folded) {
            return (self.present_fields_mask & (1u64 << bit)) != 0;
        }
        self.scratch
            .index
            .get(field_folded)
            .is_some_and(|indices| !indices.is_empty())
    }

    /// First value index for a folded field name.
    #[must_use]
    pub(crate) fn first_index_for_folded_field(&self, field_folded: &str) -> Option<usize> {
        if let Some(bit) = crate::field_mask::field_bit(field_folded) {
            let slot = self.canonical_slots[bit as usize];
            if slot != u32::MAX {
                return Some(slot as usize);
            }
            if (self.present_fields_mask & (1u64 << bit)) == 0 {
                return None;
            }
        }
        self.scratch
            .index
            .get(field_folded)
            .and_then(|indices| indices.first().copied())
    }

    /// Ensure the folded (lowercased) form of `idx` is cached.
    pub(crate) fn ensure_folded(&mut self, idx: usize) {
        debug_assert!(idx < self.total_values);
        if self.scratch.value_folded[idx].is_none() {
            let raw = self.raw_at(idx);
            let mut s = self.scratch.value_string_pool.pop().unwrap_or_default();
            s.clear();
            if raw.is_ascii() {
                for b in raw.as_bytes() {
                    s.push(b.to_ascii_lowercase() as char);
                }
            } else {
                for c in raw.chars() {
                    for lc in c.to_lowercase() {
                        s.push(lc);
                    }
                }
            }
            self.scratch.value_folded[idx] = Some(s);
        }
    }

    /// Borrow the cached folded value. Call [`Self::ensure_folded`] first.
    #[must_use]
    pub(crate) fn folded_at(&self, idx: usize) -> &str {
        self.scratch.value_folded[idx]
            .as_deref()
            .expect("ensure_folded must be called before folded_at")
    }

    /// Ensure `idx` has a char vector of its folded form (for wildcard matching).
    pub(crate) fn ensure_chars(&mut self, idx: usize) {
        self.ensure_folded(idx);
        if self.scratch.value_chars[idx].is_none() {
            let mut v = self.scratch.char_vec_pool.pop().unwrap_or_default();
            v.clear();
            let folded = self.scratch.value_folded[idx]
                .as_deref()
                .expect("ensure_folded just ran");
            v.extend(folded.chars());
            self.scratch.value_chars[idx] = Some(v);
        }
    }

    /// Ensure the Sub-256 bigram bloom filter for `idx` is computed and cached.
    pub(crate) fn ensure_bloom(&mut self, idx: usize) {
        debug_assert!(idx < self.total_values);
        if self.scratch.value_bloom[idx].is_none() {
            let raw = self.raw_at(idx);
            self.scratch.value_bloom[idx] = Some(crate::bloom::compute_bloom256(raw));
        }
    }

    /// Borrow the cached Sub-256 bloom mask. Call [`Self::ensure_bloom`] first.
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn bloom_at(&self, idx: usize) -> crate::bloom::Bloom256 {
        self.scratch.value_bloom[idx].expect("ensure_bloom must be called before bloom_at")
    }

    /// Borrow the cached folded char vector. Call [`Self::ensure_chars`] first.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn chars_at(&self, idx: usize) -> &[char] {
        self.scratch.value_chars[idx]
            .as_deref()
            .expect("ensure_chars must be called before chars_at")
    }

    /// Raw (unfolded) event value at `idx`.
    #[inline]
    #[must_use]
    pub(crate) fn raw_at(&self, idx: usize) -> &'a str {
        if idx < STACK_VALUES_CAPACITY {
            self.stack_values[idx]
        } else {
            self.heap_values[idx - STACK_VALUES_CAPACITY]
        }
    }

    /// Borrow raw + folded (+ optional chars) + Sub-256 bloom mask after caches are prepared.
    ///
    /// Returns a [`FieldInputs`] view over the value at `idx`.
    #[must_use]
    pub(crate) fn match_inputs(&self, idx: usize, with_chars: bool) -> FieldInputs<'_> {
        let raw = self.raw_at(idx);
        let folded = self.scratch.value_folded[idx]
            .as_deref()
            .expect("ensure_folded/ensure_chars must run before match_inputs");
        let chars = if with_chars {
            Some(
                self.scratch.value_chars[idx]
                    .as_deref()
                    .expect("ensure_chars must run before match_inputs(with_chars)"),
            )
        } else {
            None
        };
        let bloom = self.scratch.value_bloom[idx].unwrap_or(crate::bloom::Bloom256::ZERO);
        FieldInputs {
            raw,
            folded,
            chars,
            bloom,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EventView;
    use std::collections::HashMap;

    #[test]
    fn duplicate_case_keys_are_preserved() {
        let mut event = HashMap::new();
        event.insert("Image".to_string(), "A".to_string());
        event.insert("image".to_string(), "B".to_string());
        event.insert("Other".to_string(), "C".to_string());

        let view = EventView::from_map(&event);
        let mut vals: Vec<&str> = view.values_for_field("image").map(|(_, v)| v).collect();
        vals.sort_unstable();
        assert_eq!(vals, vec!["A", "B"]);
    }

    #[test]
    fn keyword_iteration_covers_all_values() {
        let mut event = HashMap::new();
        event.insert("A".to_string(), "1".to_string());
        event.insert("B".to_string(), "2".to_string());
        event.insert("C".to_string(), "3".to_string());
        let view = EventView::from_map(&event);
        assert_eq!(view.values_all().count(), 3);
    }

    #[test]
    fn folded_value_is_cached_and_case_folded() {
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "PowerShell -ENC".to_string());
        let mut view = EventView::from_map(&event);
        let idx = view.values_for_field("commandline").next().unwrap().0;
        view.ensure_folded(idx);
        assert_eq!(view.folded_at(idx), "powershell -enc");
        // Second call must return the same cached string (pointer-stable after ensure).
        let ptr1 = view.folded_at(idx).as_ptr();
        let ptr2 = view.folded_at(idx).as_ptr();
        assert_eq!(ptr1, ptr2);
    }

    #[test]
    fn chars_cache_matches_folded_string() {
        let mut event = HashMap::new();
        event.insert("Image".to_string(), "TeSt.EXE".to_string());
        let mut view = EventView::from_map(&event);
        let idx = view.values_for_field("image").next().unwrap().0;
        view.ensure_chars(idx);
        let expected: Vec<char> = "test.exe".chars().collect();
        assert_eq!(view.chars_at(idx), expected.as_slice());
    }

    #[test]
    fn present_fields_mask_matches_canonical_keys() {
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "foo".to_string());
        event.insert("Image".to_string(), "bar".to_string());
        event.insert("CustomNonCanonicalField".to_string(), "baz".to_string());

        let view = EventView::from_map(&event);
        let mask = view.present_fields_mask();

        let cmdline_bit = crate::field_mask::field_bit("commandline").unwrap();
        let image_bit = crate::field_mask::field_bit("image").unwrap();

        assert_ne!(mask & (1 << cmdline_bit), 0);
        assert_ne!(mask & (1 << image_bit), 0);
        assert_eq!(mask, (1 << cmdline_bit) | (1 << image_bit));
    }

    #[test]
    fn bloom_filter_is_cached_and_consistent() {
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "cmd.exe /c echo hi".to_string());
        let mut view = EventView::from_map(&event);
        let idx = view.values_for_field("commandline").next().unwrap().0;
        view.ensure_bloom(idx);
        let b = view.bloom_at(idx);
        assert!(!b.is_empty());
        let needle_b = crate::bloom::compute_bloom256("echo hi");
        assert!(needle_b.is_subset_of(&b));
    }
}
