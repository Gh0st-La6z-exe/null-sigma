use crate::fold::{fold_key, fold_value};
use std::collections::HashMap;
use std::hash::BuildHasher;

/// Case-insensitive borrowed view over one event.
///
/// Field names are indexed by folded key at construction. Field *values* are
/// folded (and optionally char-tokenized for wildcards) lazily on first use
/// and cached for the lifetime of the view — typically one event evaluation
/// across all rules.
pub(crate) struct EventView<'a> {
    index: HashMap<String, Vec<usize>>,
    values: Vec<&'a str>,
    value_folded: Vec<Option<String>>,
    value_chars: Vec<Option<Vec<char>>>,
}

impl<'a> EventView<'a> {
    /// Build a one-pass case-insensitive index over event keys.
    #[must_use]
    pub(crate) fn from_map<S: BuildHasher>(event: &'a HashMap<String, String, S>) -> Self {
        let mut index: HashMap<String, Vec<usize>> = HashMap::with_capacity(event.len());
        let mut values: Vec<&'a str> = Vec::with_capacity(event.len());
        let mut value_folded: Vec<Option<String>> = Vec::with_capacity(event.len());
        let mut value_chars: Vec<Option<Vec<char>>> = Vec::with_capacity(event.len());

        for (key, value) in event {
            let idx = values.len();
            values.push(value.as_str());
            value_folded.push(None);
            value_chars.push(None);
            index.entry(fold_key(key)).or_default().push(idx);
        }

        Self {
            index,
            values,
            value_folded,
            value_chars,
        }
    }

    /// Iterate values whose field name folds to `field_folded`.
    #[cfg(test)]
    pub(crate) fn values_for_field<'s>(
        &'s self,
        field_folded: &'s str,
    ) -> impl Iterator<Item = (usize, &'a str)> + 's {
        self.index
            .get(field_folded)
            .into_iter()
            .flat_map(move |indices| indices.iter().copied().map(|idx| (idx, self.values[idx])))
    }

    /// Copy field indices into `out` (avoids a fresh Vec alloc per condition).
    pub(crate) fn collect_indices_for_field(&self, field_folded: &str, out: &mut Vec<usize>) {
        out.clear();
        if let Some(indices) = self.index.get(field_folded) {
            out.extend_from_slice(indices);
        }
    }

    /// Copy all value indices into `out`.
    pub(crate) fn collect_indices_all(&self, out: &mut Vec<usize>) {
        out.clear();
        out.extend(0..self.values.len());
    }

    /// Iterate all values with stable per-event indices.
    #[cfg(test)]
    pub(crate) fn values_all(&self) -> impl Iterator<Item = (usize, &'a str)> + '_ {
        self.values.iter().enumerate().map(|(idx, v)| (idx, *v))
    }

    /// Does at least one field with this folded name exist?
    #[must_use]
    pub(crate) fn has_field_folded(&self, field_folded: &str) -> bool {
        self.index
            .get(field_folded)
            .is_some_and(|indices| !indices.is_empty())
    }

    /// First value index for a folded field name.
    #[must_use]
    pub(crate) fn first_index_for_folded_field(&self, field_folded: &str) -> Option<usize> {
        self.index
            .get(field_folded)
            .and_then(|indices| indices.first().copied())
    }

    /// Ensure the folded (lowercased) form of `idx` is cached.
    pub(crate) fn ensure_folded(&mut self, idx: usize) {
        debug_assert!(idx < self.values.len());
        if self.value_folded[idx].is_none() {
            self.value_folded[idx] = Some(fold_value(self.values[idx]));
        }
    }

    /// Borrow the cached folded value. Call [`Self::ensure_folded`] first.
    #[must_use]
    pub(crate) fn folded_at(&self, idx: usize) -> &str {
        self.value_folded[idx]
            .as_deref()
            .expect("ensure_folded must be called before folded_at")
    }

    /// Ensure `idx` has a char vector of its folded form (for wildcard matching).
    pub(crate) fn ensure_chars(&mut self, idx: usize) {
        self.ensure_folded(idx);
        if self.value_chars[idx].is_none() {
            let folded = self.value_folded[idx]
                .as_deref()
                .expect("ensure_folded just ran");
            self.value_chars[idx] = Some(folded.chars().collect());
        }
    }

    /// Borrow the cached folded char vector. Call [`Self::ensure_chars`] first.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn chars_at(&self, idx: usize) -> &[char] {
        self.value_chars[idx]
            .as_deref()
            .expect("ensure_chars must be called before chars_at")
    }

    /// Raw (unfolded) event value at `idx`.
    #[must_use]
    pub(crate) fn raw_at(&self, idx: usize) -> &'a str {
        self.values[idx]
    }

    /// Borrow raw + folded (+ optional chars) after caches are prepared.
    ///
    /// Returns `(raw, folded, chars)` where `chars` is `Some` when the char
    /// cache slot for `idx` is populated (i.e. after [`Self::ensure_chars`]).
    #[must_use]
    pub(crate) fn match_inputs(
        &self,
        idx: usize,
        with_chars: bool,
    ) -> (&'a str, &str, Option<&[char]>) {
        let raw = self.values[idx];
        let folded = self.value_folded[idx]
            .as_deref()
            .expect("ensure_folded/ensure_chars must run before match_inputs");
        let chars = if with_chars {
            Some(
                self.value_chars[idx]
                    .as_deref()
                    .expect("ensure_chars must run before match_inputs(with_chars)"),
            )
        } else {
            None
        };
        (raw, folded, chars)
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
}
