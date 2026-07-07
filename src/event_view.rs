use crate::fold::{fold_key, fold_value};
use std::collections::HashMap;
use std::hash::BuildHasher;

/// Case-insensitive borrowed view over one event.
pub(crate) struct EventView<'a> {
    index: HashMap<String, Vec<usize>>,
    values: Vec<&'a str>,
    value_folded: Vec<Option<String>>,
}

impl<'a> EventView<'a> {
    /// Build a one-pass case-insensitive index over event keys.
    #[must_use]
    pub(crate) fn from_map<S: BuildHasher>(event: &'a HashMap<String, String, S>) -> Self {
        let mut index: HashMap<String, Vec<usize>> = HashMap::with_capacity(event.len());
        let mut values: Vec<&'a str> = Vec::with_capacity(event.len());
        let mut value_folded: Vec<Option<String>> = Vec::with_capacity(event.len());

        for (key, value) in event {
            let idx = values.len();
            values.push(value.as_str());
            value_folded.push(None);
            index.entry(fold_key(key)).or_default().push(idx);
        }

        Self {
            index,
            values,
            value_folded,
        }
    }

    /// Iterate values whose field name folds to `field_folded`.
    pub(crate) fn values_for_field<'s>(
        &'s self,
        field_folded: &'s str,
    ) -> impl Iterator<Item = (usize, &'a str)> + 's {
        self.index
            .get(field_folded)
            .into_iter()
            .flat_map(move |indices| indices.iter().copied().map(|idx| (idx, self.values[idx])))
    }

    /// Iterate all values with stable per-event indices.
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

    /// First value for a folded field name (mirrors previous first-match semantics).
    #[must_use]
    pub(crate) fn first_value_for_folded_field(&self, field_folded: &str) -> Option<&'a str> {
        self.index
            .get(field_folded)
            .and_then(|indices| indices.first().copied())
            .map(|idx| self.values[idx])
    }

    /// Lazily fold one value for repeated case-insensitive comparisons.
    #[allow(dead_code)]
    pub(crate) fn folded_value(&mut self, idx: usize) -> &str {
        if self.value_folded[idx].is_none() {
            self.value_folded[idx] = Some(fold_value(self.values[idx]));
        }
        self.value_folded[idx].as_deref().expect("just initialized")
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
}
