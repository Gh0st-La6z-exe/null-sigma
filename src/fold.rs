/// Fold event/rule field keys for case-insensitive matching.
#[must_use]
pub(crate) fn fold_key(s: &str) -> String {
    s.to_lowercase()
}

/// Fold string values for case-insensitive matching.
#[must_use]
pub(crate) fn fold_value(s: &str) -> String {
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{fold_key, fold_value};

    #[test]
    fn fold_key_matches_std_lowercase() {
        let samples = ["CommandLine", "IMAGE", "İstanbul", "ß", "σ", "Straße"];
        for sample in samples {
            assert_eq!(fold_key(sample), sample.to_lowercase());
            assert_eq!(fold_value(sample), sample.to_lowercase());
        }
    }
}
