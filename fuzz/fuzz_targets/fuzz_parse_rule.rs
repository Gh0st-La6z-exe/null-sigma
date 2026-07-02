#![no_main]

use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to the YAML parser.
///
/// Goals:
///   - No panics on any input
///   - No stack overflows (deeply nested YAML)
///   - No OOM (very large YAML values)
///   - Parser always returns Ok or a typed ParseError, never unwinds
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic regardless of input
        let _ = null_sigma::parse_rule(s);

        // Also fuzz multi-document parsing
        let _ = null_sigma::parse_rules(s);
    }
});
