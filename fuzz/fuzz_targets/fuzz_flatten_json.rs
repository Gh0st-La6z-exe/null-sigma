#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the JSON flattening layer with arbitrary bytes.
//
// Targets:
//   - serde_json parsing of hostile input (handled: typed Parse error)
//   - recursive flattening of legal-but-adversarial structures
//     (deep nesting, huge arrays, exotic keys, numeric extremes)
//   - the depth/field guards — they must reject via typed error, never
//     panic, hang, or overflow the stack
//
// Invariant: `flatten_str` returns Ok or FlattenError for ANY input.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = null_sigma::json::flatten_str(text);
    }
});
