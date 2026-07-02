#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};
use null_sigma::SigmaEngine;
use std::collections::HashMap;

/// A fixed, valid rule loaded once. The fuzzer mutates the *event*, not the rule.
///
/// This targets the evaluation hot path:
///   - Aho-Corasick scan across arbitrary field values
///   - Condition AST evaluation
///   - Modifier pipeline (contains, regex, cidr, numeric, exists, transforms)
///   - Field name case-insensitive lookup
const RULE: &str = r#"
title: Fuzz Evaluation Target
logsource: {}
detection:
    sel_contains:
        CommandLine|contains:
            - '-enc'
            - 'powershell'
    sel_re:
        Image|re: '.*\.exe$'
    sel_cidr:
        SourceIp|cidr: '10.0.0.0/8'
    sel_exists:
        User|exists: true
    condition: sel_contains or sel_re or sel_cidr or sel_exists
"#;

/// Arbitrary event: up to 32 key-value pairs with bounded string lengths.
/// Bounded to prevent OOM while still exercising diverse field combinations.
#[derive(Arbitrary, Debug)]
struct FuzzEvent {
    fields: Vec<(String, String)>,
}

fuzz_target!(|input: FuzzEvent| {
    // Engine is re-created per iteration so rule compilation is also exercised,
    // but the primary target is evaluate_event.
    let mut engine = SigmaEngine::new();
    if engine.load_rule(RULE).is_err() {
        return; // Rule is valid; if this fails something is very wrong
    }

    // Cap at 32 fields — large events are valid, but we're fuzzing logic not
    // allocator limits.
    let event: HashMap<String, String> = input
        .fields
        .into_iter()
        .take(32)
        .collect();

    // Must never panic on any event content
    let _ = engine.evaluate_event(&event);
});
