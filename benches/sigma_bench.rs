use criterion::{criterion_group, criterion_main, Criterion, black_box};
use std::collections::HashMap;
use null_sigma::{SigmaEngine, FieldMapping};

fn bench_single_rule_single_event(c: &mut Criterion) {
    let rule_yaml = r#"
title: Suspicious PowerShell Encoded Command
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-encodedcommand'
            - '-enc'
            - '-ec'
        Image|endswith: '\powershell.exe'
    condition: selection
"#;

    let mut engine = SigmaEngine::new();
    engine.load_rule(rule_yaml).unwrap();

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("commandline".to_string(), "powershell.exe -enc SQBFAFgA".to_string());
    event.insert("image".to_string(), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string());
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("single_rule_single_event", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

fn bench_100_rules_single_event(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    // Load 100 rules with unique patterns
    for i in 0..100 {
        let rule_yaml = format!(
            r#"
title: Test Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("commandline".to_string(), "cmd.exe /c pattern_42 something".to_string());
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("100_rules_single_event", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

fn bench_1000_rules_single_event(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    for i in 0..1000 {
        let rule_yaml = format!(
            r#"
title: Test Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("commandline".to_string(), "cmd.exe /c pattern_500 something".to_string());
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("1000_rules_single_event", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

fn bench_1000_rules_mixed_field_noise_single_event(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    // Load 1000 rules distributed across different fields.
    for i in 0..1000 {
        let field = match i % 4 {
            0 => "CommandLine",
            1 => "Image",
            2 => "ParentImage",
            _ => "User",
        };

        let rule_yaml = format!(
            r#"
title: Mixed Field Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        {field}|contains: 'pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    // Add unrelated-field noise containing many rule-like patterns.
    let noise_payload = (0..300)
        .map(|i| format!("pattern_{i}"))
        .collect::<Vec<String>>()
        .join(" ");

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("commandline".to_string(), "cmd.exe /c pattern_500 something".to_string());
    event.insert(
        "image".to_string(),
        "C:\\Windows\\System32\\notepad.exe".to_string(),
    );
    event.insert(
        "parentimage".to_string(),
        "C:\\Windows\\explorer.exe".to_string(),
    );
    event.insert("user".to_string(), "SYSTEM".to_string());
    event.insert("message".to_string(), noise_payload);
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("1000_rules_mixed_field_noise_single_event", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

fn bench_batch_evaluation(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    for i in 0..100 {
        let rule_yaml = format!(
            r#"
title: Test Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    // Create 100 events, some matching
    let events: Vec<HashMap<String, String>> = (0..100)
        .map(|i| {
            let mut e = HashMap::new();
            e.insert("commandline".to_string(), format!("cmd.exe /c pattern_{i}"));
            e.insert("event_category".to_string(), "process_creation".to_string());
            e.insert("event_product".to_string(), "windows".to_string());
            e
        })
        .collect();

    c.bench_function("100_rules_100_events_batch", |b| {
        b.iter(|| {
            black_box(engine.evaluate_batch(black_box(&events)));
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Blind-spot benchmarks — scenarios not covered by the original suite
// ─────────────────────────────────────────────────────────────────────────────

/// 1000 rules loaded, event whose logsource doesn't match ANY rule.
///
/// This is the most common production case: most events are benign and belong
/// to a log category that has no loaded rules. The engine should reject all
/// 1000 rules in the hot loop (3 integer comparisons each) without touching
/// any cold CompiledRule data.
///
/// Expected: well under 10 µs — if it exceeds the `1000_rules_single_event`
/// time the logsource prefilter isn't working.
fn bench_1000_rules_logsource_mismatch(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    for i in 0..1000 {
        let rule_yaml = format!(
            r#"
title: Windows Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    // Event from a completely different log source — should skip all 1000 rules
    // after the first integer comparison in the hot loop.
    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("query_name".to_string(), "evil.example.com".to_string());
    event.insert("event_category".to_string(), "dns_query".to_string());
    event.insert("event_product".to_string(), "linux".to_string());

    c.bench_function("1000_rules_logsource_mismatch", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

/// 1000 rules loaded, event with the right logsource but no matching AC pattern.
///
/// This measures the cost of the full hot loop (logsource check PASSES for all
/// 1000 rules) followed by the AC prefilter rejecting them all. No rule reaches
/// the cold evaluation path.
///
/// Expected: faster than `1000_rules_single_event` (AC reject is cheaper than
/// full condition eval) but slower than `logsource_mismatch` (more work per rule).
fn bench_1000_rules_ac_prefilter_zero_match(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    for i in 0..1000 {
        let rule_yaml = format!(
            r#"
title: Rule {i}
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'unique_pattern_{i}'
    condition: selection
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    // Event with the right logsource but a command line containing no rule patterns.
    let mut event: HashMap<String, String> = HashMap::new();
    event.insert(
        "commandline".to_string(),
        "C:\\Windows\\System32\\svchost.exe -k netsvcs".to_string(),
    );
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("1000_rules_ac_prefilter_zero_match", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

/// 100 rules where every rule uses `|re` (regex modifier).
///
/// Before the regex-cache fix, each `|re` condition called `regex::Regex::new()`
/// on every event — compiling the pattern from scratch every time.  After the
/// fix, pre-compiled `Regex` objects are looked up from the per-rule cache.
///
/// This benchmark makes the improvement visible and detects any future
/// regression that accidentally bypasses the cache path.
fn bench_100_regex_rules_single_event(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();

    // 100 rules each with a non-trivial regex pattern (no AC prefilter applies
    // to regex rules — they always reach the full eval path).
    let patterns = [
        r"powershell\s+-(enc|encodedcommand)\s+[A-Za-z0-9+/]+=*",
        r"cmd(\.exe)?\s+/[cCkK]\s+",
        r"wscript(\.exe)?\s+.*\.(vbs|js|jse|vbe)\b",
        r"mshta(\.exe)?\s+.*(http|vbscript|javascript):",
        r"regsvr32(\.exe)?\s+.*/[sS]\s+.*\.(dll|ocx|ax)\b",
        r"rundll32(\.exe)?\s+.*,\s*[A-Za-z]",
        r"certutil(\.exe)?\s+.*(-(decode|encode|urlcache|-f)\b)",
        r"bitsadmin(\.exe)?\s+.*/transfer\b",
        r"net(\.exe)?\s+(user|group|localgroup)\s+",
        r"schtasks(\.exe)?\s+(/create|/run|/query)\b",
    ];

    for i in 0..100 {
        let pattern = patterns[i % patterns.len()];
        let rule_yaml = format!(
            r#"
title: Regex Rule {i}
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|re: '{pattern}'
    condition: sel
"#
        );
        engine.load_rule(&rule_yaml).unwrap();
    }

    // Command line that matches ~10% of the patterns.
    let mut event: HashMap<String, String> = HashMap::new();
    event.insert(
        "commandline".to_string(),
        "powershell.exe -encodedcommand SQBFAFgAKABOAGUAdAAgACcAaAB0AHQAcAA6AC8ALwBiAGEAZAA".to_string(),
    );
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(), "windows".to_string());

    c.bench_function("100_regex_rules_single_event", |b| {
        b.iter(|| {
            black_box(engine.evaluate_event(black_box(&event)));
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// enrich_event isolation — measures allocation cost on the hot path
// ─────────────────────────────────────────────────────────────────────────────

/// Event with Sigma-canonical field names (e.g., "commandline" not "command_line").
/// After the Cow fix, `enrich_event_cow` returns `Borrowed` here — zero allocation.
/// This is the most common production case for a Rust-native event producer.
fn bench_enrich_event_sigma_keys(c: &mut Criterion) {
    let mapping = FieldMapping::new();

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("commandline".to_string(),    "powershell.exe -enc SQBFAFgA".to_string());
    event.insert("image".to_string(),          "C:\\Windows\\System32\\powershell.exe".to_string());
    event.insert("parentimage".to_string(),    "C:\\Windows\\explorer.exe".to_string());
    event.insert("user".to_string(),           "DESKTOP\\user".to_string());
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(),  "windows".to_string());

    c.bench_function("enrich_event_cow_sigma_keys_borrowed", |b| {
        b.iter(|| {
            black_box(mapping.enrich_event_cow(black_box(&event)));
        })
    });
}

/// Event with application canonical snake_case field names (e.g., "command_line").
/// `enrich_event_cow` must add Sigma-canonical aliases — allocates once (Owned).
/// This is the path taken when events arrive pre-translated by the ingestion layer.
fn bench_enrich_event_canonical_keys(c: &mut Criterion) {
    let mapping = FieldMapping::new();

    let mut event: HashMap<String, String> = HashMap::new();
    event.insert("command_line".to_string(),   "powershell.exe -enc SQBFAFgA".to_string());
    event.insert("image".to_string(),          "C:\\Windows\\System32\\powershell.exe".to_string());
    event.insert("parent_image".to_string(),   "C:\\Windows\\explorer.exe".to_string());
    event.insert("user".to_string(),           "DESKTOP\\user".to_string());
    event.insert("event_category".to_string(), "process_creation".to_string());
    event.insert("event_product".to_string(),  "windows".to_string());

    c.bench_function("enrich_event_cow_canonical_keys_owned", |b| {
        b.iter(|| {
            black_box(mapping.enrich_event_cow(black_box(&event)));
        })
    });
}

criterion_group!(
    benches,
    bench_single_rule_single_event,
    bench_100_rules_single_event,
    bench_1000_rules_single_event,
    bench_1000_rules_mixed_field_noise_single_event,
    bench_batch_evaluation,
    bench_1000_rules_logsource_mismatch,
    bench_1000_rules_ac_prefilter_zero_match,
    bench_100_regex_rules_single_event,
    bench_enrich_event_sigma_keys,
    bench_enrich_event_canonical_keys,
);
criterion_main!(benches);
