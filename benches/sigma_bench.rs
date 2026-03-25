use criterion::{criterion_group, criterion_main, Criterion, black_box};
use std::collections::HashMap;
use null_sigma::SigmaEngine;

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

criterion_group!(
    benches,
    bench_single_rule_single_event,
    bench_100_rules_single_event,
    bench_1000_rules_single_event,
    bench_batch_evaluation,
);
criterion_main!(benches);
