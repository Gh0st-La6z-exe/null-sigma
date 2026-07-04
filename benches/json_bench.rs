//! Benchmarks for the `json` ingestion feature.
//!
//! Quantifies (1) the raw flattening cost for a realistic nested event and
//! (2) the total overhead of `evaluate_json` versus evaluating the same
//! pre-flattened event, so the layer's price is measured, not assumed.
//!
//! Run with: `cargo bench --features json --bench json_bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use null_sigma::json::flatten_str;
use null_sigma::SigmaEngine;

/// Realistic ECS-shaped process event: ~30 flattened fields, 4 levels deep,
/// one multi-value array — the shape the layer is designed for.
const ECS_EVENT: &str = r#"{
  "@timestamp": "2026-07-04T14:23:11.482Z",
  "event": {"category": "process", "type": "start", "kind": "event", "module": "endpoint"},
  "host": {
    "name": "ws-finance-042",
    "os": {"family": "windows", "version": "10.0.22631"},
    "ip": ["10.20.30.42", "fe80::1"]
  },
  "user": {"name": "j.doe", "domain": "CORP", "id": "S-1-5-21-3623811015-3361044348-30300820-1013"},
  "process": {
    "pid": 6244,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
    "args": ["-NoProfile", "-EncodedCommand", "SQBFAFgA"],
    "parent": {
      "pid": 5120,
      "name": "cmd.exe",
      "executable": "C:\\Windows\\System32\\cmd.exe",
      "command_line": "cmd.exe /c start.bat"
    },
    "hash": {
      "md5": "e930b05efe23891d19bc354a4209be3e",
      "sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c"
    }
  },
  "network": {"direction": "outbound", "transport": "tcp"},
  "destination": {"ip": "203.0.113.44", "port": 443}
}"#;

const RULE: &str = r#"
title: Encoded PowerShell via JSON
logsource: {}
detection:
    sel:
        process.command_line|contains: '-EncodedCommand'
    condition: sel
"#;

fn bench_flatten(c: &mut Criterion) {
    c.bench_function("flatten_ecs_event_30_fields", |b| {
        b.iter(|| flatten_str(black_box(ECS_EVENT)).unwrap());
    });
}

fn bench_evaluate_json_vs_preflattened(c: &mut Criterion) {
    let mut engine = SigmaEngine::new();
    engine.load_rule(RULE).unwrap();

    c.bench_function("evaluate_json_ecs_event", |b| {
        b.iter(|| engine.evaluate_json(black_box(ECS_EVENT)).unwrap());
    });

    let flattened = flatten_str(ECS_EVENT).unwrap();
    c.bench_function("evaluate_preflattened_ecs_event", |b| {
        b.iter(|| engine.evaluate_event(black_box(&flattened)));
    });
}

criterion_group!(benches, bench_flatten, bench_evaluate_json_vs_preflattened);
criterion_main!(benches);
