//! Tier A — matcher-level head-to-head benchmarks.
//!
//! Same rules (the common subset every engine loads), same events (seeded
//! generator), single core. Each engine receives its native pre-built event
//! representation; input preparation happens outside the timed loop.
//!
//! Run: cargo bench --bench head_to_head

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use null_sigma_harness::{gen, load_rule_dir, NullSigmaBench, SigmaRustBench, TauBench};
use serde_json::Value;

struct Setup {
    yamls: Vec<String>,
    ns: NullSigmaBench,
    tau: TauBench,
    sr: SigmaRustBench,
    /// null-sigma loaded with EVERY rule it accepts (1182/1182), not just the
    /// three-engine common set — its own full-corpus number.
    ns_full: NullSigmaBench,
    ns_full_count: usize,
    // Pre-built native event representations, index-aligned.
    ns_events: Vec<HashMap<String, String>>,
    tau_events: Vec<Value>,
    sr_events: Vec<sigma_rust::Event>,
    suspicious_idx: usize,
    benign_idx: usize,
}

fn setup() -> Setup {
    let rule_dir = null_sigma_harness::default_rule_dir();
    assert!(
        rule_dir.exists(),
        "SigmaHQ corpus not vendored at {} — clone SigmaHQ/sigma into corpus/sigmahq first",
        rule_dir.display()
    );
    let report = load_rule_dir(&rule_dir).expect("failed to read rules");
    let common = report.common();
    assert!(common.len() >= 500, "expected >= 500 common rules, got {}", common.len());

    let yamls: Vec<String> = common.iter().map(|r| r.yaml.clone()).collect();
    let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();

    let ns = NullSigmaBench::new(&refs);
    let tau = TauBench::new(&refs);
    let sr = SigmaRustBench::new(&refs);

    let full_yamls: Vec<&str> = report
        .rules
        .iter()
        .filter(|r| r.null_sigma.is_ok())
        .map(|r| r.yaml.as_str())
        .collect();
    let ns_full_count = full_yamls.len();
    let ns_full = NullSigmaBench::new(&full_yamls);

    let events = gen::generate(42, 1000);
    let ns_events: Vec<_> = events.iter().map(NullSigmaBench::prepare_event).collect();
    let tau_events: Vec<_> = events.iter().map(TauBench::prepare_event).collect();
    let sr_events: Vec<_> = events.iter().map(SigmaRustBench::prepare_event).collect();

    let suspicious_idx = events
        .iter()
        .position(|e| e["CommandLine"].as_str().unwrap().contains("-EncodedCommand"))
        .expect("no suspicious event in stream");
    let benign_idx = events
        .iter()
        .position(|e| e["Image"].as_str().unwrap().ends_with("chrome.exe"))
        .expect("no benign event in stream");

    Setup {
        yamls,
        ns,
        tau,
        sr,
        ns_full,
        ns_full_count,
        ns_events,
        tau_events,
        sr_events,
        suspicious_idx,
        benign_idx,
    }
}

fn bench_single_event(c: &mut Criterion, s: &Setup, name: &str, idx: usize) {
    let mut group = c.benchmark_group(name);
    group.bench_function(BenchmarkId::new("null_sigma", s.yamls.len()), |b| {
        let event = &s.ns_events[idx];
        b.iter(|| black_box(s.ns.count_matches(black_box(event))));
    });
    group.bench_function(BenchmarkId::new("null_sigma_full", s.ns_full_count), |b| {
        let event = &s.ns_events[idx];
        b.iter(|| black_box(s.ns_full.count_matches(black_box(event))));
    });
    group.bench_function(BenchmarkId::new("tau_engine", s.yamls.len()), |b| {
        let event = &s.tau_events[idx];
        b.iter(|| black_box(s.tau.count_matches(black_box(event))));
    });
    group.bench_function(BenchmarkId::new("sigma_rust", s.yamls.len()), |b| {
        let event = &s.sr_events[idx];
        b.iter(|| black_box(s.sr.count_matches(black_box(event))));
    });
    group.finish();
}

fn bench_batch(c: &mut Criterion, s: &Setup) {
    let mut group = c.benchmark_group("batch_1000_events");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.bench_function(BenchmarkId::new("null_sigma", s.yamls.len()), |b| {
        b.iter(|| {
            let mut total = 0usize;
            for e in &s.ns_events {
                total += s.ns.count_matches(e);
            }
            black_box(total)
        });
    });
    group.bench_function(BenchmarkId::new("tau_engine", s.yamls.len()), |b| {
        b.iter(|| {
            let mut total = 0usize;
            for e in &s.tau_events {
                total += s.tau.count_matches(e);
            }
            black_box(total)
        });
    });
    group.bench_function(BenchmarkId::new("sigma_rust", s.yamls.len()), |b| {
        b.iter(|| {
            let mut total = 0usize;
            for e in &s.sr_events {
                total += s.sr.count_matches(e);
            }
            black_box(total)
        });
    });
    group.finish();
}

fn bench_load(c: &mut Criterion, s: &Setup) {
    let refs: Vec<&str> = s.yamls.iter().map(String::as_str).collect();
    let mut group = c.benchmark_group("rule_load");
    group.sample_size(10);
    group.bench_function(BenchmarkId::new("null_sigma", refs.len()), |b| {
        b.iter(|| black_box(NullSigmaBench::new(&refs)));
    });
    group.bench_function(BenchmarkId::new("tau_engine", refs.len()), |b| {
        b.iter(|| black_box(TauBench::new(&refs)));
    });
    group.bench_function(BenchmarkId::new("sigma_rust", refs.len()), |b| {
        b.iter(|| black_box(SigmaRustBench::new(&refs)));
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    let s = setup();
    eprintln!("[harness] benchmarking {} common rules", s.yamls.len());
    bench_single_event(c, &s, "single_suspicious_event", s.suspicious_idx);
    bench_single_event(c, &s, "single_benign_event", s.benign_idx);
    bench_batch(c, &s);
    bench_load(c, &s);
}

criterion_group!(head_to_head, benches);
criterion_main!(head_to_head);
