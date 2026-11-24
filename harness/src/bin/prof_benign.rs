//! Tier A profiling target — same workload as `head_to_head` `single_benign_event`.
//!
//! Loads the 1,110-rule common SigmaHQ `process_creation` set, evaluates:
//! 1. Single benign (`chrome.exe`) event.
//! 2. Suspicious (`powershell -EncodedCommand`) event.
//! 3. 10,000 evaluations across 1,000 mixed realistic telemetry events.
//!
//! Directly measures null-sigma, rsigma-eval, and tau-engine.

use std::hint::black_box;
use std::time::Instant;

use null_sigma_harness::{load_rule_dir, r#gen, NullSigmaBench, SigmaRustBench, TauBench};

const WARMUP: usize = 100;
const ITERATIONS: usize = 5_000;
const SR_WARMUP: usize = 2;
const SR_ITERATIONS: usize = 20;

fn main() {
    let rule_dir = null_sigma_harness::default_rule_dir();
    assert!(
        rule_dir.exists(),
        "SigmaHQ corpus missing at {} — clone SigmaHQ/sigma into corpus/sigmahq first",
        rule_dir.display()
    );

    let report = load_rule_dir(&rule_dir).expect("failed to read rules");
    let common = report.common();
    let yamls: Vec<String> = common.iter().map(|r| r.yaml.clone()).collect();
    let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();

    eprintln!("[prof_benign] loading {} common rules...", refs.len());
    let bench = NullSigmaBench::new(&refs);
    let tau_bench = TauBench::new(&refs);
    let sr_bench = SigmaRustBench::new(&refs);

    let mut parsed_rules = Vec::new();
    for y in &refs {
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
            parsed_rules.extend(col.rules);
        }
    }
    let mut rsigma_eng = rsigma_eval::Engine::new();
    rsigma_eng.add_rules(&parsed_rules);

    let events = r#gen::generate(42, 1000);
    let benign_idx = events
        .iter()
        .position(|e| e["Image"].as_str().unwrap().ends_with("chrome.exe"))
        .expect("no benign chrome.exe event in seed-42 stream");
    let event = NullSigmaBench::prepare_event(&events[benign_idx]);
    let tau_event = TauBench::prepare_event(&events[benign_idx]);
    let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&tau_event);
    let sr_event = SigmaRustBench::prepare_event(&events[benign_idx]);

    // ── Benign Event Evaluation ──────────────────────────────────────────
    eprintln!("\n=== 1. Benign Event (chrome.exe rejection) ===");
    for _ in 0..WARMUP {
        black_box(bench.count_matches(&event));
        black_box(tau_bench.count_matches(&tau_event));
        black_box(rsigma_eng.evaluate(&rsigma_event).len());
    }
    for _ in 0..SR_WARMUP {
        black_box(sr_bench.count_matches(&sr_event));
    }

    let start = Instant::now();
    let mut ns_total = 0usize;
    for _ in 0..ITERATIONS {
        ns_total += black_box(bench.count_matches(&event));
    }
    let ns_elapsed = start.elapsed();
    let ns_us = ns_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let tau_start = Instant::now();
    let mut tau_total = 0usize;
    for _ in 0..ITERATIONS {
        tau_total += black_box(tau_bench.count_matches(&tau_event));
    }
    let tau_elapsed = tau_start.elapsed();
    let tau_us = tau_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let rsigma_start = Instant::now();
    let mut rsigma_total = 0usize;
    for _ in 0..ITERATIONS {
        rsigma_total += black_box(rsigma_eng.evaluate(&rsigma_event).len());
    }
    let rsigma_elapsed = rsigma_start.elapsed();
    let rsigma_us = rsigma_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let sr_start = Instant::now();
    let mut sr_total = 0usize;
    for _ in 0..SR_ITERATIONS {
        sr_total += black_box(sr_bench.count_matches(&sr_event));
    }
    let sr_elapsed = sr_start.elapsed();
    let sr_us = sr_elapsed.as_secs_f64() * 1e6 / SR_ITERATIONS as f64;

    eprintln!(
        "  null-sigma  : {:6.2} µs/event (matches = {})",
        ns_us,
        ns_total / ITERATIONS
    );
    eprintln!(
        "  rsigma-eval : {:6.2} µs/event (matches = {})",
        rsigma_us,
        rsigma_total / ITERATIONS
    );
    eprintln!(
        "  tau-engine  : {:6.2} µs/event (matches = {})",
        tau_us,
        tau_total / ITERATIONS
    );
    eprintln!(
        "  sigma-rust  : {:6.2} µs/event (matches = {})",
        sr_us,
        sr_total / SR_ITERATIONS
    );

    // ── Suspicious Event Evaluation ──────────────────────────────────────
    eprintln!("\n=== 2. Suspicious Event (-EncodedCommand attack) ===");
    let suspicious_idx = events
        .iter()
        .position(|e| {
            e["CommandLine"]
                .as_str()
                .is_some_and(|c| c.contains("-EncodedCommand"))
        })
        .expect("no suspicious event in stream");
    let ns_susp_event = NullSigmaBench::prepare_event(&events[suspicious_idx]);
    let tau_susp_event = TauBench::prepare_event(&events[suspicious_idx]);
    let rsigma_susp_event = rsigma_eval::event::JsonEvent::borrow(&tau_susp_event);
    let sr_susp_event = SigmaRustBench::prepare_event(&events[suspicious_idx]);

    for _ in 0..WARMUP {
        black_box(bench.count_matches(&ns_susp_event));
        black_box(tau_bench.count_matches(&tau_susp_event));
        black_box(rsigma_eng.evaluate(&rsigma_susp_event).len());
    }
    for _ in 0..SR_WARMUP {
        black_box(sr_bench.count_matches(&sr_susp_event));
    }

    let susp_start = Instant::now();
    let mut susp_total = 0usize;
    for _ in 0..ITERATIONS {
        susp_total += black_box(bench.count_matches(&ns_susp_event));
    }
    let susp_elapsed = susp_start.elapsed();
    let susp_us = susp_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let tau_susp_start = Instant::now();
    let mut tau_susp_total = 0usize;
    for _ in 0..ITERATIONS {
        tau_susp_total += black_box(tau_bench.count_matches(&tau_susp_event));
    }
    let tau_susp_elapsed = tau_susp_start.elapsed();
    let tau_susp_us = tau_susp_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let rsigma_susp_start = Instant::now();
    let mut rsigma_susp_total = 0usize;
    for _ in 0..ITERATIONS {
        rsigma_susp_total += black_box(rsigma_eng.evaluate(&rsigma_susp_event).len());
    }
    let rsigma_susp_elapsed = rsigma_susp_start.elapsed();
    let rsigma_susp_us = rsigma_susp_elapsed.as_secs_f64() * 1e6 / ITERATIONS as f64;

    let sr_susp_start = Instant::now();
    let mut sr_susp_total = 0usize;
    for _ in 0..SR_ITERATIONS {
        sr_susp_total += black_box(sr_bench.count_matches(&sr_susp_event));
    }
    let sr_susp_elapsed = sr_susp_start.elapsed();
    let sr_susp_us = sr_susp_elapsed.as_secs_f64() * 1e6 / SR_ITERATIONS as f64;

    eprintln!(
        "  null-sigma  : {:6.2} µs/event (matches = {})",
        susp_us,
        susp_total / ITERATIONS
    );
    eprintln!(
        "  rsigma-eval : {:6.2} µs/event (matches = {})",
        rsigma_susp_us,
        rsigma_susp_total / ITERATIONS
    );
    eprintln!(
        "  tau-engine  : {:6.2} µs/event (matches = {})",
        tau_susp_us,
        tau_susp_total / ITERATIONS
    );
    eprintln!(
        "  sigma-rust  : {:6.2} µs/event (matches = {})",
        sr_susp_us,
        sr_susp_total / SR_ITERATIONS
    );

    // ── Batch 1,000 mixed events benchmark ──────────────────────────────
    eprintln!("\n=== 3. Mixed Telemetry (1,000 events × 10 batches = 10,000 evals) ===");
    let ns_events: Vec<_> = events.iter().map(NullSigmaBench::prepare_event).collect();
    let tau_events: Vec<_> = events.iter().map(TauBench::prepare_event).collect();
    let rsigma_events: Vec<_> = tau_events
        .iter()
        .map(rsigma_eval::event::JsonEvent::borrow)
        .collect();
    let sr_events: Vec<_> = events.iter().map(SigmaRustBench::prepare_event).collect();
    const BATCH_ITERS: usize = 10;

    let batch_start = Instant::now();
    let mut batch_ns_matches = 0usize;
    for _ in 0..BATCH_ITERS {
        for e in &ns_events {
            batch_ns_matches += black_box(bench.count_matches(e));
        }
    }
    let batch_ns_elapsed = batch_start.elapsed();
    let batch_ns_us = batch_ns_elapsed.as_secs_f64() * 1e6 / (BATCH_ITERS * events.len()) as f64;

    let rsigma_batch_start = Instant::now();
    let mut batch_rsigma_matches = 0usize;
    for _ in 0..BATCH_ITERS {
        for e in &rsigma_events {
            batch_rsigma_matches += black_box(rsigma_eng.evaluate(e).len());
        }
    }
    let batch_rsigma_elapsed = rsigma_batch_start.elapsed();
    let batch_rsigma_us =
        batch_rsigma_elapsed.as_secs_f64() * 1e6 / (BATCH_ITERS * events.len()) as f64;

    let tau_batch_start = Instant::now();
    let mut batch_tau_matches = 0usize;
    for _ in 0..BATCH_ITERS {
        for e in &tau_events {
            batch_tau_matches += black_box(tau_bench.count_matches(e));
        }
    }
    let batch_tau_elapsed = tau_batch_start.elapsed();
    let batch_tau_us = batch_tau_elapsed.as_secs_f64() * 1e6 / (BATCH_ITERS * events.len()) as f64;

    const SR_BATCH_EVENTS: usize = 50;
    let sr_batch_start = Instant::now();
    let mut batch_sr_matches = 0usize;
    for e in sr_events.iter().take(SR_BATCH_EVENTS) {
        batch_sr_matches += black_box(sr_bench.count_matches(e));
    }
    let batch_sr_elapsed = sr_batch_start.elapsed();
    let batch_sr_us = batch_sr_elapsed.as_secs_f64() * 1e6 / SR_BATCH_EVENTS as f64;

    eprintln!(
        "  null-sigma  : {:6.2} µs/event ({:.0} EPS, total_matches = {})",
        batch_ns_us,
        1e6 / batch_ns_us,
        batch_ns_matches
    );
    eprintln!(
        "  rsigma-eval : {:6.2} µs/event ({:.0} EPS, total_matches = {})",
        batch_rsigma_us,
        1e6 / batch_rsigma_us,
        batch_rsigma_matches
    );
    eprintln!(
        "  tau-engine  : {:6.2} µs/event ({:.0} EPS, total_matches = {})",
        batch_tau_us,
        1e6 / batch_tau_us,
        batch_tau_matches
    );
    eprintln!(
        "  sigma-rust  : {:6.2} µs/event ({:.0} EPS, matches = {} in {} events)",
        batch_sr_us,
        1e6 / batch_sr_us,
        batch_sr_matches,
        SR_BATCH_EVENTS
    );
}
