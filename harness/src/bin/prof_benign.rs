//! Tier A profiling target — same workload as `head_to_head` `single_benign_event`.
//!
//! Loads the 1 102-rule common SigmaHQ `process_creation` set, evaluates the
//! seed-42 benign (`chrome.exe`) event in a tight loop. Input preparation and
//! rule loading happen outside the timed region (before samply records).
//!
//! Run: `harness/scripts/prof_benign.sh` (output under `harness/prof/`, gitignored).

use std::hint::black_box;
use std::time::Instant;

use null_sigma_harness::{r#gen, load_rule_dir, NullSigmaBench};

/// Warm-up iterations (not profiled when using samply — entire process is recorded;
/// warmup still drives caches/automaton before the bulk of samples).
const WARMUP: usize = 1_000;
/// Profiled iterations — long enough for stable samply stacks.
const ITERATIONS: usize = 100_000;

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

    let events = r#gen::generate(42, 1000);
    let benign_idx = events
        .iter()
        .position(|e| e["Image"].as_str().unwrap().ends_with("chrome.exe"))
        .expect("no benign chrome.exe event in seed-42 stream");
    let event = NullSigmaBench::prepare_event(&events[benign_idx]);

    eprintln!("[prof_benign] warmup {WARMUP} × evaluate_event_count...");
    for _ in 0..WARMUP {
        black_box(bench.count_matches(&event));
    }

    eprintln!("[prof_benign] profiled loop {ITERATIONS} × evaluate_event_count...");
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..ITERATIONS {
        total += black_box(bench.count_matches(&event));
    }
    let elapsed = start.elapsed();
    let us_per_event = elapsed.as_secs_f64() * 1e6 / f64::from(ITERATIONS as u32);

    eprintln!(
        "[prof_benign] wall: {us_per_event:.2} µs/event ({ITERATIONS} iters in {elapsed:?}), total_matches={total}"
    );

    // Sink `total` so the loop isn't optimized away when profiling without black_box.
    std::process::exit(if total == usize::MAX { 1 } else { 0 });
}
