//! Multi-Core Concurrency & SMP Cache Contention Gauntlet.
//!
//! Measures parallel scaling of null-sigma, rsigma-eval, and tau-engine across
//! 1, 2, 4, and 8 worker threads evaluating against shared engines with 1,110 SigmaHQ rules.
//! Accurately benchmarks after thread creation and thread-local warmup via Barrier synchronization.

use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::time::Instant;

use null_sigma_harness::{load_rule_dir, NullSigmaBench, TauBench};

fn main() {
    println!("===============================================================================");
    println!("        NULL-SIGMA MULTI-CORE CONCURRENCY & SMP SCALING GAUNTLET              ");
    println!("===============================================================================");
    let num_cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("Operating System : {}", std::env::consts::OS);
    println!("Architecture     : {}", std::env::consts::ARCH);
    println!("Available Cores  : {}", num_cpus);
    println!("===============================================================================\n");

    let rule_dir = null_sigma_harness::default_rule_dir();
    println!(
        "[+] Loading SigmaHQ rule corpus from: {}",
        rule_dir.display()
    );
    let report = load_rule_dir(&rule_dir).expect("failed to load rule directory");
    let common = report.common();
    let yamls: Vec<String> = common.iter().map(|r| r.yaml.clone()).collect();
    let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
    println!("[+] Common rule set loaded: {} rules\n", refs.len());

    println!("[+] Compiling engines...");
    let ns_bench = NullSigmaBench::new(&refs);
    let tau_bench = TauBench::new(&refs);
    let ns_engine = Arc::new(ns_bench.engine);
    let tau_rules = Arc::new(tau_bench.rules);

    println!("[+] Compiling rsigma-eval engine...");
    let mut parsed_rules = Vec::new();
    for y in &refs {
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
            parsed_rules.extend(col.rules);
        }
    }
    let mut rsigma_eng = rsigma_eval::Engine::new();
    rsigma_eng.add_rules(&parsed_rules);
    let rsigma_engine = Arc::new(rsigma_eng);

    println!("[+] Pre-generating 10,000 realistic mixed telemetry events...");
    let raw_events = null_sigma_harness::gen::generate(42, 10_000);
    let ns_events: Arc<Vec<HashMap<String, String>>> = Arc::new(
        raw_events
            .iter()
            .map(NullSigmaBench::prepare_event)
            .collect(),
    );
    let tau_events: Arc<Vec<serde_json::Value>> =
        Arc::new(raw_events.iter().map(TauBench::prepare_event).collect());
    println!("[+] Dataset ready.\n");

    let total_evals = 100_000;
    let mut thread_counts = vec![1, 2, 4];
    if num_cpus >= 8 && !thread_counts.contains(&num_cpus) {
        thread_counts.push(num_cpus);
    }
    if !thread_counts.contains(&num_cpus) && num_cpus > 1 {
        thread_counts.push(num_cpus);
    }
    thread_counts.sort_unstable();
    thread_counts.dedup();

    // ─────────────────────────────────────────────────────────────────────────
    // null-sigma Parallel Scaling
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" null-sigma Multi-Threaded Throughput & Scaling (100,000 Evaluations)          ");
    println!("-------------------------------------------------------------------------------");

    let mut baseline_eps = 0.0;
    for &threads in &thread_counts {
        let iters_per_thread = total_evals / threads;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let mut start_time = None;

        let total_hits: usize = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let engine = Arc::clone(&ns_engine);
                let events = Arc::clone(&ns_events);
                let barrier = Arc::clone(&barrier);
                let handle = s.spawn(move || {
                    // Warmup thread-local scratch & CPU cache
                    for w in 0..500 {
                        let idx = (t * 500 + w) % events.len();
                        let _ = engine.evaluate_event_count(&events[idx]);
                    }
                    barrier.wait();
                    let mut hits = 0;
                    for i in 0..iters_per_thread {
                        let idx = (t * iters_per_thread + i) % events.len();
                        hits += engine.evaluate_event_count(&events[idx]);
                    }
                    hits
                });
                handles.push(handle);
            }
            barrier.wait();
            let start = Instant::now();
            let sum: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
            start_time = Some(start.elapsed());
            sum
        });

        let elapsed = start_time.unwrap();
        let eps = (iters_per_thread * threads) as f64 / elapsed.as_secs_f64();
        if threads == 1 {
            baseline_eps = eps;
        }
        let speedup = eps / baseline_eps;
        let efficiency = (speedup / threads as f64) * 100.0;

        println!(
            "Threads: {:2} | Time: {:8.3?} | Total Hits: {:6} | Throughput: {:9.0} EPS | Speedup: {:5.2}× | Efficiency: {:5.1}%",
            threads, elapsed, total_hits, eps, speedup, efficiency
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // rsigma-eval Parallel Scaling
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" rsigma-eval Multi-Threaded Scaling (100,000 Evaluations)                      ");
    println!("-------------------------------------------------------------------------------");

    let mut rsigma_baseline_eps = 0.0;
    for &threads in &thread_counts {
        let iters_per_thread = total_evals / threads;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let mut start_time = None;

        let total_hits: usize = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let engine = Arc::clone(&rsigma_engine);
                let events = Arc::clone(&tau_events);
                let barrier = Arc::clone(&barrier);
                let handle = s.spawn(move || {
                    // Warmup
                    for w in 0..500 {
                        let idx = (t * 500 + w) % events.len();
                        let json_evt = rsigma_eval::event::JsonEvent::borrow(&events[idx]);
                        let _ = engine.evaluate(&json_evt).len();
                    }
                    barrier.wait();
                    let mut hits = 0;
                    for i in 0..iters_per_thread {
                        let idx = (t * iters_per_thread + i) % events.len();
                        let json_evt = rsigma_eval::event::JsonEvent::borrow(&events[idx]);
                        hits += engine.evaluate(&json_evt).len();
                    }
                    hits
                });
                handles.push(handle);
            }
            barrier.wait();
            let start = Instant::now();
            let sum: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
            start_time = Some(start.elapsed());
            sum
        });

        let elapsed = start_time.unwrap();
        let eps = (iters_per_thread * threads) as f64 / elapsed.as_secs_f64();
        if threads == 1 {
            rsigma_baseline_eps = eps;
        }
        let speedup = eps / rsigma_baseline_eps;
        let efficiency = (speedup / threads as f64) * 100.0;

        println!(
            "Threads: {:2} | Time: {:8.3?} | Total Hits: {:6} | Throughput: {:9.0} EPS | Speedup: {:5.2}× | Efficiency: {:5.1}%",
            threads, elapsed, total_hits, eps, speedup, efficiency
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // tau-engine (Chainsaw) Parallel Scaling
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" tau-engine (Chainsaw) Multi-Threaded Scaling (10,000 Evaluations)             ");
    println!("-------------------------------------------------------------------------------");

    let tau_total_evals = 10_000;
    let mut tau_baseline_eps = 0.0;
    for &threads in &thread_counts {
        let iters_per_thread = tau_total_evals / threads;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let mut start_time = None;

        let total_hits: usize = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let rules = Arc::clone(&tau_rules);
                let events = Arc::clone(&tau_events);
                let barrier = Arc::clone(&barrier);
                let handle = s.spawn(move || {
                    // Warmup
                    for w in 0..100 {
                        let idx = (t * 100 + w) % events.len();
                        let evt = &events[idx];
                        let _ = rules.iter().filter(|r| r.matches(evt)).count();
                    }
                    barrier.wait();
                    let mut hits = 0;
                    for i in 0..iters_per_thread {
                        let idx = (t * iters_per_thread + i) % events.len();
                        let evt = &events[idx];
                        hits += rules.iter().filter(|r| r.matches(evt)).count();
                    }
                    hits
                });
                handles.push(handle);
            }
            barrier.wait();
            let start = Instant::now();
            let sum: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
            start_time = Some(start.elapsed());
            sum
        });

        let elapsed = start_time.unwrap();
        let eps = (iters_per_thread * threads) as f64 / elapsed.as_secs_f64();
        if threads == 1 {
            tau_baseline_eps = eps;
        }
        let speedup = eps / tau_baseline_eps;
        let efficiency = (speedup / threads as f64) * 100.0;

        println!(
            "Threads: {:2} | Time: {:8.3?} | Total Hits: {:6} | Throughput: {:9.0} EPS | Speedup: {:5.2}× | Efficiency: {:5.1}%",
            threads, elapsed, total_hits, eps, speedup, efficiency
        );
    }
    println!("\n===============================================================================");
    println!("                     CONCURRENCY GAUNTLET COMPLETE                             ");
    println!("===============================================================================");
}
