//! Minimal end-to-end CLI runner for Tier B wall-clock comparison
//! (and a precursor to roadmap item 4's `null-sigma-cli`).
//!
//! Reads a Sigma rule directory and a JSONL event file, evaluates every event
//! through `SigmaEngine::evaluate_event_count`, and prints the match count.
//!
//! Timing breakdown (stderr) splits scan wall clock into:
//!   read  — `BufRead::read_line` into a reused `String`
//!   parse — `serde_json::from_str`
//!   flat  — `flatten_value`
//!   eval  — `evaluate_event_count` (parallel when `--threads` > 1)
//!
//! Usage: null_sigma_run [--threads N] <rule_dir> <events.jsonl>
//!
//! `--threads 1` (default): single-threaded eval.
//! `--threads 0`: Rayon pool sized to `available_parallelism()`.
//! `--threads N` (N > 1): fixed Rayon pool of N workers.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;

use rayon::prelude::*;

struct Args {
    threads: usize,
    rule_dir: std::path::PathBuf,
    events_path: std::path::PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut threads = 1usize;

    while let Some(arg) = iter.next() {
        if arg == "--threads" {
            let n = iter
                .next()
                .ok_or_else(|| "--threads requires a value".to_string())?;
            threads = n
                .parse()
                .map_err(|_| format!("invalid --threads value: {n}"))?;
        } else if arg.starts_with("--threads=") {
            let n = arg
                .split_once('=')
                .map(|(_, v)| v)
                .ok_or_else(|| "invalid --threads syntax".to_string())?;
            threads = n
                .parse()
                .map_err(|_| format!("invalid --threads value: {n}"))?;
        } else if arg == "--help" || arg == "-h" {
            eprintln!(
                "usage: null_sigma_run [--threads N] <rule_dir> <events.jsonl>\n\
                 \n\
                 --threads 1   single-threaded eval (default)\n\
                 --threads 0   Rayon pool = available_parallelism()\n\
                 --threads N   fixed Rayon pool of N workers"
            );
            std::process::exit(0);
        } else {
            let events_path = iter
                .next()
                .ok_or_else(|| format!("missing events path after {arg}"))?;
            return Ok(Args {
                threads,
                rule_dir: std::path::PathBuf::from(arg),
                events_path: std::path::PathBuf::from(events_path),
            });
        }
    }

    Err("usage: null_sigma_run [--threads N] <rule_dir> <events.jsonl>".to_string())
}

fn resolve_thread_count(requested: usize) -> usize {
    if requested == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        requested
    }
}

fn ingest_events(
    events_path: &std::path::Path,
) -> (Vec<HashMap<String, String>>, u64, Duration, Duration, Duration) {
    let mut reader = BufReader::new(std::fs::File::open(events_path).expect("cannot open events"));
    let mut line = String::new();
    let mut events = Vec::new();
    let mut event_count = 0u64;
    let mut t_read = Duration::ZERO;
    let mut t_parse = Duration::ZERO;
    let mut t_flat = Duration::ZERO;

    loop {
        line.clear();
        let t0 = std::time::Instant::now();
        let n = reader.read_line(&mut line).expect("read error");
        t_read += t0.elapsed();
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        event_count += 1;

        let t0 = std::time::Instant::now();
        let value: serde_json::Value =
            serde_json::from_str(trimmed).expect("bad event JSON");
        t_parse += t0.elapsed();

        let t0 = std::time::Instant::now();
        let event = null_sigma::flatten_value(&value).expect("flatten failed");
        t_flat += t0.elapsed();

        events.push(event);
    }

    (events, event_count, t_read, t_parse, t_flat)
}

fn evaluate_events(
    engine: Arc<null_sigma::SigmaEngine>,
    events: &[HashMap<String, String>],
    threads: usize,
) -> u64 {
    if threads == 1 {
        events
            .iter()
            .map(|event| engine.evaluate_event_count(event) as u64)
            .sum()
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("failed to build Rayon thread pool");

        pool.install(|| {
            events
                .par_iter()
                .map(|event| engine.evaluate_event_count(event) as u64)
                .sum()
        })
    }
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let threads = resolve_thread_count(args.threads);

    let start = std::time::Instant::now();
    let mut engine = null_sigma::SigmaEngine::new();
    let mut paths: Vec<_> = std::fs::read_dir(&args.rule_dir)
        .expect("cannot read rule dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    paths.sort();
    // Bulk load as one multi-document stream: the AC automaton is rebuilt
    // once at the end instead of once per rule.
    let joined = paths
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("cannot read rule"))
        .collect::<Vec<_>>()
        .join("\n---\n");
    let (loaded_ids, errors) = engine.load_rules(&joined);
    let (loaded, skipped) = (loaded_ids.len(), errors.len());
    let load_ms = start.elapsed().as_millis();

    let ingest_start = std::time::Instant::now();
    let (events, event_count, t_read, t_parse, t_flat) =
        ingest_events(&args.events_path);
    let ingest = ingest_start.elapsed();

    let eval_start = std::time::Instant::now();
    let engine = Arc::new(engine);
    let matches = evaluate_events(engine, &events, threads);
    let t_eval = eval_start.elapsed();

    let scan = ingest + t_eval;
    let accounted = t_read + t_parse + t_flat + t_eval;
    let other = scan.saturating_sub(accounted);

    let pct = |d: Duration| -> f64 {
        if scan.is_zero() {
            0.0
        } else {
            100.0 * d.as_secs_f64() / scan.as_secs_f64()
        }
    };

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {event_count} | \
         matches: {matches} | threads: {threads} | scan: {:.3}s ({:.0} events/sec)",
        scan.as_secs_f64(),
        event_count as f64 / scan.as_secs_f64()
    );
    eprintln!(
        "tier_b_tax: read={:.3}s ({:.1}%) parse={:.3}s ({:.1}%) flat={:.3}s ({:.1}%) \
         eval={:.3}s ({:.1}%) other={:.3}s ({:.1}%)",
        t_read.as_secs_f64(),
        pct(t_read),
        t_parse.as_secs_f64(),
        pct(t_parse),
        t_flat.as_secs_f64(),
        pct(t_flat),
        t_eval.as_secs_f64(),
        pct(t_eval),
        other.as_secs_f64(),
        pct(other),
    );
    println!("{matches}");
}
