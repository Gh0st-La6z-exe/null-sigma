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
//! Usage: null_sigma_run [--threads N] [--on-error continue|fail-fast] <rule_dir> <events.jsonl>
//!
//! `--threads 1` (default): single-threaded eval.
//! `--threads 0`: Rayon pool sized to `available_parallelism()`.
//! `--threads N` (N > 1): fixed Rayon pool of N workers.
//! `--on-error continue` (default): count bad events and keep going.
//! `--on-error fail-fast`: exit non-zero on first event-level error.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;

use rayon::prelude::*;

struct Args {
    threads: usize,
    on_error: OnErrorMode,
    rule_dir: std::path::PathBuf,
    events_path: std::path::PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OnErrorMode {
    Continue,
    FailFast,
}

#[derive(Debug, Default)]
struct ErrorCounters {
    err_io_read: u64,
    err_json_parse: u64,
    err_flatten: u64,
}

impl ErrorCounters {
    fn total(&self) -> u64 {
        self.err_io_read + self.err_json_parse + self.err_flatten
    }
}

#[derive(Debug, Default)]
struct IngestStats {
    events: Vec<HashMap<String, String>>,
    events_total: u64,
    events_ok: u64,
    events_failed: u64,
    t_read: Duration,
    t_parse: Duration,
    t_flat: Duration,
    errors: ErrorCounters,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut threads = 1usize;
    let mut on_error = OnErrorMode::Continue;

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
        } else if arg == "--on-error" {
            let mode = iter
                .next()
                .ok_or_else(|| "--on-error requires a value".to_string())?;
            on_error = parse_on_error_mode(&mode)?;
        } else if arg.starts_with("--on-error=") {
            let mode = arg
                .split_once('=')
                .map(|(_, v)| v)
                .ok_or_else(|| "invalid --on-error syntax".to_string())?;
            on_error = parse_on_error_mode(mode)?;
        } else if arg == "--help" || arg == "-h" {
            eprintln!(
                "usage: null_sigma_run [--threads N] [--on-error continue|fail-fast] <rule_dir> <events.jsonl>\n\
                 \n\
                 --threads 1   single-threaded eval (default)\n\
                 --threads 0   Rayon pool = available_parallelism()\n\
                 --threads N   fixed Rayon pool of N workers\n\
                 --on-error continue   count bad events and continue (default)\n\
                 --on-error fail-fast  exit non-zero on first event error"
            );
            std::process::exit(0);
        } else {
            let events_path = iter
                .next()
                .ok_or_else(|| format!("missing events path after {arg}"))?;
            return Ok(Args {
                threads,
                on_error,
                rule_dir: std::path::PathBuf::from(arg),
                events_path: std::path::PathBuf::from(events_path),
            });
        }
    }

    Err("usage: null_sigma_run [--threads N] [--on-error continue|fail-fast] <rule_dir> <events.jsonl>".to_string())
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

fn parse_on_error_mode(raw: &str) -> Result<OnErrorMode, String> {
    match raw {
        "continue" => Ok(OnErrorMode::Continue),
        "fail-fast" => Ok(OnErrorMode::FailFast),
        _ => Err(format!(
            "invalid --on-error value: {raw} (expected continue|fail-fast)"
        )),
    }
}

fn ingest_events(
    events_path: &std::path::Path,
    on_error: OnErrorMode,
) -> Result<IngestStats, String> {
    let file = std::fs::File::open(events_path)
        .map_err(|e| format!("cannot open events '{}': {e}", events_path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut stats = IngestStats::default();

    loop {
        line.clear();
        let t0 = std::time::Instant::now();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                stats.errors.err_io_read += 1;
                stats.events_failed += 1;
                if on_error == OnErrorMode::FailFast {
                    return Err(format!("read error: {e}"));
                }
                break;
            }
        };
        stats.t_read += t0.elapsed();
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        stats.events_total += 1;

        let t0 = std::time::Instant::now();
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => {
                stats.t_parse += t0.elapsed();
                stats.errors.err_json_parse += 1;
                stats.events_failed += 1;
                if on_error == OnErrorMode::FailFast {
                    return Err("bad event JSON".to_string());
                }
                continue;
            }
        };
        stats.t_parse += t0.elapsed();

        let t0 = std::time::Instant::now();
        let event = match null_sigma::flatten_value(&value) {
            Ok(event) => event,
            Err(_) => {
                stats.t_flat += t0.elapsed();
                stats.errors.err_flatten += 1;
                stats.events_failed += 1;
                if on_error == OnErrorMode::FailFast {
                    return Err("flatten failed".to_string());
                }
                continue;
            }
        };
        stats.t_flat += t0.elapsed();

        stats.events_ok += 1;
        stats.events.push(event);
    }

    Ok(stats)
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

    let ingest_stats = match ingest_events(&args.events_path, args.on_error) {
        Ok(stats) => stats,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let eval_start = std::time::Instant::now();
    let engine = Arc::new(engine);
    let matches = evaluate_events(engine, &ingest_stats.events, threads);
    let t_eval = eval_start.elapsed();

    let scan = ingest_stats.t_read + ingest_stats.t_parse + ingest_stats.t_flat + t_eval;
    let accounted = ingest_stats.t_read + ingest_stats.t_parse + ingest_stats.t_flat + t_eval;
    let other = scan.saturating_sub(accounted);

    let pct = |d: Duration| -> f64 {
        if scan.is_zero() {
            0.0
        } else {
            100.0 * d.as_secs_f64() / scan.as_secs_f64()
        }
    };

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {events_total} | \
         ok: {events_ok} failed: {events_failed} | matches: {matches} | threads: {threads} | \
         on_error: {on_error} | scan: {scan_s:.3}s ({eps:.0} events/sec)",
        events_total = ingest_stats.events_total,
        events_ok = ingest_stats.events_ok,
        events_failed = ingest_stats.events_failed,
        on_error = match args.on_error {
            OnErrorMode::Continue => "continue",
            OnErrorMode::FailFast => "fail-fast",
        },
        scan_s = scan.as_secs_f64(),
        eps = ingest_stats.events_total as f64 / scan.as_secs_f64()
    );
    eprintln!(
        "tier_b_tax: read={:.3}s ({:.1}%) parse={:.3}s ({:.1}%) flat={:.3}s ({:.1}%) \
         eval={:.3}s ({:.1}%) other={:.3}s ({:.1}%)",
        ingest_stats.t_read.as_secs_f64(),
        pct(ingest_stats.t_read),
        ingest_stats.t_parse.as_secs_f64(),
        pct(ingest_stats.t_parse),
        ingest_stats.t_flat.as_secs_f64(),
        pct(ingest_stats.t_flat),
        t_eval.as_secs_f64(),
        pct(t_eval),
        other.as_secs_f64(),
        pct(other),
    );
    eprintln!(
        "ingest_errors: io_read={} json_parse={} flatten={} total={}",
        ingest_stats.errors.err_io_read,
        ingest_stats.errors.err_json_parse,
        ingest_stats.errors.err_flatten,
        ingest_stats.errors.total()
    );
    eprintln!(
        "ingest_accounting: events_total={} events_ok={} events_failed={} invariant_ok={}",
        ingest_stats.events_total,
        ingest_stats.events_ok,
        ingest_stats.events_failed,
        ingest_stats.events_total == (ingest_stats.events_ok + ingest_stats.events_failed)
    );
    println!("{matches}");
}
