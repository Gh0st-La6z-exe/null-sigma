//! Minimal end-to-end CLI runner for Tier B wall-clock comparison
//! (and a precursor to roadmap item 4's `null-sigma-cli`).
//!
//! Reads a Sigma rule directory and a JSONL event file, evaluates every event
//! through `SigmaEngine::evaluate_event_count`, and prints the match count.
//!
//! Timing breakdown (stderr) splits scan wall clock into:
//!   read  — `BufRead::read_line` into a reused `String`
//!   parse — `serde_json::from_str`
//!   flat  — `flatten_value_with` (depth/field guards)
//!   eval  — `evaluate_event_count` (parallel when `--threads` > 1)
//!
//! Usage:
//!   null_sigma_run [--threads N] [--on-error continue|fail-fast]
//!                  [--max-line-bytes N] [--max-error-samples N]
//!                  <rule_dir> <events.jsonl>

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;

use null_sigma::json::{flatten_value_with, FlattenError, FlattenOptions};
use rayon::prelude::*;

/// Default max bytes per JSONL line (8 MiB) — rejects oversize before parse/alloc.
const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

struct Args {
    threads: usize,
    on_error: OnErrorMode,
    max_line_bytes: usize,
    max_error_samples: usize,
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
    err_line_too_large: u64,
    err_json_parse: u64,
    err_flatten_not_object: u64,
    err_flatten_depth: u64,
    err_flatten_fields: u64,
}

impl ErrorCounters {
    fn flatten_total(&self) -> u64 {
        self.err_flatten_not_object + self.err_flatten_depth + self.err_flatten_fields
    }

    fn total(&self) -> u64 {
        self.err_io_read
            + self.err_line_too_large
            + self.err_json_parse
            + self.flatten_total()
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
    let mut max_line_bytes = DEFAULT_MAX_LINE_BYTES;
    let mut max_error_samples = 0usize;

    while let Some(arg) = iter.next() {
        if arg == "--threads" {
            let n = iter
                .next()
                .ok_or_else(|| "--threads requires a value".to_string())?;
            threads = n
                .parse()
                .map_err(|_| format!("invalid --threads value: {n}"))?;
        } else if let Some(n) = arg.strip_prefix("--threads=") {
            threads = n
                .parse()
                .map_err(|_| format!("invalid --threads value: {n}"))?;
        } else if arg == "--on-error" {
            let mode = iter
                .next()
                .ok_or_else(|| "--on-error requires a value".to_string())?;
            on_error = parse_on_error_mode(&mode)?;
        } else if let Some(mode) = arg.strip_prefix("--on-error=") {
            on_error = parse_on_error_mode(mode)?;
        } else if arg == "--max-line-bytes" {
            let n = iter
                .next()
                .ok_or_else(|| "--max-line-bytes requires a value".to_string())?;
            max_line_bytes = n
                .parse()
                .map_err(|_| format!("invalid --max-line-bytes value: {n}"))?;
            if max_line_bytes == 0 {
                return Err("--max-line-bytes must be > 0".to_string());
            }
        } else if let Some(n) = arg.strip_prefix("--max-line-bytes=") {
            max_line_bytes = n
                .parse()
                .map_err(|_| format!("invalid --max-line-bytes value: {n}"))?;
            if max_line_bytes == 0 {
                return Err("--max-line-bytes must be > 0".to_string());
            }
        } else if arg == "--max-error-samples" {
            let n = iter
                .next()
                .ok_or_else(|| "--max-error-samples requires a value".to_string())?;
            max_error_samples = n
                .parse()
                .map_err(|_| format!("invalid --max-error-samples value: {n}"))?;
        } else if let Some(n) = arg.strip_prefix("--max-error-samples=") {
            max_error_samples = n
                .parse()
                .map_err(|_| format!("invalid --max-error-samples value: {n}"))?;
        } else if arg == "--help" || arg == "-h" {
            print_help();
            std::process::exit(0);
        } else {
            let events_path = iter
                .next()
                .ok_or_else(|| format!("missing events path after {arg}"))?;
            return Ok(Args {
                threads,
                on_error,
                max_line_bytes,
                max_error_samples,
                rule_dir: std::path::PathBuf::from(arg),
                events_path: std::path::PathBuf::from(events_path),
            });
        }
    }

    Err("usage: null_sigma_run [--threads N] [--on-error continue|fail-fast] [--max-line-bytes N] [--max-error-samples N] <rule_dir> <events.jsonl>".to_string())
}

fn print_help() {
    eprintln!(
        "usage: null_sigma_run [--threads N] [--on-error continue|fail-fast] [--max-line-bytes N] [--max-error-samples N] <rule_dir> <events.jsonl>\n\
         \n\
         --threads 1           single-threaded eval (default)\n\
         --threads 0           Rayon pool = available_parallelism()\n\
         --threads N           fixed Rayon pool of N workers\n\
         --on-error continue   count bad events and continue (default)\n\
         --on-error fail-fast  exit non-zero on first event error\n\
         --max-line-bytes N    reject lines larger than N bytes (default {DEFAULT_MAX_LINE_BYTES})\n\
         --max-error-samples N emit up to N ingest_error_sample lines (default 0)"
    );
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

fn record_flatten_error(counters: &mut ErrorCounters, err: &FlattenError) {
    match err {
        FlattenError::NotAnObject => counters.err_flatten_not_object += 1,
        FlattenError::DepthExceeded { .. } => counters.err_flatten_depth += 1,
        FlattenError::FieldsExceeded { .. } => counters.err_flatten_fields += 1,
        // Parse errors are handled before flatten; defensive no-op.
        FlattenError::Parse(_) => {}
    }
}

fn flatten_error_kind(err: &FlattenError) -> &'static str {
    match err {
        FlattenError::NotAnObject => "flatten_not_object",
        FlattenError::DepthExceeded { .. } => "flatten_depth",
        FlattenError::FieldsExceeded { .. } => "flatten_fields",
        FlattenError::Parse(_) => "json_parse",
    }
}

fn maybe_emit_error_sample(
    line_number: u64,
    kind: &str,
    msg: &str,
    max_error_samples: usize,
    error_samples_emitted: &mut usize,
) {
    if *error_samples_emitted >= max_error_samples {
        return;
    }
    eprintln!("ingest_error_sample: line={line_number} kind={kind} msg=\"{msg}\"");
    *error_samples_emitted += 1;
}

fn fail_event(
    stats: &mut IngestStats,
    on_error: OnErrorMode,
    line_number: u64,
    kind: &str,
    msg: &str,
    max_error_samples: usize,
    error_samples_emitted: &mut usize,
) -> Result<(), String> {
    maybe_emit_error_sample(
        line_number,
        kind,
        msg,
        max_error_samples,
        error_samples_emitted,
    );
    stats.events_failed += 1;
    if on_error == OnErrorMode::FailFast {
        Err(msg.to_string())
    } else {
        Ok(())
    }
}

fn ingest_events(
    events_path: &std::path::Path,
    on_error: OnErrorMode,
    max_line_bytes: usize,
    max_error_samples: usize,
    flatten_options: FlattenOptions,
) -> Result<IngestStats, String> {
    let file = std::fs::File::open(events_path)
        .map_err(|e| format!("cannot open events '{}': {e}", events_path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut stats = IngestStats::default();
    let mut line_number = 0u64;
    let mut error_samples_emitted = 0usize;

    loop {
        line.clear();
        let t0 = std::time::Instant::now();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                stats.errors.err_io_read += 1;
                let failed_line = line_number.saturating_add(1);
                fail_event(
                    &mut stats,
                    on_error,
                    failed_line,
                    "io_read",
                    &format!("read error: {e}"),
                    max_error_samples,
                    &mut error_samples_emitted,
                )?;
                break;
            }
        };
        stats.t_read += t0.elapsed();
        if n == 0 {
            break;
        }
        line_number += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        stats.events_total += 1;

        if trimmed.len() > max_line_bytes {
            stats.errors.err_line_too_large += 1;
            fail_event(
                &mut stats,
                on_error,
                line_number,
                "line_too_large",
                "line exceeds --max-line-bytes",
                max_error_samples,
                &mut error_samples_emitted,
            )?;
            continue;
        }

        let t0 = std::time::Instant::now();
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => {
                stats.t_parse += t0.elapsed();
                stats.errors.err_json_parse += 1;
                fail_event(
                    &mut stats,
                    on_error,
                    line_number,
                    "json_parse",
                    "bad event JSON",
                    max_error_samples,
                    &mut error_samples_emitted,
                )?;
                continue;
            }
        };
        stats.t_parse += t0.elapsed();

        let t0 = std::time::Instant::now();
        let event = match flatten_value_with(&value, flatten_options) {
            Ok(event) => event,
            Err(err) => {
                stats.t_flat += t0.elapsed();
                record_flatten_error(&mut stats.errors, &err);
                let kind = flatten_error_kind(&err);
                fail_event(
                    &mut stats,
                    on_error,
                    line_number,
                    kind,
                    "flatten failed",
                    max_error_samples,
                    &mut error_samples_emitted,
                )?;
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
) -> Result<u64, String> {
    if threads == 1 {
        return Ok(events
            .iter()
            .map(|event| engine.evaluate_event_count(event) as u64)
            .sum());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("failed to build Rayon thread pool: {e}"))?;

    Ok(pool.install(|| {
        events
            .par_iter()
            .map(|event| engine.evaluate_event_count(event) as u64)
            .sum()
    }))
}

fn load_rules_from_dir(rule_dir: &std::path::Path) -> Result<(null_sigma::SigmaEngine, usize, usize, u128), String> {
    let start = std::time::Instant::now();
    let mut engine = null_sigma::SigmaEngine::new();
    let entries = std::fs::read_dir(rule_dir)
        .map_err(|e| format!("cannot read rule dir '{}': {e}", rule_dir.display()))?;
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "yml" || ext == "yaml"))
        .collect();
    paths.sort();

    let joined = paths
        .iter()
        .map(|p| {
            std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read rule '{}': {e}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n---\n");

    let (loaded_ids, errors) = engine.load_rules(&joined);
    let load_ms = start.elapsed().as_millis();
    Ok((engine, loaded_ids.len(), errors.len(), load_ms))
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

    let (engine, loaded, skipped, load_ms) = match load_rules_from_dir(&args.rule_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let ingest_stats = match ingest_events(
        &args.events_path,
        args.on_error,
        args.max_line_bytes,
        args.max_error_samples,
        FlattenOptions::default(),
    ) {
        Ok(stats) => stats,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let eval_start = std::time::Instant::now();
    let engine = Arc::new(engine);
    let matches = match evaluate_events(engine, &ingest_stats.events, threads) {
        Ok(m) => m,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };
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
         on_error: {on_error} | max_line_bytes: {max_line_bytes} | max_error_samples: {max_error_samples} | scan: {scan_s:.3}s ({eps:.0} events/sec)",
        events_total = ingest_stats.events_total,
        events_ok = ingest_stats.events_ok,
        events_failed = ingest_stats.events_failed,
        on_error = match args.on_error {
            OnErrorMode::Continue => "continue",
            OnErrorMode::FailFast => "fail-fast",
        },
        max_line_bytes = args.max_line_bytes,
        max_error_samples = args.max_error_samples,
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
        "ingest_errors: io_read={} line_too_large={} json_parse={} flatten_not_object={} \
         flatten_depth={} flatten_fields={} flatten_total={} total={}",
        ingest_stats.errors.err_io_read,
        ingest_stats.errors.err_line_too_large,
        ingest_stats.errors.err_json_parse,
        ingest_stats.errors.err_flatten_not_object,
        ingest_stats.errors.err_flatten_depth,
        ingest_stats.errors.err_flatten_fields,
        ingest_stats.errors.flatten_total(),
        ingest_stats.errors.total()
    );
    let invariant_ok =
        ingest_stats.events_total == ingest_stats.events_ok + ingest_stats.events_failed;
    eprintln!(
        "ingest_accounting: events_total={} events_ok={} events_failed={} invariant_ok={invariant_ok}",
        ingest_stats.events_total,
        ingest_stats.events_ok,
        ingest_stats.events_failed,
    );
    if !invariant_ok {
        eprintln!(
            "FATAL: ingest accounting invariant violated: events_total={} != events_ok({}) + events_failed({})",
            ingest_stats.events_total,
            ingest_stats.events_ok,
            ingest_stats.events_failed,
        );
        std::process::exit(1);
    }
    println!("{matches}");
}
