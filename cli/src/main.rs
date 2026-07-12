//! null-sigma-cli — ROADMAP §4 product CLI (Week 2 Day 1: trust parity).
//!
//! Usage:
//!   null-sigma-cli --rules <dir> [options] [events.jsonl | -]
//!
//! Omit the events path or pass `-` to read JSONL from stdin.
//! Day 1 stdout is a temporary match-count integer; NDJSON alerts land Day 2.

mod ingest;
mod rules;

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use ingest::{
    ingest_and_eval, OnErrorMode, DEFAULT_MAX_LINE_BYTES,
};
use null_sigma::json::FlattenOptions;

struct Args {
    /// Accepted for forward-compat; MVP always evaluates single-threaded.
    threads: usize,
    on_error: OnErrorMode,
    max_line_bytes: usize,
    max_error_samples: usize,
    rule_dir: PathBuf,
    /// `None` means stdin.
    events_path: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut threads = 1usize;
    let mut on_error = OnErrorMode::Continue;
    let mut max_line_bytes = DEFAULT_MAX_LINE_BYTES;
    let mut max_error_samples = 0usize;
    let mut rule_dir: Option<PathBuf> = None;
    let mut positional: Vec<String> = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--rules" {
            let p = iter
                .next()
                .ok_or_else(|| "--rules requires a directory path".to_string())?;
            rule_dir = Some(PathBuf::from(p));
        } else if let Some(p) = arg.strip_prefix("--rules=") {
            rule_dir = Some(PathBuf::from(p));
        } else if arg == "--threads" {
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
            max_line_bytes = parse_positive_usize("--max-line-bytes", &n)?;
        } else if let Some(n) = arg.strip_prefix("--max-line-bytes=") {
            max_line_bytes = parse_positive_usize("--max-line-bytes", n)?;
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
        } else if arg.starts_with('-') && arg != "-" {
            return Err(format!("unknown flag: {arg}"));
        } else {
            positional.push(arg);
        }
    }

    let rule_dir = rule_dir.ok_or_else(|| {
        "missing --rules <dir>\n\
         usage: null-sigma-cli --rules <dir> [--on-error continue|fail-fast] \
         [--max-line-bytes N] [--max-error-samples N] [--threads N] [events.jsonl | -]"
            .to_string()
    })?;

    let events_path = match positional.len() {
        0 => None,
        1 => {
            let p = &positional[0];
            if p == "-" {
                None
            } else {
                Some(PathBuf::from(p))
            }
        }
        _ => {
            return Err(
                "too many positional arguments (expected at most one events path or -)".to_string(),
            )
        }
    };

    let _ = threads; // accepted; ST-only until §4b
    Ok(Args {
        threads,
        on_error,
        max_line_bytes,
        max_error_samples,
        rule_dir,
        events_path,
    })
}

fn parse_positive_usize(flag: &str, raw: &str) -> Result<usize, String> {
    let n: usize = raw
        .parse()
        .map_err(|_| format!("invalid {flag} value: {raw}"))?;
    if n == 0 {
        return Err(format!("{flag} must be > 0"));
    }
    Ok(n)
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

fn print_help() {
    eprintln!(
        "usage: null-sigma-cli --rules <dir> [options] [events.jsonl | -]\n\
         \n\
         --rules <dir>         Sigma YAML rule directory (required)\n\
         --on-error continue   count bad events and continue (default)\n\
         --on-error fail-fast  exit non-zero on first event error\n\
         --max-line-bytes N    reject lines larger than N bytes (default {DEFAULT_MAX_LINE_BYTES})\n\
         --max-error-samples N emit up to N ingest_error_sample lines (default 0)\n\
         --threads N           accepted for forward-compat; MVP is single-threaded\n\
         \n\
         events path omitted or '-' reads JSONL from stdin.\n\
         Day 1: stdout is match count; NDJSON alerts land Day 2."
    );
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let (engine, loaded, skipped, load_ms) = match rules::load_rules_from_dir(&args.rule_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let stats = match run_ingest(&args, &engine) {
        Ok(stats) => stats,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    emit_summary(&args, loaded, skipped, load_ms, &stats);

    let invariant_ok = stats.events_total == stats.events_ok + stats.events_failed;
    eprintln!(
        "ingest_accounting: events_total={} events_ok={} events_failed={} invariant_ok={invariant_ok}",
        stats.events_total, stats.events_ok, stats.events_failed,
    );
    if !invariant_ok {
        eprintln!(
            "FATAL: ingest accounting invariant violated: events_total={} != events_ok({}) + events_failed({})",
            stats.events_total, stats.events_ok, stats.events_failed,
        );
        std::process::exit(1);
    }

    // Day 1 temporary stdout — replaced by NDJSON alerts on Day 2.
    println!("{}", stats.matches);
}

fn run_ingest(
    args: &Args,
    engine: &null_sigma::SigmaEngine,
) -> Result<ingest::IngestStats, String> {
    let flatten = FlattenOptions::default();
    if let Some(path) = &args.events_path {
        let file = File::open(path)
            .map_err(|e| format!("cannot open events '{}': {e}", path.display()))?;
        let mut reader = BufReader::new(file);
        ingest_and_eval(
            &mut reader,
            engine,
            args.on_error,
            args.max_line_bytes,
            args.max_error_samples,
            flatten,
        )
    } else {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        ingest_and_eval(
            &mut reader,
            engine,
            args.on_error,
            args.max_line_bytes,
            args.max_error_samples,
            flatten,
        )
    }
}

fn emit_summary(
    args: &Args,
    loaded: usize,
    skipped: usize,
    load_ms: u128,
    stats: &ingest::IngestStats,
) {
    let scan = stats.t_read + stats.t_parse + stats.t_flat + stats.t_eval;
    let pct = |d: Duration| -> f64 {
        if scan.is_zero() {
            0.0
        } else {
            100.0 * d.as_secs_f64() / scan.as_secs_f64()
        }
    };
    let on_error = match args.on_error {
        OnErrorMode::Continue => "continue",
        OnErrorMode::FailFast => "fail-fast",
    };
    let input = args
        .events_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "- (stdin)".to_string());

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {} | \
         ok: {} failed: {} | matches: {} | threads: {} (st-mvp) | \
         on_error: {on_error} | max_line_bytes: {} | max_error_samples: {} | \
         input: {input} | scan: {:.3}s ({:.0} events/sec)",
        stats.events_total,
        stats.events_ok,
        stats.events_failed,
        stats.matches,
        args.threads,
        args.max_line_bytes,
        args.max_error_samples,
        scan.as_secs_f64(),
        if scan.is_zero() {
            0.0
        } else {
            stats.events_total as f64 / scan.as_secs_f64()
        },
    );
    eprintln!(
        "tier_b_tax: read={:.3}s ({:.1}%) parse={:.3}s ({:.1}%) flat={:.3}s ({:.1}%) \
         eval={:.3}s ({:.1}%) other={:.3}s ({:.1}%)",
        stats.t_read.as_secs_f64(),
        pct(stats.t_read),
        stats.t_parse.as_secs_f64(),
        pct(stats.t_parse),
        stats.t_flat.as_secs_f64(),
        pct(stats.t_flat),
        stats.t_eval.as_secs_f64(),
        pct(stats.t_eval),
        0.0,
        0.0,
    );
    eprintln!(
        "ingest_errors: io_read={} line_too_large={} json_parse={} flatten_not_object={} \
         flatten_depth={} flatten_fields={} flatten_total={} total={}",
        stats.errors.err_io_read,
        stats.errors.err_line_too_large,
        stats.errors.err_json_parse,
        stats.errors.err_flatten_not_object,
        stats.errors.err_flatten_depth,
        stats.errors.err_flatten_fields,
        stats.errors.flatten_total(),
        stats.errors.total()
    );
}
