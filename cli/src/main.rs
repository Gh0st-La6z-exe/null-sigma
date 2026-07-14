//! null-sigma-cli — ROADMAP §4 product CLI (sequenced block-chunk MT, §4b).
//!
//! Usage:
//!   null-sigma-cli --rules <dir> [options] [events.jsonl | -]
//!
//! Omit the events path or pass `-` to read JSONL from stdin.
//! Stdout = alerts only (buffered / ordered chunks); stderr = trust / tax.

mod chunker;
mod ingest;
mod output;
mod pipeline;
mod rules;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ingest::{EmitOptions, IngestConfig, OnErrorMode, DEFAULT_MAX_LINE_BYTES};
use null_sigma::json::FlattenOptions;
use output::OutputFormat;
use pipeline::run_pipeline;

struct Args {
    threads: usize,
    on_error: OnErrorMode,
    max_line_bytes: usize,
    max_error_samples: usize,
    format: OutputFormat,
    include_event: bool,
    flush_alerts: bool,
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
    let mut format = OutputFormat::Ndjson;
    let mut include_event = false;
    let mut flush_alerts = false;
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
        } else if arg == "--format" {
            let v = iter
                .next()
                .ok_or_else(|| "--format requires a value".to_string())?;
            format = OutputFormat::parse(&v)?;
        } else if let Some(v) = arg.strip_prefix("--format=") {
            format = OutputFormat::parse(v)?;
        } else if arg == "--include-event" {
            include_event = true;
        } else if arg == "--flush-alerts" {
            flush_alerts = true;
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
         usage: null-sigma-cli --rules <dir> [options] [events.jsonl | -]"
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

    Ok(Args {
        threads,
        on_error,
        max_line_bytes,
        max_error_samples,
        format,
        include_event,
        flush_alerts,
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
         --format ndjson|text  alert stdout format (default ndjson)\n\
         --include-event       include full flattened event in NDJSON alerts\n\
         --flush-alerts        flush stdout after each released chunk (live pipes)\n\
         --threads N           eval workers (1=default; 0=all cores); ordered alerts\n\
         \n\
         events path omitted or '-' reads JSONL from stdin.\n\
         stdout = alerts only (sequenced chunks); stderr = trust/tax diagnostics.\n\
         See PERFORMANCE.md §11.10 / §4b for I/O + pipeline policy."
    );
}

fn resolve_threads_display(threads: usize) -> usize {
    if threads == 0 {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    } else {
        threads.max(1)
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

    let (engine, loaded, skipped, load_ms) = match rules::load_rules_from_dir(&args.rule_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };
    let engine = Arc::new(engine);

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let stats = match run_ingest(&args, Arc::clone(&engine), &mut out) {
        Ok(stats) => stats,
        Err(msg) if msg == "broken_pipe" => {
            let _ = out.flush();
            std::process::exit(0);
        }
        Err(msg) => {
            let _ = out.flush();
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    if let Err(err) = out.flush() {
        if err.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("stdout flush error: {err}");
        std::process::exit(1);
    }

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
}

fn run_ingest(
    args: &Args,
    engine: Arc<null_sigma::SigmaEngine>,
    out: &mut impl Write,
) -> Result<ingest::IngestStats, String> {
    let cfg = IngestConfig {
        on_error: args.on_error,
        max_line_bytes: args.max_line_bytes,
        max_error_samples: args.max_error_samples,
        flatten_options: FlattenOptions::default(),
        emit: EmitOptions {
            format: args.format,
            include_event: args.include_event,
            flush_alerts: args.flush_alerts,
        },
    };
    if let Some(path) = &args.events_path {
        let file = File::open(path)
            .map_err(|e| format!("cannot open events '{}': {e}", path.display()))?;
        run_pipeline(file, out, engine, &cfg, args.threads)
    } else {
        let stdin = std::io::stdin();
        let locked = stdin.lock();
        run_pipeline(locked, out, engine, &cfg, args.threads)
    }
}

fn emit_summary(
    args: &Args,
    loaded: usize,
    skipped: usize,
    load_ms: u128,
    stats: &ingest::IngestStats,
) {
    let scan = stats.t_read + stats.t_parse + stats.t_flat + stats.t_eval + stats.t_emit;
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
    let format = match args.format {
        OutputFormat::Ndjson => "ndjson",
        OutputFormat::Text => "text",
    };
    let input = args
        .events_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "- (stdin)".to_string());
    let threads = resolve_threads_display(args.threads);

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {} | \
         ok: {} failed: {} | matches: {} | threads: {threads} | \
         on_error: {on_error} | format: {format} | include_event: {} | flush_alerts: {} | \
         max_line_bytes: {} | max_error_samples: {} | input: {input} | \
         scan: {:.3}s ({:.0} events/sec)",
        stats.events_total,
        stats.events_ok,
        stats.events_failed,
        stats.matches,
        args.include_event,
        args.flush_alerts,
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
         eval={:.3}s ({:.1}%) emit={:.3}s ({:.1}%) other={:.3}s ({:.1}%)",
        stats.t_read.as_secs_f64(),
        pct(stats.t_read),
        stats.t_parse.as_secs_f64(),
        pct(stats.t_parse),
        stats.t_flat.as_secs_f64(),
        pct(stats.t_flat),
        stats.t_eval.as_secs_f64(),
        pct(stats.t_eval),
        stats.t_emit.as_secs_f64(),
        pct(stats.t_emit),
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
