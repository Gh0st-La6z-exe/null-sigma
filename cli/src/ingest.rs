//! Trust-first JSONL ingest (Week 1 parity) over any [`BufRead`].
//!
//! Evaluates each successfully flattened event immediately (streaming) and
//! emits alerts into a caller-owned [`Write`] (typically `BufWriter<StdoutLock>`).

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::time::Duration;

use null_sigma::json::{flatten_value_with, FlattenError, FlattenOptions};
use null_sigma::SigmaEngine;

use crate::output::{self, OutputFormat};

/// Default max bytes per JSONL line (8 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnErrorMode {
    Continue,
    FailFast,
}

#[derive(Clone, Copy, Debug)]
pub struct EmitOptions {
    pub format: OutputFormat,
    pub include_event: bool,
    pub flush_alerts: bool,
}

/// Runtime knobs for one ingest+eval pass (keeps `ingest_and_eval` arity down).
pub struct IngestConfig<'a> {
    pub engine: &'a SigmaEngine,
    pub on_error: OnErrorMode,
    pub max_line_bytes: usize,
    pub max_error_samples: usize,
    pub flatten_options: FlattenOptions,
    pub emit: EmitOptions,
}

#[derive(Debug, Default)]
pub struct ErrorCounters {
    pub err_io_read: u64,
    pub err_line_too_large: u64,
    pub err_json_parse: u64,
    pub err_flatten_not_object: u64,
    pub err_flatten_depth: u64,
    pub err_flatten_fields: u64,
}

impl ErrorCounters {
    pub fn flatten_total(&self) -> u64 {
        self.err_flatten_not_object + self.err_flatten_depth + self.err_flatten_fields
    }

    pub fn total(&self) -> u64 {
        self.err_io_read
            + self.err_line_too_large
            + self.err_json_parse
            + self.flatten_total()
    }
}

#[derive(Debug, Default)]
pub struct IngestStats {
    pub events_total: u64,
    pub events_ok: u64,
    pub events_failed: u64,
    pub matches: u64,
    pub t_read: Duration,
    pub t_parse: Duration,
    pub t_flat: Duration,
    pub t_eval: Duration,
    pub t_emit: Duration,
    pub errors: ErrorCounters,
}

fn record_flatten_error(counters: &mut ErrorCounters, err: &FlattenError) {
    match err {
        FlattenError::NotAnObject => counters.err_flatten_not_object += 1,
        FlattenError::DepthExceeded { .. } => counters.err_flatten_depth += 1,
        FlattenError::FieldsExceeded { .. } => counters.err_flatten_fields += 1,
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

/// Read JSONL, flatten, evaluate, and stream alerts into `out`.
pub fn ingest_and_eval<R: BufRead, W: Write>(
    reader: &mut R,
    out: &mut W,
    cfg: &IngestConfig<'_>,
) -> Result<IngestStats, String> {
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
                    cfg.on_error,
                    failed_line,
                    "io_read",
                    &format!("read error: {e}"),
                    cfg.max_error_samples,
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

        if trimmed.len() > cfg.max_line_bytes {
            stats.errors.err_line_too_large += 1;
            fail_event(
                &mut stats,
                cfg.on_error,
                line_number,
                "line_too_large",
                "line exceeds --max-line-bytes",
                cfg.max_error_samples,
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
                    cfg.on_error,
                    line_number,
                    "json_parse",
                    "bad event JSON",
                    cfg.max_error_samples,
                    &mut error_samples_emitted,
                )?;
                continue;
            }
        };
        stats.t_parse += t0.elapsed();

        let t0 = std::time::Instant::now();
        let event: HashMap<String, String> =
            match flatten_value_with(&value, cfg.flatten_options) {
                Ok(event) => event,
                Err(err) => {
                    stats.t_flat += t0.elapsed();
                    record_flatten_error(&mut stats.errors, &err);
                    let kind = flatten_error_kind(&err);
                    fail_event(
                        &mut stats,
                        cfg.on_error,
                        line_number,
                        kind,
                        "flatten failed",
                        cfg.max_error_samples,
                        &mut error_samples_emitted,
                    )?;
                    continue;
                }
            };
        stats.t_flat += t0.elapsed();

        let t0 = std::time::Instant::now();
        let matches = cfg.engine.evaluate_event(&event);
        stats.t_eval += t0.elapsed();

        stats.matches += matches.len() as u64;
        for m in &matches {
            let t0 = std::time::Instant::now();
            output::write_alert(
                out,
                cfg.emit.format,
                cfg.emit.include_event,
                m,
                &event,
            )
            .map_err(output::map_write_err)?;
            if cfg.emit.flush_alerts {
                out.flush().map_err(output::map_write_err)?;
            }
            stats.t_emit += t0.elapsed();
        }

        stats.events_ok += 1;
    }

    Ok(stats)
}
