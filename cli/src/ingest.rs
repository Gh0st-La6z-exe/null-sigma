//! Trust-first JSONL line evaluation (Week 1 counter contract).
//!
//! Per-line work shared by the sequenced pipeline — workers write alerts into
//! a local buffer and accumulate [`ChunkTrustMetrics`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Runtime knobs for one ingest+eval pass.
pub struct IngestConfig {
    pub on_error: OnErrorMode,
    pub max_line_bytes: usize,
    pub max_error_samples: usize,
    pub flatten_options: FlattenOptions,
    pub emit: EmitOptions,
}

#[derive(Debug, Default, Clone)]
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
        self.err_io_read + self.err_line_too_large + self.err_json_parse + self.flatten_total()
    }

    pub fn merge_from(&mut self, other: &Self) {
        self.err_io_read += other.err_io_read;
        self.err_line_too_large += other.err_line_too_large;
        self.err_json_parse += other.err_json_parse;
        self.err_flatten_not_object += other.err_flatten_not_object;
        self.err_flatten_depth += other.err_flatten_depth;
        self.err_flatten_fields += other.err_flatten_fields;
    }
}

/// Per-chunk trust bag returned to the ordered sink.
#[derive(Debug, Default, Clone)]
pub struct ChunkTrustMetrics {
    pub events_total: u64,
    pub events_ok: u64,
    pub events_failed: u64,
    pub matches: u64,
    pub t_parse: Duration,
    pub t_flat: Duration,
    pub t_eval: Duration,
    pub t_emit: Duration,
    pub errors: ErrorCounters,
}

impl ChunkTrustMetrics {
    pub fn merge_into(&self, stats: &mut IngestStats) {
        stats.events_total += self.events_total;
        stats.events_ok += self.events_ok;
        stats.events_failed += self.events_failed;
        stats.matches += self.matches;
        stats.t_parse += self.t_parse;
        stats.t_flat += self.t_flat;
        stats.t_eval += self.t_eval;
        stats.t_emit += self.t_emit;
        stats.errors.merge_from(&self.errors);
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
    samples: &AtomicUsize,
) {
    if max_error_samples == 0 {
        return;
    }
    let prev = samples.fetch_add(1, Ordering::Relaxed);
    if prev >= max_error_samples {
        return;
    }
    eprintln!("ingest_error_sample: line={line_number} kind={kind} msg=\"{msg}\"");
}

/// Shared knobs for worker-side line evaluation (no engine borrow lifetime).
#[derive(Clone, Copy)]
pub struct LineEvalParams {
    pub on_error: OnErrorMode,
    pub max_line_bytes: usize,
    pub max_error_samples: usize,
    pub flatten_options: FlattenOptions,
    pub emit: EmitOptions,
}

impl LineEvalParams {
    pub fn from_config(cfg: &IngestConfig) -> Self {
        Self {
            on_error: cfg.on_error,
            max_line_bytes: cfg.max_line_bytes,
            max_error_samples: cfg.max_error_samples,
            flatten_options: cfg.flatten_options,
            emit: cfg.emit,
        }
    }
}

/// Process one non-empty JSONL line into `alerts` / `trust`.
///
/// Returns `Err(msg)` only for fail-fast event errors (or stdout/blob write errors).
pub fn eval_line(
    engine: &SigmaEngine,
    params: &LineEvalParams,
    line_number: u64,
    trimmed: &str,
    alerts: &mut Vec<u8>,
    trust: &mut ChunkTrustMetrics,
    samples: &AtomicUsize,
) -> Result<(), String> {
    trust.events_total += 1;

    if trimmed.len() > params.max_line_bytes {
        trust.errors.err_line_too_large += 1;
        return fail_line(
            trust,
            params,
            line_number,
            "line_too_large",
            "line exceeds --max-line-bytes",
            samples,
        );
    }

    let t0 = std::time::Instant::now();
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(_) => {
            trust.t_parse += t0.elapsed();
            trust.errors.err_json_parse += 1;
            return fail_line(
                trust,
                params,
                line_number,
                "json_parse",
                "bad event JSON",
                samples,
            );
        }
    };
    trust.t_parse += t0.elapsed();

    let t0 = std::time::Instant::now();
    let event: HashMap<String, String> = match flatten_value_with(&value, params.flatten_options) {
        Ok(event) => event,
        Err(err) => {
            trust.t_flat += t0.elapsed();
            record_flatten_error(&mut trust.errors, &err);
            let kind = flatten_error_kind(&err);
            return fail_line(trust, params, line_number, kind, "flatten failed", samples);
        }
    };
    trust.t_flat += t0.elapsed();

    let t0 = std::time::Instant::now();
    let matches = engine.evaluate_event(&event);
    trust.t_eval += t0.elapsed();

    trust.matches += matches.len() as u64;
    for m in &matches {
        let t0 = std::time::Instant::now();
        output::write_alert(
            alerts,
            params.emit.format,
            params.emit.include_event,
            m,
            &event,
        )
        .map_err(output::map_write_err)?;
        trust.t_emit += t0.elapsed();
    }

    trust.events_ok += 1;
    Ok(())
}

fn fail_line(
    trust: &mut ChunkTrustMetrics,
    params: &LineEvalParams,
    line_number: u64,
    kind: &str,
    msg: &str,
    samples: &AtomicUsize,
) -> Result<(), String> {
    maybe_emit_error_sample(line_number, kind, msg, params.max_error_samples, samples);
    trust.events_failed += 1;
    if params.on_error == OnErrorMode::FailFast {
        Err(msg.to_string())
    } else {
        Ok(())
    }
}

/// Record a chunker-detected oversized line into trust (and fail-fast if set).
pub fn record_line_too_large(
    trust: &mut ChunkTrustMetrics,
    params: &LineEvalParams,
    line_number: u64,
    samples: &AtomicUsize,
) -> Result<(), String> {
    trust.events_total += 1;
    trust.errors.err_line_too_large += 1;
    fail_line(
        trust,
        params,
        line_number,
        "line_too_large",
        "line exceeds --max-line-bytes",
        samples,
    )
}
