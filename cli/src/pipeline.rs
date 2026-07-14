//! Sequenced block-chunk pipeline: chunker → Rayon workers → ordered sink.
//!
//! Workers never touch stdout. The main thread releases `(ChunkID, alerts)` in
//! order and merges [`ChunkTrustMetrics`] sequentially.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::Instant;

use rayon::ThreadPoolBuilder;

use crate::chunker::{ChunkItem, Chunker};
use crate::ingest::{
    eval_line, record_line_too_large, ChunkTrustMetrics, IngestConfig, IngestStats, LineEvalParams,
    OnErrorMode,
};
use crate::output;

/// Worker / sink unit.
struct ChunkResult {
    id: u64,
    alerts: Vec<u8>,
    trust: ChunkTrustMetrics,
    /// Fail-fast message, if this chunk hit a fatal event error.
    fatal: Option<String>,
    /// Wall time attributed to chunker wait / submit path (read) — filled by main.
    t_read: std::time::Duration,
}

fn process_data_chunk(
    engine: &null_sigma::SigmaEngine,
    params: &LineEvalParams,
    start_line: u64,
    bytes: &[u8],
    samples: &AtomicUsize,
) -> ChunkResult {
    let mut alerts = Vec::new();
    let mut trust = ChunkTrustMetrics::default();
    let mut fatal = None;
    let mut line_number = start_line;

    for raw in bytes.split_inclusive(|&b| b == b'\n') {
        let trimmed = match std::str::from_utf8(raw) {
            Ok(s) => s.trim(),
            Err(_) => {
                trust.events_total += 1;
                trust.errors.err_json_parse += 1;
                trust.events_failed += 1;
                if params.on_error == OnErrorMode::FailFast {
                    fatal = Some("bad event JSON".to_string());
                    break;
                }
                line_number += 1;
                continue;
            }
        };
        if trimmed.is_empty() {
            line_number += 1;
            continue;
        }
        if let Err(msg) = eval_line(
            engine,
            params,
            line_number,
            trimmed,
            &mut alerts,
            &mut trust,
            samples,
        ) {
            fatal = Some(msg);
            break;
        }
        line_number += 1;
    }

    ChunkResult {
        id: 0, // filled by caller
        alerts,
        trust,
        fatal,
        t_read: std::time::Duration::ZERO,
    }
}

fn process_item(
    engine: &null_sigma::SigmaEngine,
    params: &LineEvalParams,
    item: ChunkItem,
    samples: &AtomicUsize,
) -> ChunkResult {
    match item {
        ChunkItem::Data {
            id,
            start_line,
            bytes,
        } => {
            let mut r = process_data_chunk(engine, params, start_line, &bytes, samples);
            r.id = id;
            r
        }
        ChunkItem::LineTooLarge { id, line_number } => {
            let mut trust = ChunkTrustMetrics::default();
            let fatal =
                record_line_too_large(&mut trust, params, line_number, samples).err();
            ChunkResult {
                id,
                alerts: Vec::new(),
                trust,
                fatal,
                t_read: std::time::Duration::ZERO,
            }
        }
    }
}

fn resolve_threads(threads: usize) -> usize {
    if threads == 0 {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .max(1)
    } else {
        threads.max(1)
    }
}

/// Run the sequenced pipeline. `threads == 1` uses the same chunker/worker/sink path synchronously.
pub fn run_pipeline<R: Read, W: Write>(
    reader: R,
    out: &mut W,
    engine: Arc<null_sigma::SigmaEngine>,
    cfg: &IngestConfig,
    threads: usize,
) -> Result<IngestStats, String> {
    let threads = resolve_threads(threads);
    let params = LineEvalParams::from_config(cfg);
    let samples = Arc::new(AtomicUsize::new(0));

    if threads == 1 {
        return run_pipeline_st(
            reader,
            out,
            &params,
            &engine,
            &samples,
            cfg.emit.flush_alerts,
        );
    }

    run_pipeline_mt(
        reader,
        out,
        &params,
        engine,
        samples,
        threads,
        cfg.emit.flush_alerts,
        cfg.on_error,
    )
}

fn release_result<W: Write>(
    out: &mut W,
    stats: &mut IngestStats,
    result: ChunkResult,
    flush_alerts: bool,
) -> Result<(), String> {
    stats.t_read += result.t_read;
    result.trust.merge_into(stats);
    if !result.alerts.is_empty() {
        out.write_all(&result.alerts)
            .map_err(output::map_write_err)?;
        if flush_alerts {
            out.flush().map_err(output::map_write_err)?;
        }
    }
    if let Some(msg) = result.fatal {
        return Err(msg);
    }
    Ok(())
}

fn run_pipeline_st<R: Read, W: Write>(
    reader: R,
    out: &mut W,
    params: &LineEvalParams,
    engine: &null_sigma::SigmaEngine,
    samples: &AtomicUsize,
    flush_alerts: bool,
) -> Result<IngestStats, String> {
    let mut chunker = Chunker::new(reader, params.max_line_bytes);
    let mut stats = IngestStats::default();
    loop {
        let t0 = Instant::now();
        let item = match chunker.next_item() {
            Ok(v) => v,
            Err(msg) => {
                stats.errors.err_io_read += 1;
                stats.events_total += 1;
                stats.events_failed += 1;
                if params.on_error == OnErrorMode::FailFast {
                    return Err(msg);
                }
                // continue mode: stop reading after io error
                break;
            }
        };
        let t_read = t0.elapsed();
        let Some(item) = item else {
            break;
        };
        let mut result = process_item(engine, params, item, samples);
        result.t_read = t_read;
        release_result(out, &mut stats, result, flush_alerts)?;
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn run_pipeline_mt<R: Read, W: Write>(
    reader: R,
    out: &mut W,
    params: &LineEvalParams,
    engine: Arc<null_sigma::SigmaEngine>,
    samples: Arc<AtomicUsize>,
    threads: usize,
    flush_alerts: bool,
    on_error: OnErrorMode,
) -> Result<IngestStats, String> {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("failed to build Rayon thread pool: {e}"))?;

    let max_inflight = threads.saturating_mul(2).max(2);
    let (tx, rx) = sync_channel::<ChunkResult>(max_inflight);

    let mut chunker = Chunker::new(reader, params.max_line_bytes);
    let mut stats = IngestStats::default();
    let mut pending: BTreeMap<u64, ChunkResult> = BTreeMap::new();
    let mut next_expected = 0u64;
    let mut inflight = 0usize;
    let mut eof = false;
    let mut fatal_io: Option<String> = None;

    let params = *params;

    loop {
        while !eof && fatal_io.is_none() && inflight < max_inflight {
            let t0 = Instant::now();
            let item = match chunker.next_item() {
                Ok(v) => v,
                Err(msg) => {
                    stats.errors.err_io_read += 1;
                    stats.events_total += 1;
                    stats.events_failed += 1;
                    eof = true;
                    if on_error == OnErrorMode::FailFast {
                        fatal_io = Some(msg);
                    }
                    break;
                }
            };
            let t_read = t0.elapsed();
            let Some(item) = item else {
                eof = true;
                break;
            };

            let eng = Arc::clone(&engine);
            let samp = Arc::clone(&samples);
            let tx = tx.clone();
            inflight += 1;
            pool.spawn(move || {
                let mut result = process_item(&eng, &params, item, &samp);
                result.t_read = t_read;
                let _ = tx.send(result);
            });
        }

        if inflight == 0 {
            if eof || fatal_io.is_some() {
                break;
            }
            continue;
        }

        let result = rx
            .recv()
            .map_err(|_| "worker channel disconnected".to_string())?;
        inflight -= 1;
        pending.insert(result.id, result);

        while let Some(result) = pending.remove(&next_expected) {
            release_result(out, &mut stats, result, flush_alerts)?;
            next_expected += 1;
        }

        if fatal_io.is_some() && inflight == 0 {
            break;
        }
    }

    drop(tx);
    while inflight > 0 {
        if let Ok(result) = rx.recv() {
            pending.insert(result.id, result);
        }
        inflight -= 1;
    }
    // Release any contiguous prefix still held (continue-mode IO stop).
    while let Some(result) = pending.remove(&next_expected) {
        release_result(out, &mut stats, result, flush_alerts)?;
        next_expected += 1;
    }

    if let Some(msg) = fatal_io {
        return Err(msg);
    }

    Ok(stats)
}
