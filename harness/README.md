# null-sigma head-to-head benchmark harness

Roadmap item 3. Compares **null-sigma**, **tau-engine** (Chainsaw's matching
core), and **sigma-rust** on the same SigmaHQ rules and seeded event stream.
Also measures CLI end-to-end wall-clock vs Hayabusa and Chainsaw.

The harness is a standalone workspace crate — it does not modify the core
library except to consume it.

## Prerequisites

```bash
# SigmaHQ corpus (dev-only, gitignored)
git clone --depth 1 https://github.com/SigmaHQ/sigma.git corpus/sigmahq

# Tier B only
brew install hyperfine
```

## Measurement tiers

| Tier | What | Command | Comparable? |
|---|---|---|---|
| **0** | Synthetic micro-rules (prefilter scaling) | `cargo bench --bench sigma_bench` (root crate) | Internal only |
| **A** | Matcher-level, real rules, library APIs | `cargo bench --bench head_to_head` | null-sigma vs tau vs sigma-rust |
| **B** | Full CLI wall-clock | `./scripts/run_cli_bench.sh` | Includes parse/enrich/output |

**Never conflate Tier A and Tier B.** Tier A times only the matching call with
pre-built native event representations. Tier B includes JSON parsing, field
enrichment, alert formatting, and (for Hayabusa) multi-threading.

## Correctness gate (run first)

```bash
cd harness
cargo run --release --bin cross_check
```

Loads SigmaHQ `rules/windows/process_creation` (1 182 files) into all three
engines, evaluates every common rule against 2 000 seeded events, and reports
pairwise disagreements.

Latest result (2026-07-07):

| Pair | Disagreements | Rate |
|---|---|---|
| null-sigma vs sigma-rust | **0** | 0.0000% |
| null-sigma vs tau-engine | 13 | 0.0006% |
| tau-engine vs sigma-rust | 13 | 0.0006% |

The 13 cells are all on `Suspicious SYSTEM User Process Creation` — attributable
to Chainsaw converter semantics, not an engine bug in null-sigma.

Load compatibility:

| Engine | Loaded | Rate |
|---|---|---|
| null-sigma | 1 182 | 100.0% |
| tau-engine (Chainsaw converter) | 1 102 | 93.2% |
| sigma-rust | 1 181 | 99.9% |

## Tier A — Criterion (matcher-level)

```bash
cd harness
cargo bench --bench head_to_head
```

Benchmarks (1 102 common rules, seed-42 events, Apple M4, release, 2026-07-08):

| Benchmark | null-sigma | tau-engine | sigma-rust |
|---|---|---|---|
| `single_benign_event` | **309 µs** | **136 µs** | 4.61 ms |
| `batch_1000_events` | 373 ms | 142 ms | 3.94 s |
| `rule_load` | 71 ms | 200 ms | 43 ms |

null-sigma also benchmarks `null_sigma_full` with all 1 182 rules it loads
(`single_benign_event/null_sigma_full`: ~369 µs).

Interactive HTML: `harness/target/criterion/report/index.html`

## Profiling gate (local only)

Tier A `prof_benign` — same workload as `single_benign_event`. Run before and
after matcher changes to validate hotspot shifts. Output under `harness/prof/`
(gitignored).

```bash
cargo install samply   # once
cd harness && ./scripts/prof_benign.sh
```

Produces:
- `prof/samply_*.json.gz` — open with `samply load …` (Firefox Profiler)
- `prof/sample_*.txt` — run `sample $BPID` during the 100k loop for symbolicated stacks (see script output)
- `prof/summary_*.txt` — fill after review (template: `scripts/prof_NOTES.template.md`)

Do not commit `harness/prof/` artifacts.

## Tier B — CLI end-to-end (hyperfine)

```bash
cd harness
./scripts/run_cli_bench.sh          # default: 100k events, seed 42
EVENTS=10000 ./scripts/run_cli_bench.sh   # smaller smoke run

# Trust-policy smoke (mixed good/bad JSONL)
./scripts/smoke_error_policy.sh

# Day 2 robustness corpus (depth/field guards, line limit)
./scripts/smoke_robustness.sh
```

Downloads pinned binaries to `harness/bin/` (gitignored):

- Hayabusa **3.9.0** (native aarch64)
- Chainsaw **2.13.1** (x86_64 under Rosetta 2 on Apple Silicon — noted in report)

Dataset: deterministic flat JSONL (`gen_dataset` binary, seed 42).

Latest hyperfine (100k events, 2026-07-08, Rayon prototype; warmup 1 + 5 runs):

| Command | Mean | Events/sec |
|---|---|---|
| `null-sigma-runner-default-threads` | **15.2 s ± 0.3** | **6 560** |
| `hayabusa-default-threads` | 23.9 s ± 0.3 | 4 190 |
| `null-sigma-runner-4-thread` | 18.0 s ± 2.0 | 5 550 |
| `chainsaw-hunt` | 37.3 s ± 1.0 | 2 680 |
| `null-sigma-runner` | **45.2 s ± 0.2** | **2 210** |
| `hayabusa-1-thread` | 57.3 s ± 0.8 | 1 750 |

**Single-thread win:** null-sigma ~1.27× faster than Hayabusa `--threads 1`.
**Multi-thread win:** null-sigma `--threads 0` ~1.57× faster than Hayabusa default.
Parity gate: `./scripts/smoke_parallel.sh` (10k events, threads 1/2/4/8/0).
Tax split: **eval 99%** — see `PERFORMANCE.md` §11.5a.

Written to `harness/data/tier_b_results.md` (gitignored).

### Chainsaw JSON mapping

Chainsaw's bundled EVTX mapping expects nested `Event.System.*` documents.
For JSONL input we ship `config/chainsaw-json-mapping.yml` (`kind: json`) so
flat nxlog-style records produce non-zero detections. Without it, Chainsaw
silently matches nothing on JSONL and looks artificially fast.

## Binaries

| Binary | Purpose |
|---|---|
| `cross_check` | Correctness gate — run before publishing numbers |
| `null_sigma_run` | Tier B reference CLI (`[--threads N] [--on-error continue|fail-fast] [--max-line-bytes N] rule_dir events.jsonl`); prints `tier_b_tax` + honest ingest error accounting |
| `gen_dataset` | Deterministic JSONL event generator |
| `prof_benign` | Tier A profiling target (`--profile prof`) |

Scripts: `scripts/smoke_parallel.sh` (thread-count parity on 10k events),
`scripts/smoke_error_policy.sh` (continue/fail-fast trust checks),
`scripts/smoke_robustness.sh` (malformed corpus + guard checks; asserts
`ingest_errors` line parity across `--threads 1` and `--threads 0`).

### Trust-first ingestion policy

- Default mode is `--on-error continue`: event-level parse/flatten/read errors
  are counted and reported, and the run completes.
- `--on-error fail-fast` exits non-zero on the first event-level error.
- Startup/config errors (cannot read rules/events file) always exit non-zero.
- Summary accounting invariant (`events_total = events_ok + events_failed`) is
  reported on stderr and **enforced**: violation prints `FATAL:` and exits 1
  before match output.
- Flatten failures are split honestly:
  `flatten_not_object`, `flatten_depth`, `flatten_fields`.
- `--max-line-bytes` (default 8 MiB) rejects oversize JSONL lines before parse.
  Enforced after `read_line`, so it blocks JSON parse/flatten heap growth but not
  line-buffer allocation on pathological unterminated lines; bounded byte-loop
  ingest is deferred to Phase 3 streaming rewrite.
- Ingest error counters are single-threaded (no atomics); Rayon parallelizes eval only.
- Malformed corpus fixtures live in `tests/fixtures/robustness/` (see README there).

## Layout

```
harness/
├── benches/head_to_head.rs    # Tier A
├── src/
│   ├── lib.rs                 # Engine wrappers, rule compatibility
│   ├── convert.rs             # Sigma → tau (Chainsaw path)
│   └── gen.rs                 # Event generator
├── src/bin/
│   ├── cross_check.rs
│   ├── null_sigma_run.rs
│   ├── gen_dataset.rs
│   └── prof_benign.rs         # Profiling gate (local)
├── scripts/
│   ├── run_cli_bench.sh       # Tier B
│   ├── smoke_parallel.sh      # Thread-count parity (10k)
│   ├── smoke_error_policy.sh  # continue/fail-fast policy
│   ├── smoke_robustness.sh    # malformed corpus + guards
│   └── prof_benign.sh         # samply profiling (local output → prof/)
├── prof/                      # gitignored — profiles + summary notes
├── config/chainsaw-json-mapping.yml
└── data/tier_b_results.md     # Latest Tier B output
```

Full performance analysis: `../PERFORMANCE.md` §11.
