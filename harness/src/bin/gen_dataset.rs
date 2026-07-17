//! Write the deterministic event stream to disk for the Tier B CLI
//! benchmark: one flat JSONL file (null-sigma runner input) and one
//! EVTX-dump-shaped JSONL file (Hayabusa `-J` / Chainsaw input).
//!
//! Usage:
//!   gen_dataset <out_dir> [count] [seed]
//!   gen_dataset <out_dir> [count] [seed] --a4-hit-bpm <N>
//!
//! `--a4-hit-bpm N` (0..=10000) writes A4 firehose fixtures with controlled
//! event-hit rate p = N/10000 and field `A4Hit` = "1"|"0".

use std::io::Write;

use null_sigma_harness::gen;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: gen_dataset <out_dir> [count] [seed] [--a4-hit-bpm N]\n\
             \n\
             --a4-hit-bpm N   A4 firehose: hit rate N/10000 (0..=10000)"
        );
        std::process::exit(2);
    }

    let out_dir = std::path::Path::new(&args[1]);
    let mut count: usize = 100_000;
    let mut seed: u64 = 42;
    let mut hit_bpm: Option<u32> = None;
    let mut positional = 0usize;

    let mut i = 2usize;
    while i < args.len() {
        let a = &args[i];
        if a == "--a4-hit-bpm" {
            let raw = args.get(i + 1).unwrap_or_else(|| {
                eprintln!("--a4-hit-bpm requires a value");
                std::process::exit(2);
            });
            let n: u32 = raw.parse().unwrap_or_else(|_| {
                eprintln!("invalid --a4-hit-bpm value: {raw}");
                std::process::exit(2);
            });
            if n > 10_000 {
                eprintln!("--a4-hit-bpm must be 0..=10000");
                std::process::exit(2);
            }
            hit_bpm = Some(n);
            i += 2;
        } else if let Some(n) = a.strip_prefix("--a4-hit-bpm=") {
            let n: u32 = n.parse().unwrap_or_else(|_| {
                eprintln!("invalid --a4-hit-bpm value: {n}");
                std::process::exit(2);
            });
            if n > 10_000 {
                eprintln!("--a4-hit-bpm must be 0..=10000");
                std::process::exit(2);
            }
            hit_bpm = Some(n);
            i += 1;
        } else if a.starts_with('-') {
            eprintln!("unknown flag: {a}");
            std::process::exit(2);
        } else {
            match positional {
                0 => {
                    count = a.parse().unwrap_or_else(|_| {
                        eprintln!("invalid count: {a}");
                        std::process::exit(2);
                    });
                }
                1 => {
                    seed = a.parse().unwrap_or_else(|_| {
                        eprintln!("invalid seed: {a}");
                        std::process::exit(2);
                    });
                }
                _ => {
                    eprintln!("too many positional arguments");
                    std::process::exit(2);
                }
            }
            positional += 1;
            i += 1;
        }
    }

    std::fs::create_dir_all(out_dir).expect("create out dir");
    let events = match hit_bpm {
        Some(bpm) => gen::generate_a4(seed, count, bpm),
        None => gen::generate(seed, count),
    };

    let (flat_name, evtx_name) = match hit_bpm {
        Some(bpm) => (
            format!("events_flat_a4_{count}_bpm{bpm}.jsonl"),
            format!("events_evtx_a4_{count}_bpm{bpm}.jsonl"),
        ),
        None => (
            format!("events_flat_{count}.jsonl"),
            format!("events_evtx_{count}.jsonl"),
        ),
    };

    let flat_path = out_dir.join(&flat_name);
    let mut flat = std::io::BufWriter::new(std::fs::File::create(&flat_path).expect("create"));
    for e in &events {
        serde_json::to_writer(&mut flat, e).expect("write");
        flat.write_all(b"\n").expect("write");
    }
    flat.flush().expect("flush");

    let evtx_path = out_dir.join(&evtx_name);
    let mut evtx = std::io::BufWriter::new(std::fs::File::create(&evtx_path).expect("create"));
    for (idx, e) in events.iter().enumerate() {
        serde_json::to_writer(&mut evtx, &gen::to_evtx_json(e, idx as u64 + 1)).expect("write");
        evtx.write_all(b"\n").expect("write");
    }
    evtx.flush().expect("flush");

    if let Some(bpm) = hit_bpm {
        let expected = gen::a4_expected_hits(count, bpm);
        eprintln!(
            "wrote {count} A4 events (seed {seed}, hit_bpm={bpm}, expected_hits={expected}) to {} and {}",
            flat_path.display(),
            evtx_path.display()
        );
    } else {
        eprintln!(
            "wrote {count} events (seed {seed}) to {} and {}",
            flat_path.display(),
            evtx_path.display()
        );
    }
}
