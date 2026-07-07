//! Write the deterministic event stream to disk for the Tier B CLI
//! benchmark: one flat JSONL file (null-sigma runner input) and one
//! EVTX-dump-shaped JSONL file (Hayabusa `-J` / Chainsaw input).
//!
//! Usage: gen_dataset <out_dir> [count] [seed]

use std::io::Write;

use null_sigma_harness::gen;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: gen_dataset <out_dir> [count] [seed]");
        std::process::exit(2);
    }
    let out_dir = std::path::Path::new(&args[1]);
    let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let seed: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(42);

    std::fs::create_dir_all(out_dir).expect("create out dir");
    let events = gen::generate(seed, count);

    let flat_path = out_dir.join(format!("events_flat_{count}.jsonl"));
    let mut flat = std::io::BufWriter::new(std::fs::File::create(&flat_path).expect("create"));
    for e in &events {
        serde_json::to_writer(&mut flat, e).expect("write");
        flat.write_all(b"\n").expect("write");
    }
    flat.flush().expect("flush");

    let evtx_path = out_dir.join(format!("events_evtx_{count}.jsonl"));
    let mut evtx = std::io::BufWriter::new(std::fs::File::create(&evtx_path).expect("create"));
    for (i, e) in events.iter().enumerate() {
        serde_json::to_writer(&mut evtx, &gen::to_evtx_json(e, i as u64 + 1)).expect("write");
        evtx.write_all(b"\n").expect("write");
    }
    evtx.flush().expect("flush");

    eprintln!(
        "wrote {} events (seed {seed}) to {} and {}",
        count,
        flat_path.display(),
        evtx_path.display()
    );
}
