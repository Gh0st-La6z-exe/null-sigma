//! Integration tests for `null_sigma_run` trust behavior.
//! Hermetic: uses committed fixtures only (no SigmaHQ corpus).

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness manifest has parent")
        .to_path_buf()
}

fn runner_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_null_sigma_run"))
}

fn rule_dir() -> PathBuf {
    repo_root().join("tests/fixtures/rules/minimal")
}

fn mixed_fixture() -> PathBuf {
    repo_root().join("tests/fixtures/robustness/mixed_valid_invalid.jsonl")
}

fn run_runner(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(runner_path());
    cmd.args(args);
    cmd.output().expect("spawn null_sigma_run")
}

fn stderr_utf8(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_utf8(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn continue_mode_reports_expected_ingest_accounting() {
    let rules = rule_dir();
    let events = mixed_fixture();
    let output = run_runner(&[
        "--on-error",
        "continue",
        rules.to_str().unwrap(),
        events.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "continue mode should exit 0: {}",
        stderr_utf8(&output)
    );

    let stderr = stderr_utf8(&output);
    assert!(
        stderr.contains(
            "ingest_errors: io_read=0 line_too_large=0 json_parse=1 flatten_not_object=1 flatten_depth=0 flatten_fields=0 flatten_total=1 total=2"
        ),
        "unexpected ingest_errors line: {stderr}"
    );
    assert!(
        stderr.contains(
            "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true"
        ),
        "unexpected ingest_accounting line: {stderr}"
    );
    assert!(
        !stdout_utf8(&output).trim().is_empty(),
        "stdout should contain match count"
    );
}

#[test]
fn fail_fast_mode_exits_nonzero_on_first_bad_event() {
    let rules = rule_dir();
    let events = mixed_fixture();
    let output = run_runner(&[
        "--on-error",
        "fail-fast",
        rules.to_str().unwrap(),
        events.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "fail-fast should exit non-zero on mixed fixture"
    );

    let stderr = stderr_utf8(&output);
    assert!(
        stderr.contains("bad event JSON")
            || stderr.contains("flatten failed")
            || stderr.contains("read error")
            || stderr.contains("line exceeds"),
        "fail-fast should report first event error: {stderr}"
    );
}

#[test]
fn max_error_samples_emits_bounded_debug_lines() {
    let rules = rule_dir();
    let events = mixed_fixture();
    let output = run_runner(&[
        "--max-error-samples",
        "1",
        "--on-error",
        "continue",
        rules.to_str().unwrap(),
        events.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr_utf8(&output));

    let stderr = stderr_utf8(&output);
    let sample_count = stderr
        .lines()
        .filter(|line| line.starts_with("ingest_error_sample:"))
        .count();
    assert_eq!(sample_count, 1, "expected exactly one sample line: {stderr}");
    assert!(
        stderr.contains(r#"ingest_error_sample: line=3 kind=json_parse msg="bad event JSON""#),
        "first sample should be json_parse on line 3: {stderr}"
    );
}

#[test]
fn bad_rule_dir_exits_nonzero() {
    let events = mixed_fixture();
    let missing = repo_root().join("tests/fixtures/rules/does_not_exist");
    let output = run_runner(&[
        "--on-error",
        "continue",
        missing.to_str().unwrap(),
        events.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "missing rule dir should exit non-zero"
    );
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "startup failure should exit 1");
}

#[test]
fn bad_cli_args_exit_two() {
    let output = run_runner(&["--on-error", "definitely-not-a-mode"]);
    assert!(!output.status.success(), "invalid CLI should exit non-zero");
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "CLI parse failure should exit 2");
}

#[test]
fn ingest_accounting_is_deterministic_across_runs() {
    let rules = rule_dir();
    let events = mixed_fixture();
    let args = [
        "--threads",
        "1",
        "--on-error",
        "continue",
        rules.to_str().unwrap(),
        events.to_str().unwrap(),
    ];

    fn accounting_lines(stderr: &str) -> Vec<&str> {
        stderr
            .lines()
            .filter(|line| {
                line.starts_with("ingest_errors: ") || line.starts_with("ingest_accounting: ")
            })
            .collect()
    }

    let run1 = run_runner(&args);
    let run2 = run_runner(&args);
    assert!(run1.status.success() && run2.status.success());

    let stderr1 = stderr_utf8(&run1);
    let stderr2 = stderr_utf8(&run2);
    let lines1 = accounting_lines(&stderr1);
    let lines2 = accounting_lines(&stderr2);
    assert_eq!(lines1, lines2, "accounting stderr must be identical across runs");
}
