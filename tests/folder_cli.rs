use binsith::batch::{Event, JournalRecord, Manifest, Outcome};
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(input: &Path, output: &Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binsith"))
        .arg(input)
        .arg("--output-dir")
        .arg(output)
        .args(if flags.contains(&"--jobs") {
            vec![]
        } else {
            vec!["--jobs", "1"]
        })
        .args(flags)
        .output()
        .unwrap()
}
fn manifest(output: &Path) -> Manifest {
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    manifest.validate().unwrap();
    manifest
}
fn records(output: &Path) -> Vec<JournalRecord> {
    let text = fs::read_to_string(output.join("files.jsonl")).unwrap();
    text.lines()
        .enumerate()
        .map(|(i, line)| {
            let record: JournalRecord = serde_json::from_str(line).unwrap();
            record.validate().unwrap();
            assert_eq!(record.sequence, i as u64 + 1);
            record
        })
        .collect()
}
fn report(output: &Path) -> Value {
    let entries = records(output);
    let report = entries
        .iter()
        .find_map(|entry| match &entry.event {
            Event::Terminal {
                outcome: Outcome::Complete { report } | Outcome::Limited { report },
            } => Some(report),
            _ => None,
        })
        .unwrap();
    serde_json::from_slice(&fs::read(output.join(&report.location)).unwrap()).unwrap()
}
#[test]
fn empty_and_summary_only_batches_complete_without_indicator_claims() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let output = temp.path().join("empty");
    let result = run(&input, &output, &["-q"]);
    assert!(result.status.success(), "{result:?}");
    assert!(result.stdout.is_empty() && result.stderr.is_empty());
    assert_eq!(manifest(&output).counters.eligible, 0);
    assert!(records(&output).is_empty());
    assert!(!output.join(".binsith.lock").exists());
    fs::write(input.join("sample"), b"https://example.com").unwrap();
    let output = temp.path().join("summary");
    assert!(run(&input, &output, &[]).status.success());
    let m = manifest(&output);
    assert_eq!(m.status, binsith::batch::BatchStatus::Complete);
    assert_eq!(m.counters.complete, 1);
    assert_eq!(m.counters.files_with_indicators, None);
    let r = report(&output);
    assert_eq!(r["file_summary"]["size_bytes"], 19);
    for entry in records(&output) {
        if let Event::Terminal {
            outcome: Outcome::Complete { report },
        } = entry.event
        {
            assert_eq!(report.has_actionable_indicators, None);
        }
    }
}
#[test]
fn recursion_skips_output_and_links_and_preserves_distinct_report_paths() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("nested")).unwrap();
    fs::write(input.join("sample"), b"https://example.com").unwrap();
    fs::write(input.join("nested/sample"), b"https://example.org").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(input.join("sample"), input.join("link")).unwrap();
    let flat = temp.path().join("flat");
    assert!(run(&input, &flat, &["-s"]).status.success());
    assert_eq!(manifest(&flat).counters.complete, 1);
    assert!(manifest(&flat).counters.policy_skipped >= 1);
    let output = input.join("reports");
    assert!(run(&input, &output, &["--recursive", "-s"])
        .status
        .success());
    let m = manifest(&output);
    assert_eq!(m.counters.complete, 2);
    assert_eq!(m.counters.files_with_indicators, Some(2));
    assert!(m.counters.policy_skipped >= 1);
    let locations: Vec<_> = records(&output)
        .into_iter()
        .filter_map(|e| match e.event {
            Event::Terminal {
                outcome: Outcome::Complete { report },
            } => Some(report.location),
            _ => None,
        })
        .collect();
    assert_ne!(locations[0], locations[1]);
}
#[test]
fn limited_and_failed_scans_have_distinct_artifacts_and_exit_one() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("sample"), b"abcdefghijklmno").unwrap();
    let output = temp.path().join("limited");
    assert_eq!(
        run(
            &input,
            &output,
            &["-s", "--max-string-bytes", "4", "--fail-fast"]
        )
        .status
        .code(),
        Some(1)
    );
    let m = manifest(&output);
    assert_eq!(m.counters.limited, 1);
    assert_eq!(m.status, binsith::batch::BatchStatus::Complete);
    assert!(m.stop_reasons.is_empty());
    assert!(report(&output).is_object());
    let output = temp.path().join("failed");
    assert_eq!(
        run(&input, &output, &["--offset", "100"]).status.code(),
        Some(1)
    );
    let m = manifest(&output);
    assert_eq!(m.counters.failed, 1);
    assert_eq!(m.status, binsith::batch::BatchStatus::Complete);
    let errors = fs::read_to_string(output.join("errors.jsonl")).unwrap();
    let error: binsith::batch::ErrorRecord = serde_json::from_str(errors.trim()).unwrap();
    let entries = records(&output);
    error.validate_link(&m.batch_id, entries.last()).unwrap();
    assert_eq!(error.code, "input_range");
}
#[test]
fn fail_fast_cancels_admitted_queue_and_stops_discovery() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    for i in 0..8 {
        fs::write(input.join(i.to_string()), b"a").unwrap();
    }
    let output = temp.path().join("output");
    assert_eq!(
        run(&input, &output, &["--offset", "100", "--fail-fast"])
            .status
            .code(),
        Some(1)
    );
    let m = manifest(&output);
    assert_eq!(m.counters.failed, 1);
    assert!(m.counters.cancelled >= 1);
    assert!(m.counters.eligible < 8);
    assert_eq!(m.counters.active + m.counters.queued, 0);
    assert!(!m.discovery_complete);
    assert!(m.stop_reasons.contains(&"fail_fast".into()));
    assert_eq!(records(&output).len() as u64, 2 * m.counters.eligible);
}
#[test]
fn setup_errors_do_not_claim_output_and_folder_flags_reject_single_files() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let output = temp.path().join("output");
    for flags in [
        vec!["--jobs", "0"],
        vec!["--jsonl"],
        vec!["--patterns", "missing-patterns.toml"],
        vec!["--category", "unknown"],
    ] {
        assert_eq!(run(&input, &output, &flags).status.code(), Some(2));
        assert!(!output.exists());
    }
    let file = input.join("file");
    fs::write(&file, b"a").unwrap();
    assert_eq!(run(&file, &output, &[]).status.code(), Some(2));
    assert!(!output.exists());
}
#[test]
fn summary_preflight_validates_all_patterns_and_preserves_filtered_fingerprints() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("sample"), b"hello").unwrap();
    let patterns = temp.path().join("patterns.toml");
    let path = patterns.to_str().unwrap();
    for (index, invalid) in ["[", "a{100000000}"].iter().enumerate() {
        fs::write(&patterns, format!("keep = 'hello'\nunused = '{invalid}'\n")).unwrap();
        for strings in [false, true] {
            let output = temp.path().join(format!("invalid-{index}-{strings}"));
            let mut flags = vec!["--patterns", path, "--category", "keep"];
            if strings {
                flags.push("-s");
            }
            let result = run(&input, &output, &flags);
            assert_eq!(result.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&result.stderr).contains("invalid pattern unused"));
            assert!(
                !output.exists(),
                "pattern errors must precede output claims"
            );
        }
    }
    fs::write(&patterns, "keep = 'hello'\nunused = 'world'\n").unwrap();
    let expected = binsith::batch::pattern_fingerprint([("keep", "hello")]);
    for strings in [false, true] {
        let output = temp.path().join(format!("valid-{strings}"));
        let mut flags = vec!["--patterns", path, "--category", "keep"];
        if strings {
            flags.push("-s");
        }
        let result = run(&input, &output, &flags);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(manifest(&output).configuration.patterns_sha256, expected);
    }
}

#[test]
fn per_file_range_and_findings_match_single_file_json() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let sample = input.join("sample");
    fs::write(&sample, b"junkhttps://example.com\0tail").unwrap();
    let output = temp.path().join("output");
    let flags = [
        "-q",
        "-s",
        "--offset",
        "4",
        "--length",
        "20",
        "--scan-utf16",
        "--entropy",
    ];
    assert!(run(&input, &output, &flags).status.success());
    let single = temp.path().join("single.json");
    assert!(Command::new(env!("CARGO_BIN_EXE_binsith"))
        .arg(&sample)
        .args(flags)
        .arg("-j")
        .arg(&single)
        .status()
        .unwrap()
        .success());
    let a = report(&output);
    let b: Value = serde_json::from_slice(&fs::read(single).unwrap()).unwrap();
    for key in [
        "strings",
        "entropy_regions",
        "scan_range",
        "analysis_coverage",
    ] {
        assert!(!a[key].is_null(), "missing {key}");
        assert_eq!(a[key], b[key], "{key}");
    }
    let mut a_summary = a["file_summary"].clone();
    let mut b_summary = b["file_summary"].clone();
    a_summary.as_object_mut().unwrap().remove("file_path");
    b_summary.as_object_mut().unwrap().remove("file_path");
    assert_eq!(a_summary, b_summary);
}

#[cfg(unix)]
#[test]
fn sigint_cancels_active_and_queued_work_and_releases_claim() {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    for i in 0..5 {
        fs::File::create(input.join(i.to_string()))
            .unwrap()
            .set_len(8 * 1024 * 1024 * 1024)
            .unwrap();
    }
    let output = temp.path().join("output");
    let mut child = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .arg(&input)
        .arg("--output-dir")
        .arg(&output)
        .arg("--progress")
        .args(["--jobs", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if fs::read(output.join("manifest.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Manifest>(&bytes).ok())
            .is_some_and(|m| m.counters.active == 1 && m.counters.queued == 2)
        {
            break;
        }
        if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("worker did not reach active checkpoint");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cooperative shutdown timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    use std::io::Read;
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.contains("Batch incomplete: 3 processed"), "{stderr}");
    assert!(stderr.contains("3 cancelled") && stderr.contains("Stopping: 3/? processed"));
    assert!(!stderr.contains("Finished:") && !stderr.contains("remaining"));
    let m = manifest(&output);
    assert_eq!(m.counters.cancelled, 3);
    assert_eq!(m.counters.queued + m.counters.active, 0);
    assert!(m.stop_reasons.contains(&"interrupted".into()));
    assert_eq!(m.status, binsith::batch::BatchStatus::Incomplete);
    assert_eq!(records(&output).len(), 6);
    assert!(!output.join(".binsith.lock").exists());
}

#[test]
fn skipped_only_and_mixed_failure_batches_finish_with_exact_counters() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("nested")).unwrap();
    let output = temp.path().join("skipped");
    assert!(run(&input, &output, &[]).status.success());
    let m = manifest(&output);
    assert_eq!(m.counters.policy_skipped, 1);
    assert_eq!(m.counters.eligible, 0);
    assert!(m.discovery_complete);
    fs::write(input.join("short"), b"a").unwrap();
    fs::write(input.join("long"), b"abcdefg").unwrap();
    let output = temp.path().join("mixed");
    assert_eq!(
        run(&input, &output, &["--offset", "3"]).status.code(),
        Some(1)
    );
    let m = manifest(&output);
    assert_eq!(m.counters.failed, 1);
    assert_eq!(m.counters.complete, 1);
    assert_eq!(m.counters.cancelled, 0);
    assert!(m.discovery_complete);
    assert_eq!(report(&output)["file_summary"]["size_bytes"], 4);
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(input.join("missing"))
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn parallel_cli_reports_match_one_worker_and_keep_all_terminal_records() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    for i in 0..24 {
        fs::write(
            input.join(format!("sample-{i}")),
            format!("{i}\0https://example.com/{i}\0dXNlckBleGFtcGxlLmNvbQ==\0"),
        )
        .unwrap();
    }
    let mut baseline = std::collections::BTreeMap::new();
    for jobs in [1, 2, 4, 8] {
        let output = temp.path().join(format!("reports-{jobs}"));
        let jobs_text = jobs.to_string();
        let result = run(
            &input,
            &output,
            &[
                "--jobs",
                &jobs_text,
                "-s",
                "--scan-utf16",
                "--entropy",
                "-q",
            ],
        );
        assert!(result.status.success(), "jobs={jobs}: {result:?}");
        assert!(result.stdout.is_empty() && result.stderr.is_empty());
        let m = manifest(&output);
        assert_eq!(m.configuration.jobs, jobs);
        assert_eq!(m.configuration.work_queue_capacity, 2 * jobs);
        assert_eq!(m.counters.complete, 24);
        assert_eq!(m.counters.active + m.counters.queued, 0);
        let entries = records(&output);
        assert_eq!(entries.len(), 48);
        let mut reports = std::collections::BTreeMap::new();
        for entry in entries {
            if let Event::Terminal {
                outcome: Outcome::Complete { report },
            } = entry.event
            {
                let json: Value =
                    serde_json::from_slice(&fs::read(output.join(&report.location)).unwrap())
                        .unwrap();
                assert!(reports.insert(report.report_id, json).is_none());
            }
        }
        if jobs == 1 {
            baseline = reports;
        } else {
            assert_eq!(reports, baseline, "jobs={jobs}");
        }
    }
}

#[test]
fn parallel_cli_default_uses_available_cpus_capped_at_four() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let output = temp.path().join("output");
    let result = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .arg(&input)
        .arg("--output-dir")
        .arg(&output)
        .arg("-q")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        manifest(&output).configuration.jobs,
        std::thread::available_parallelism()
            .map_or(1, usize::from)
            .clamp(1, 4)
    );
}

#[test]
fn explicit_progress_with_quiet_keeps_stdout_clean_and_reports_processed_work() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("a"), b"hello").unwrap();
    let output = temp.path().join("reports");
    let result = run(&input, &output, &["-q", "--progress"]);
    assert!(result.status.success() && result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("Discovering: 0/? processed"));
    assert!(stderr.contains("Finished: 1/1 processed"));
    assert!(stderr.contains("5 selected bytes read"));
    assert!(!stderr.contains("Batch finished") && !stderr.contains('\x1b'));
    assert_eq!(manifest(&output).counters.complete, 1);
}

#[test]
fn summary_matrix_keeps_analysis_coverage_and_artifact_paths_visible() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(
        input.join("a"),
        b"https://example.com\0abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();
    for (name, flags, code, expected) in [
        ("summary", vec![], 0, "indicators not analyzed"),
        (
            "strings",
            vec!["-s"],
            0,
            "1 files with indicators (0 limited)",
        ),
        (
            "limited",
            vec!["-s", "--max-string-bytes", "24"],
            1,
            "1 files with indicators (1 limited)",
        ),
        ("failed", vec!["--offset", "999"], 1, "1 failed"),
        (
            "stopped",
            vec!["--offset", "999", "--fail-fast"],
            1,
            "Batch incomplete",
        ),
    ] {
        let output = temp.path().join(name);
        let result = run(&input, &output, &flags);
        assert_eq!(result.status.code(), Some(code), "{name}");
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("Discovering:") && !stderr.contains("https://example.com"));
        if name != "stopped" {
            assert!(stderr.contains("Batch finished"));
        }
        for (label, file) in [
            ("Manifest", "manifest.json"),
            ("Files", "files.jsonl"),
            ("Errors", "errors.jsonl"),
            ("Reports", "results"),
        ] {
            assert!(stderr.contains(&format!("{label}: {:?}", output.join(file))));
        }
        manifest(&output);
    }
}

#[test]
fn progress_counts_selected_bytes_once_across_workers_and_extra_passes() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    for i in 0..9 {
        fs::write(
            input.join(i.to_string()),
            b"prefix\0https://example.com\0suffix",
        )
        .unwrap();
    }
    for jobs in ["1", "4"] {
        let output = temp.path().join(jobs);
        let result = run(
            &input,
            &output,
            &[
                "--jobs",
                jobs,
                "--progress",
                "-q",
                "-s",
                "--entropy",
                "--scan-utf16",
                "--offset",
                "7",
                "--length",
                "20",
            ],
        );
        assert!(result.status.success() && result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        let final_line = stderr.lines().last().unwrap();
        assert!(final_line.contains("Finished: 9/9 processed"));
        assert!(final_line.contains("180 selected bytes read"), "{stderr}");
        assert!(!stderr.contains("https://example.com"));
        assert_eq!(manifest(&output).counters.complete, 9);
    }
}

#[cfg(unix)]
#[test]
fn summary_escapes_native_output_path_controls() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let output = temp.path().join("reports\n\r\x1b[31m\t");
    let result = run(&input, &output, &[]);
    assert!(result.status.success() && result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 5);
    assert!(!stderr.contains('\x1b') && !stderr.contains('\r') && !stderr.contains('\t'));
    assert!(stderr.contains(&format!("Manifest: {:?}", output.join("manifest.json"))));
    manifest(&output);
}
