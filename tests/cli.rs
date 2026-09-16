use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn default_summary_and_empty_hex() {
    let output = run(&["-"], b"abc");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("900150983cd24fb0d6963f7d28e17f72"));
    let output = run(&["-x", "-"], b"");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn bundled_patterns_work_and_controls_are_escaped() {
    let output = run(&["-s", "-"], b"https://example.com\0G1sySmhlbGxv");
    assert!(output.status.success(), "{:?}", output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("URL"));
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("\\u{1b}"));
}

#[test]
fn missing_input_fails() {
    let output = run(&["/this/path/does/not/exist/binsith"], b"");
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
}

#[test]
fn json_and_bad_patterns() {
    let dir = std::env::temp_dir().join(format!("binsith-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json_path = dir.join("analysis.json");
    let output = run(
        &["-s", "-j", json_path.to_str().unwrap(), "-"],
        b"https://example.com",
    );
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["file_summary"]["size_bytes"], 19);
    assert_eq!(json["strings"][0]["matches"][0], "URL");
    let patterns = dir.join("patterns.toml");
    for bad in ["invalid toml", "bad = '['"] {
        std::fs::write(&patterns, bad).unwrap();
        let output = run(
            &["-s", "--patterns", patterns.to_str().unwrap(), "-"],
            b"hello",
        );
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn combined_modes_share_stdin_and_write_complete_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let output = run(
        &["-i", "-s", "-x", "-j", path.to_str().unwrap(), "-"],
        b"hello world\0",
    );
    assert!(output.status.success(), "{:?}", output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.find("File Summary").unwrap() < text.find("Offset\tEncoding").unwrap());
    assert!(text.find("Offset\tEncoding").unwrap() < text.find("00000000: 68").unwrap());
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["file_summary"]["size_bytes"], 12);
    assert_eq!(json["strings"][0]["value"], "hello world");
    assert_eq!(json["strings"].as_array().unwrap().len(), 1);
}

#[test]
fn json_can_replace_input_after_analysis_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let output = run(
        &["-s", "-j", path.to_str().unwrap(), path.to_str().unwrap()],
        b"",
    );
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["file_summary"]["size_bytes"], 11);
    assert_eq!(json["strings"][0]["value"], "hello world");
}

#[test]
fn report_survives_closed_stdout_and_terminal_only_pipe_is_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    std::fs::write(&input, b"hello world\0".repeat(5000)).unwrap();
    for report in [false, true] {
        let path = dir.path().join("report.json");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_binsith"));
        cmd.args(["-s", input.to_str().unwrap()]);
        if report {
            cmd.args(["-j", path.to_str().unwrap()]);
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
        if report {
            let json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(json["strings"].as_array().unwrap().len(), 5000);
        }
    }
}

#[test]
fn invalid_limits_and_report_destination_fail_without_replacement() {
    let output = run(&["-s", "--max-string-bytes", "3", "-"], b"");
    assert!(!output.status.success());
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("destination");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("keep"), b"original").unwrap();
    let output = run(&["-j", dest.to_str().unwrap(), "-"], b"hello");
    assert!(!output.status.success());
    assert_eq!(std::fs::read(dest.join("keep")).unwrap(), b"original");
    let entries = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(
        entries, 1,
        "failed publication should clean up temporary report"
    );
}

#[test]
fn truncated_findings_are_visible_in_matching_only_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let output = run(
        &[
            "-S",
            "--max-string-bytes",
            "4",
            "-j",
            path.to_str().unwrap(),
            "-",
        ],
        b"abcdefghij\0",
    );
    assert!(output.status.success(), "{:?}", output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("TRUNCATED"));
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["strings"][0]["value"], "abcd");
    assert_eq!(json["strings"][0]["length"], 10);
    assert_eq!(json["strings"][0]["truncated"], true);
    assert_eq!(json["strings"][0]["decode_status"], "truncated");
}

#[test]
fn match_details_round_trip_in_json_and_terminal_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let input = b"prefix https://example.com and https://example.org\0";
    let output = run(&["-S", "-j", path.to_str().unwrap(), "-"], input);
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let details = json["strings"][0]["match_details"].as_array().unwrap();
    let urls: Vec<_> = details.iter().filter(|d| d["pattern"] == "URL").collect();
    assert_eq!(urls.len(), 2);
    for detail in urls {
        let start = detail["offset"].as_u64().unwrap() as usize;
        let end = detail["end_offset"].as_u64().unwrap() as usize;
        assert_eq!(
            &input[start..end],
            detail["text"].as_str().unwrap().as_bytes()
        );
    }
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("Match URL [00000007..0000001a): https://example.com"));
    assert_eq!(json["strings"][0]["match_details_truncated"], false);
}

#[test]
fn embedded_scan_from_stdin_reaches_terminal_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let mut bytes = vec![255];
    for unit in "https://example.com".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    let output = run(
        &["--scan-utf16", "-S", "-j", path.to_str().unwrap(), "-"],
        &bytes,
    );
    assert!(output.status.success(), "{:?}", output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Embedded UTF-16 candidate"));
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let hit = json["strings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["encoding"] == "UTF-16LE" && f["offset"] == 1)
        .unwrap();
    assert_eq!(hit["value"], "https://example.com");
    assert_eq!(hit["extraction"], "embedded_utf16_candidate");
}

#[test]
fn encoding_selection_enables_string_analysis_and_rejects_bom_conflict() {
    let bytes = b"h\0e\0l\0l\0o\0";
    let output = run(&["--encoding", "utf16le", "-"], bytes);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    let output = run(&["--encoding", "utf16be", "-"], b"\xff\xfe");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("conflicts"));
}

#[test]
fn validation_statuses_and_api_context_reach_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let bytes = b"card=4111111111111111\0card=4111111111111112\0id=0123456789abcdef0123456789abcdef\0api_key=0123456789abcdef0123456789abcdef\0";
    let output = run(&["-S", "-j", path.to_str().unwrap(), "-"], bytes);
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let findings = json["strings"].as_array().unwrap();
    let details: Vec<_> = findings
        .iter()
        .flat_map(|f| f["match_details"].as_array().unwrap())
        .collect();
    let cards: Vec<_> = details
        .iter()
        .filter(|d| d["pattern"] == "credit_card")
        .collect();
    assert_eq!(cards.len(), 2);
    assert_eq!(cards[0]["validation"]["status"], "validated");
    assert_eq!(cards[1]["validation"]["status"], "invalid");
    let keys: Vec<_> = details
        .iter()
        .filter(|d| d["pattern"] == "api_key")
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["validation"]["status"], "candidate");
    let start = keys[0]["offset"].as_u64().unwrap() as usize;
    let end = keys[0]["end_offset"].as_u64().unwrap() as usize;
    assert_eq!(&bytes[start..end], b"0123456789abcdef0123456789abcdef");
    let terminal = String::from_utf8_lossy(&output.stdout);
    assert!(terminal.contains("Validated:"));
    assert!(terminal.contains("Invalid:"));
    assert!(terminal.contains("Candidate:"));
}

#[test]
fn decoded_layers_keep_source_envelope_and_use_decoded_offsets() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let first = STANDARD.encode(b"https://example.com");
    let outer = STANDARD.encode(first.as_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let mut input = b"skip".to_vec();
    input.extend_from_slice(outer.as_bytes());
    let output = run(
        &[
            "--offset",
            "4",
            "--decode-depth",
            "2",
            "--category",
            "URL",
            "-j",
            path.to_str().unwrap(),
            "-",
        ],
        &input,
    );
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let finding = &json["strings"][0];
    assert!(finding["matches"].as_array().unwrap().is_empty());
    let layers = finding["decoded_layers"].as_array().unwrap();
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[1]["source_offset"], 4);
    assert_eq!(layers[1]["source_end_offset"], input.len());
    assert_eq!(layers[1]["offset_space"], "decoded_layer_utf8");
    assert_eq!(layers[1]["match_details"][0]["offset"], 0);
    assert_eq!(layers[1]["match_details"][0]["end_offset"], 19);
    assert_eq!(layers[1]["match_details"][0]["text"], "https://example.com");
    let output = run(
        &[
            "-s",
            "--decode-depth",
            "8",
            "--max-decode-bytes",
            &first.len().to_string(),
            "-j",
            path.to_str().unwrap(),
            "-",
        ],
        outer.as_bytes(),
    );
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        json["strings"][0]["decoded_layers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json["strings"][0]["decoded_layers"][0]["next_decode"],
        "byte_limit"
    );
}

#[test]
fn range_hashes_offsets_minimum_length_and_invalid_range() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let output = run(
        &[
            "-s",
            "-x",
            "--offset",
            "0x4",
            "--length",
            "3",
            "--min-length",
            "3",
            "-j",
            path.to_str().unwrap(),
            "-",
        ],
        b"skipabcignored",
    );
    assert!(output.status.success(), "{:?}", output);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        json["file_summary"]["md5"],
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(json["file_summary"]["size_bytes"], 3);
    assert_eq!(json["scan_range"]["offset"], 4);
    assert_eq!(json["strings"][0]["offset"], 4);
    assert_eq!(json["strings"][0]["value"], "abc");
    assert!(String::from_utf8_lossy(&output.stdout).contains("00000004: 61 62 63"));
    assert!(!run(&["--offset", "20", "-"], b"abc").status.success());
    assert!(!run(
        &["--offset", "18446744073709551615", "--length", "1", "-"],
        b""
    )
    .status
    .success());
    assert!(!run(&["--category", "typo", "-"], b"").status.success());
}

#[test]
fn jsonl_quiet_and_custom_exit_codes() {
    let output = run(
        &[
            "--jsonl",
            "--quiet",
            "--category",
            "URL",
            "--match-exit-code",
            "7",
            "--no-match-exit-code",
            "8",
            "-",
        ],
        b"https://example.com",
    );
    assert_eq!(output.status.code(), Some(7));
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "summary");
    assert_eq!(lines[1]["type"], "string");
    assert_eq!(lines.last().unwrap()["type"], "complete");
    assert_eq!(lines[1]["data"]["matches"][0], "URL");
    let output = run(
        &[
            "--quiet",
            "--category",
            "URL",
            "--match-exit-code",
            "7",
            "--no-match-exit-code",
            "8",
            "-",
        ],
        b"ordinary text",
    );
    assert_eq!(output.status.code(), Some(8));
    assert!(output.stdout.is_empty());
    let output = run(
        &[
            "--quiet",
            "--match-exit-code",
            "7",
            "--no-match-exit-code",
            "8",
            "-",
        ],
        b"card=4111111111111112",
    );
    assert_eq!(output.status.code(), Some(8));
}

#[test]
fn regional_entropy_has_absolute_offsets_and_partial_final_window() {
    let mut input = vec![0; 4 + 256];
    input.extend(0u8..=255);
    input.extend([42, 42]);
    let output = run(
        &[
            "--entropy",
            "--entropy-window",
            "256",
            "--offset",
            "4",
            "--jsonl",
            "-",
        ],
        &input,
    );
    assert!(output.status.success(), "{:?}", output);
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let regions: Vec<_> = lines
        .iter()
        .filter(|v| v["type"] == "entropy")
        .map(|v| &v["data"])
        .collect();
    assert_eq!(regions.len(), 3);
    assert_eq!(regions[0]["offset"], 4);
    assert_eq!(regions[0]["entropy"], 0.0);
    assert_eq!(regions[1]["offset"], 260);
    assert_eq!(regions[1]["entropy"], 8.0);
    assert_eq!(regions[1]["high"], true);
    assert_eq!(regions[2]["length"], 2);
    assert!(!run(&["--entropy", "--entropy-window", "0", "-"], b"")
        .status
        .success());
    assert!(!run(&["--entropy", "--entropy-threshold", "NaN", "-"], b"")
        .status
        .success());
}

#[test]
fn comparisons_show_added_removed_moved_strings_and_indicators() {
    let dir = tempfile::tempdir().unwrap();
    let left = dir.path().join("left.bin");
    let right = dir.path().join("right.bin");
    let report = dir.path().join("report.json");
    std::fs::write(&left, b"https://old.example\0stable\0").unwrap();
    std::fs::write(&right, b"prefix\0https://new.example\0stable\0").unwrap();
    let output = run(
        &[
            left.to_str().unwrap(),
            "--compare",
            right.to_str().unwrap(),
            "-j",
            report.to_str().unwrap(),
            "--quiet",
        ],
        b"",
    );
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stdout.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    let c = &json["comparison"];
    assert_eq!(c["identical_content"], false);
    assert!(c["strings"]["added"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["preview"] == "https://new.example"));
    assert!(c["strings"]["removed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["preview"] == "https://old.example"));
    assert!(c["strings"]["changed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["before"]["preview"] == "stable"));
    assert!(!c["indicators"]["added"].as_array().unwrap().is_empty());
    assert!(!c["entropy_changes"].as_array().unwrap().is_empty());
    assert_eq!(c["incomplete_index"], false);
    let output = run(
        &[
            left.to_str().unwrap(),
            "--compare",
            left.to_str().unwrap(),
            "--jsonl",
        ],
        b"",
    );
    assert!(output.status.success());
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let c = &events.iter().find(|e| e["type"] == "comparison").unwrap()["data"];
    assert_eq!(c["identical_content"], true);
    assert!(c["strings"]["changed"].as_array().unwrap().is_empty());
    assert!(c["entropy_changes"].as_array().unwrap().is_empty());
}

#[test]
fn empty_entropy_report_and_jsonl_file_have_complete_output() {
    let output = run(&["--entropy", "-j", "-", "-"], b"");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["entropy_regions"], serde_json::json!([]));
    assert_eq!(json["complete"], true);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.jsonl");
    let output = run(
        &["--jsonl", "-s", "-q", "-j", path.to_str().unwrap(), "-"],
        b"hello",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let text = std::fs::read_to_string(path).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(events.last().unwrap()["type"], "complete");
}

#[test]
fn match_exit_code_does_not_depend_on_detail_cap() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let mut text = "4111111111111112;".repeat(1001);
    text.push_str("4111111111111111");
    std::fs::write(&input, text).unwrap();
    let output = run(
        &[
            "--category",
            "credit_card",
            "--match-exit-code",
            "7",
            "--no-match-exit-code",
            "8",
            "-q",
            input.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(7));
}
