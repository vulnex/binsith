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
    std::thread::scope(|scope| {
        let mut stdin = child.stdin.take().unwrap();
        let writer = scope.spawn(move || {
            let _ = stdin.write_all(input);
        });
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap();
        output
    })
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

fn report(args: &[&str], input: &[u8]) -> (Output, serde_json::Value) {
    let mut flags = vec!["-s", "-j", "-", "-"];
    flags.extend_from_slice(args);
    let output = run(&flags, input);
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}: {output:?}"));
    (output, json)
}

#[test]
fn full_urls_preserve_evidence_and_validate_syntax() {
    for url in [
        "https://example.com:8443/a?x=1&y=2#part",
        "HTTPS://example.com/a%20b",
        "http://[2001:db8::1]:8080/a",
        "https://example.com/a_(b)",
    ] {
        let input = format!("url=\"{url}\"");
        let (_, json) = report(&["--category", "URL"], input.as_bytes());
        let d = &json["strings"][0]["match_details"][0];
        assert_eq!(d["text"], url);
        assert_eq!(d["offset"], 5);
        assert_eq!(d["end_offset"], 5 + url.len());
        assert_eq!(d["validation"]["status"], "validated");
    }
    let (_, json) = report(&["--category", "URL"], b"(https://example.com/path).");
    assert_eq!(
        json["strings"][0]["match_details"][0]["text"],
        "https://example.com/path"
    );
    for url in ["http://example.com:99999/a", "https://example.com/%ZZ"] {
        let (output, json) = report(
            &["--category", "URL", "--match-exit-code", "7"],
            url.as_bytes(),
        );
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            json["strings"][0]["match_details"][0]["validation"]["status"],
            "invalid"
        );
    }
}

#[test]
fn windows_paths_and_ipv4_boundaries() {
    for path in [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Program Files\Example\app.exe",
        "/usr/local/bin/tool.sh",
    ] {
        let (_, json) = report(&["--category", "file_path"], path.as_bytes());
        assert_eq!(json["strings"][0]["match_details"][0]["text"], path);
    }
    for malformed in [
        "999.192.168.1.1.999",
        "1.192.168.1.1",
        "192.168.1.1.example",
        "abc192.168.1.1",
    ] {
        let (_, json) = report(
            &["--category", "ip_address", "--no-decode"],
            malformed.as_bytes(),
        );
        assert!(
            json["strings"].as_array().unwrap().is_empty(),
            "{malformed}"
        );
    }
    let (_, json) = report(&["--category", "ip_address"], b"server=192.168.1.1:8080");
    assert_eq!(
        json["strings"][0]["match_details"][0]["text"],
        "192.168.1.1"
    );
}

#[test]
fn base64_tokens_have_exact_source_envelopes() {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("https://example.com:8443/a?x=1&y=2#part");
    let text = format!("config={encoded}; other=\"{encoded}\"");
    for utf16 in [false, true] {
        let input = if utf16 {
            text.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        } else {
            text.as_bytes().to_vec()
        };
        let mut flags = vec!["--category", "URL", "--offset", "2"];
        if utf16 {
            flags.extend(["--encoding", "utf16le"]);
        }
        let mut bytes = vec![0, 0];
        bytes.extend(input);
        let (_, json) = report(&flags, &bytes);
        let layers = json["strings"][0]["decoded_layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        let scale = if utf16 { 2 } else { 1 };
        for (i, start) in [7, 7 + encoded.len() + 9].into_iter().enumerate() {
            assert_eq!(layers[i]["source_offset"], 2 + start * scale);
            assert_eq!(
                layers[i]["source_end_offset"],
                2 + (start + encoded.len()) * scale
            );
            assert_eq!(layers[i]["match_details"][0]["offset"], 0);
            assert_eq!(layers[i]["next_decode"], "not_utf8_base64");
        }
    }
}

#[test]
fn coverage_exit_precedence_and_metadata() {
    let flags = [
        "--category",
        "URL",
        "--max-string-bytes",
        "24",
        "--match-exit-code",
        "7",
        "--no-match-exit-code",
        "8",
        "--inconclusive-exit-code",
        "9",
    ];
    let (output, json) = report(&flags, b"https://example.com/this-is-longer-than-the-limit");
    assert_eq!(output.status.code(), Some(9));
    assert_eq!(json["processing_complete"], true);
    assert_eq!(json["analysis_coverage"]["status"], "limited");
    assert_eq!(
        json["analysis_coverage"]["limitations"]["truncated_strings"],
        1
    );
    assert_eq!(json["metadata"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        json["metadata"]["configuration"]["inconclusive_exit_code"],
        9
    );
    assert_eq!(
        json["metadata"]["source_sha256"].as_str().unwrap().len(),
        64
    );
    let (output, _) = report(
        &flags,
        b"https://example.com\0https://example.com/this-is-longer-than-the-limit",
    );
    assert_eq!(output.status.code(), Some(7));
    let (output, clean) = report(&flags, b"plain text");
    assert_eq!(output.status.code(), Some(8));
    assert_eq!(
        clean["analysis_coverage"]["status"],
        "complete_within_configured_scope"
    );
    assert_eq!(
        clean["metadata"]["patterns_sha256"],
        json["metadata"]["patterns_sha256"]
    );
    let (_, other) = report(&["--category", "ip_address"], b"plain text");
    assert_ne!(
        other["metadata"]["patterns_sha256"],
        json["metadata"]["patterns_sha256"]
    );
}

#[test]
fn decode_limits_survive_match_filtering() {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let encoded = engine.encode("https://example.com");
    for (args, input) in [
        (vec!["--max-decode-bytes", "2"], format!("config={encoded}")),
        (vec!["--decode-depth", "1"], engine.encode(&encoded)),
        (
            vec!["--max-decode-bytes", "19"],
            format!("{encoded};{encoded}"),
        ),
        (
            vec![],
            std::iter::repeat_n("aGVsbG8=", 130)
                .collect::<Vec<_>>()
                .join(";"),
        ),
    ] {
        let mut flags = vec!["--category", "Email", "--inconclusive-exit-code", "9"];
        flags.extend(args);
        let (output, json) = report(&flags, input.as_bytes());
        assert_eq!(output.status.code(), Some(9), "{input}");
        assert_eq!(
            json["analysis_coverage"]["limitations"]["decode_limited_strings"],
            1
        );
    }
}

#[test]
fn jsonl_completion_reports_coverage_and_build() {
    let output = run(
        &["-s", "--jsonl", "--max-string-bytes", "4", "-"],
        b"long string",
    );
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let last = events.last().unwrap();
    assert_eq!(last["type"], "complete");
    assert_eq!(last["data"]["processing_complete"], true);
    assert_eq!(last["data"]["analysis_coverage"]["status"], "limited");
    assert!(last["data"]["metadata"]["target"].is_string());
}

#[test]
fn coverage_counts_omitted_details_and_comparison_limits() {
    let input = std::iter::repeat_n("https://example.com", 1002)
        .collect::<Vec<_>>()
        .join(" ");
    let (_, json) = report(&["--category", "URL", "--no-decode"], input.as_bytes());
    assert_eq!(
        json["analysis_coverage"]["limitations"]["strings_with_omitted_details"],
        1
    );
    assert_eq!(
        json["strings"][0]["match_details"]
            .as_array()
            .unwrap()
            .len(),
        1000
    );
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&input);
    let (_, json) = report(&["--category", "URL"], encoded.as_bytes());
    assert_eq!(
        json["analysis_coverage"]["limitations"]["decoded_layers_with_omitted_details"],
        1
    );
    let mut other = tempfile::NamedTempFile::new().unwrap();
    other
        .write_all(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    let (output, json) = report(
        &[
            "--compare",
            other.path().to_str().unwrap(),
            "--max-string-bytes",
            "8",
            "--no-decode",
            "--inconclusive-exit-code",
            "9",
        ],
        b"hello",
    );
    assert_eq!(output.status.code(), Some(9));
    assert_eq!(
        json["analysis_coverage"]["limitations"]["truncated_strings"],
        1
    );
    assert_eq!(
        json["analysis_coverage"]["limitations"]["comparison_limited"],
        true
    );
}

#[test]
fn custom_url_rules_keep_their_original_span_and_provenance() {
    let mut patterns = tempfile::NamedTempFile::new().unwrap();
    patterns.write_all(b"URL = 'custom!'").unwrap();
    let (_, custom) = report(
        &["--patterns", patterns.path().to_str().unwrap()],
        b"custom!",
    );
    let detail = &custom["strings"][0]["match_details"][0];
    assert_eq!(detail["text"], "custom!");
    assert_eq!(detail["validation"]["status"], "candidate");
    let (_, builtin) = report(&[], b"custom!");
    assert_ne!(
        custom["metadata"]["patterns_sha256"],
        builtin["metadata"]["patterns_sha256"]
    );
    let output = run(&["--version"], b"");
    let version = String::from_utf8(output.stdout).unwrap();
    assert!(version.contains(env!("CARGO_PKG_VERSION")));
    assert!(version.contains(custom["metadata"]["source_sha256"].as_str().unwrap()));
}

#[test]
fn regular_file_ranges_match_stdin_at_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("range.bin");
    for bytes in [b"prefix\0https://example.com\0tail".as_slice(), b""] {
        std::fs::write(&path, bytes).unwrap();
        for offset in [0, 1, bytes.len() as u64, bytes.len() as u64 + 1] {
            for length in [None, Some(0), Some(4), Some(100)] {
                let offset = offset.to_string();
                let length = length.map(|n| n.to_string());
                let mut flags = vec!["-s", "-x", "--min-length", "1", "--offset", &offset];
                if let Some(length) = &length {
                    flags.extend(["--length", length]);
                }
                flags.push("-");
                let stdin = run(&flags, bytes);
                *flags.last_mut().unwrap() = path.to_str().unwrap();
                let file = run(&flags, b"");
                assert_eq!(file.status.code(), stdin.status.code());
                assert_eq!(file.stdout, stdin.stdout);
                assert_eq!(file.stderr, stdin.stderr);
            }
        }
    }
}

#[test]
fn large_sparse_file_range_preserves_absolute_offsets_and_hashes() {
    use std::io::{Seek, SeekFrom};
    let mut sample = tempfile::NamedTempFile::new().unwrap();
    let offset = 1u64 << 30;
    sample.seek(SeekFrom::Start(offset)).unwrap();
    sample.write_all(b"https://example.com").unwrap();
    sample.flush().unwrap();
    let output = run(
        &[
            sample.path().to_str().unwrap(),
            "-s",
            "-j",
            "-",
            "--offset",
            &offset.to_string(),
        ],
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["file_summary"]["size_bytes"], 19);
    assert_eq!(
        json["file_summary"]["md5"],
        format!("{:x}", md5::compute(b"https://example.com"))
    );
    assert_eq!(json["strings"][0]["offset"], offset);
    assert_eq!(json["strings"][0]["match_details"][0]["offset"], offset);
}

#[cfg(unix)]
#[test]
fn named_pipe_input_keeps_streaming_range_semantics() {
    let bytes = b"skiphttps://example.com";
    let output = run(
        &["/dev/stdin", "-s", "--offset", "4", "--length", "19"],
        bytes,
    );
    let stdin = run(&["-", "-s", "--offset", "4", "--length", "19"], bytes);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, stdin.stdout);
}

#[test]
fn live_jsonl_emits_findings_while_stdin_is_open() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;
    let mut child = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .args(["--live-jsonl", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    stdin.write_all(b"https://example.com\0").unwrap();
    stdin.flush().unwrap();
    let start = rx.recv_timeout(Duration::from_secs(10));
    let finding = rx.recv_timeout(Duration::from_secs(10));
    let still_running = child.try_wait().unwrap().is_none();
    drop(stdin);
    if start.is_err() || finding.is_err() {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    reader.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(still_running);
    let parse = |line: String| serde_json::from_str::<serde_json::Value>(&line).unwrap();
    assert_eq!(parse(start.unwrap().unwrap())["type"], "start");
    let finding = parse(finding.unwrap().unwrap());
    assert_eq!(finding["type"], "string");
    assert_eq!(finding["data"]["value"], "https://example.com");
    let rest: Vec<_> = rx.into_iter().map(|l| parse(l.unwrap())).collect();
    assert_eq!(rest[0]["type"], "summary");
    assert_eq!(rest[0]["file_summary"]["size_bytes"], 20);
    assert_eq!(rest.last().unwrap()["type"], "complete");
}

#[test]
fn live_jsonl_matches_regular_results_and_range_summary() {
    for input in [
        b"skiphttps://example.com\0tail".as_slice(),
        b"skip",
        b"skip\xff\xfeh\0i\0!\0!\0",
    ] {
        let flags = ["--jsonl", "-s", "--offset", "4", "--length", "100", "-"];
        let parse = |output: Output| {
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .collect::<Vec<_>>()
        };
        let regular = parse(run(&flags, input));
        let mut live_flags = flags.to_vec();
        live_flags.push("--live-jsonl");
        let live = parse(run(&live_flags, input));
        assert_eq!(live[0]["type"], "start");
        assert_eq!(&regular[0], &live[live.len() - 2]);
        let strings = |events: Vec<serde_json::Value>| {
            events
                .into_iter()
                .filter(|e| e["type"] == "string")
                .collect::<Vec<_>>()
        };
        assert_eq!(strings(regular), strings(live));
    }
}

#[test]
fn live_combined_modes_and_named_report_complete_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.bin");
    let report = dir.path().join("report.jsonl");
    std::fs::write(&input, b"https://example.com\0h\0e\0l\0l\0o\0").unwrap();
    let output = run(
        &[
            input.to_str().unwrap(),
            "--live-jsonl",
            "--scan-utf16",
            "--entropy",
            "--compare",
            input.to_str().unwrap(),
            "--summary",
            "--hexdump",
            "-j",
            report.to_str().unwrap(),
        ],
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    let events: Vec<serde_json::Value> = std::fs::read_to_string(&report)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for kind in [
        "start",
        "string",
        "entropy",
        "comparison",
        "summary",
        "complete",
    ] {
        assert!(events.iter().any(|e| e["type"] == kind), "{kind}");
    }
    assert_eq!(events[events.len() - 2]["type"], "summary");
    assert_eq!(events.last().unwrap()["data"]["processing_complete"], true);
    let prior = std::fs::read(&report).unwrap();
    let failed = run(
        &[
            "--live-jsonl",
            "--encoding",
            "utf16be",
            "-j",
            report.to_str().unwrap(),
            "-",
        ],
        b"\xff\xfea\0b\0",
    );
    assert!(!failed.status.success());
    assert_eq!(std::fs::read(report).unwrap(), prior);
}

#[test]
fn live_failure_has_no_completion_and_limits_keep_exit_policy() {
    let failure = run(
        &["--live-jsonl", "--encoding", "utf16be", "-"],
        b"\xff\xfea\0b\0",
    );
    assert!(!failure.status.success());
    let text = String::from_utf8(failure.stdout).unwrap();
    assert!(text.contains("start"));
    assert!(!text.contains("\"type\":\"complete\""));
    let limited = run(
        &[
            "--live-jsonl",
            "--max-string-bytes",
            "4",
            "--inconclusive-exit-code",
            "9",
            "-",
        ],
        b"https://example.com",
    );
    assert_eq!(limited.status.code(), Some(9));
    let last: serde_json::Value = serde_json::from_str(
        String::from_utf8(limited.stdout)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last["data"]["analysis_coverage"]["status"], "limited");
}

#[test]
fn cancelling_live_stdout_leaves_no_completion_marker() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;
    let mut child = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .args(["--live-jsonl", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    stdin.write_all(b"https://example.com\0").unwrap();
    stdin.flush().unwrap();
    let first = rx.recv_timeout(Duration::from_secs(10));
    let second = rx.recv_timeout(Duration::from_secs(10));
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    reader.join().unwrap();
    assert!(!output.status.success());
    let parse = |s: String| serde_json::from_str::<serde_json::Value>(&s).unwrap();
    assert_eq!(parse(first.unwrap().unwrap())["type"], "start");
    assert_eq!(parse(second.unwrap().unwrap())["type"], "string");
    assert!(rx
        .into_iter()
        .all(|line| parse(line.unwrap())["type"] != "complete"));
}

#[test]
fn cancelling_live_named_report_preserves_previous_destination() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("report.jsonl");
    std::fs::write(&destination, b"previous report").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .args(["--live-jsonl", "-j", destination.to_str().unwrap(), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"https://example.com\0").unwrap();
    stdin.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut finding_written = false;
    while Instant::now() < deadline {
        finding_written = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path() != destination)
            .any(|entry| {
                std::fs::read_to_string(entry.path())
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .any(|event| event["type"] == "string")
            });
        if finding_written {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    assert!(finding_written, "no partial finding observed: {output:?}");
    assert!(!output.status.success());
    assert_eq!(std::fs::read(destination).unwrap(), b"previous report");
}

#[test]
fn unreadable_input_never_publishes_a_complete_report() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("report.jsonl");
    std::fs::write(&destination, b"previous report").unwrap();
    let output = run(
        &[
            "--live-jsonl",
            dir.path().to_str().unwrap(),
            "-j",
            destination.to_str().unwrap(),
        ],
        b"",
    );
    assert!(!output.status.success());
    assert_eq!(std::fs::read(destination).unwrap(), b"previous report");
    let output = run(&["--live-jsonl", dir.path().to_str().unwrap()], b"");
    assert!(!output.status.success());
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_ne!(event["type"], "complete");
    }
}

#[test]
fn indicator_export_deduplicates_raw_and_decoded_evidence() {
    use base64::Engine;
    let value = "https://example.com";
    let token = base64::engine::general_purpose::STANDARD.encode(value);
    let input = format!("{value}\0{value}\0config={token}");
    let output = run(
        &["--export-indicators", "-", "--category", "URL", "-"],
        input.as_bytes(),
    );
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = json["indicators"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let indicator = &entries[0];
    assert_eq!(indicator["value"], value);
    assert_eq!(indicator["validation_status"], "validated");
    assert_eq!(indicator["observed_occurrences"], 3);
    let locations = indicator["locations"].as_array().unwrap();
    assert_eq!(locations.len(), 3);
    assert_eq!(locations[0]["source_offset"], 0);
    assert_eq!(locations[1]["source_offset"], value.len() + 1);
    assert_eq!(locations[2]["source_offset"], (value.len() + 1) * 2 + 7);
    assert_eq!(locations[2]["source_end_offset"], input.len());
    assert_eq!(locations[2]["decode_depth"], 1);
    assert_eq!(locations[2]["decoded_offset"], 0);
    assert_eq!(json["context"]["file_summary"]["size_bytes"], input.len());
    assert_eq!(json["context"]["export_limited"], false);
}

#[test]
fn indicator_export_preserves_empty_limited_and_invalid_results() {
    let run_export = |flags: &[&str], input: &[u8]| {
        let mut args = vec!["--export-indicators", "-", "-"];
        args.extend_from_slice(flags);
        let output = run(&args, input);
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output, json)
    };
    let (_, empty) = run_export(&[], b"");
    assert_eq!(empty["indicators"], serde_json::json!([]));
    assert_eq!(empty["context"]["processing_complete"], true);
    let (output, limited) = run_export(
        &["--max-string-bytes", "4", "--inconclusive-exit-code", "9"],
        b"https://example.com",
    );
    assert_eq!(output.status.code(), Some(9));
    assert_eq!(limited["context"]["analysis_coverage"]["status"], "limited");
    let (_, invalid) = run_export(&["--category", "credit_card"], b"4111111111111112");
    assert_eq!(invalid["indicators"][0]["validation_status"], "invalid");
    let input = "https://example.com\0".repeat(65);
    let (_, capped) = run_export(&["--category", "URL"], input.as_bytes());
    assert_eq!(capped["indicators"][0]["observed_occurrences"], 65);
    assert_eq!(
        capped["indicators"][0]["locations"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(capped["context"]["export_limited"], true);
    assert_eq!(
        capped["context"]["analysis_coverage"]["limitations"]["indicator_export_limited"],
        true
    );
}

#[test]
fn export_destinations_are_validated_and_failures_preserve_old_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.json");
    std::fs::write(&path, b"previous export").unwrap();
    let destination = path.to_str().unwrap();
    for args in [
        vec!["--export-indicators", "-", "--jsonl", "-"],
        vec!["--export-indicators", destination, "-j", destination, "-"],
        vec![
            "--export-indicators",
            destination,
            "--encoding",
            "utf16be",
            "-",
        ],
    ] {
        let output = run(&args, b"\xff\xfea\0b\0");
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"previous export");
    }
    let report = dir.path().join("analysis.json");
    let output = run(
        &[
            "--export-indicators",
            destination,
            "-j",
            report.to_str().unwrap(),
            "-q",
            "-",
        ],
        b"https://example.com",
    );
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    for file in [&path, &report] {
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert!(json.is_object());
    }
}

#[test]
fn live_export_contains_only_primary_comparison_indicators_and_utf16_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let other = dir.path().join("other.bin");
    let export = dir.path().join("indicators.json");
    std::fs::write(
        &other,
        "https://other.example"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let value = "https://example.com";
    let mut input = vec![0, 0];
    input.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
    let output = run(
        &[
            "--live-jsonl",
            "--encoding",
            "utf16le",
            "--offset",
            "2",
            "--category",
            "URL",
            "--compare",
            other.to_str().unwrap(),
            "--export-indicators",
            export.to_str().unwrap(),
            "-",
        ],
        &input,
    );
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(export).unwrap()).unwrap();
    assert_eq!(json["indicators"].as_array().unwrap().len(), 1);
    assert_eq!(json["indicators"][0]["value"], value);
    assert_eq!(json["indicators"][0]["locations"][0]["source_offset"], 2);
    assert_eq!(
        json["indicators"][0]["locations"][0]["source_end_offset"],
        input.len()
    );
    let last: serde_json::Value = serde_json::from_str(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last["type"], "complete");
}

#[test]
fn csv_export_has_context_even_without_indicators() {
    let output = run(
        &["--export-indicators", "-", "--export-format", "csv", "-"],
        b"",
    );
    assert!(output.status.success(), "{output:?}");
    let csv = String::from_utf8(output.stdout).unwrap();
    assert!(csv.starts_with("\"record_type\",\"category\",\"value\""));
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.contains("\"context\""));
    assert!(csv.contains("\"\"processing_complete\"\":true"));
}
