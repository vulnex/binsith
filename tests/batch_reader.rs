use binsith::{
    batch::reader::{self, Limits, ValidatedBatch},
    scanner::CancellationToken,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
impl Fixture {
    fn new(flags: &[&str]) -> Self {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let input = temp.path().join("samples");
        fs::create_dir_all(input.join("nested")).unwrap();
        fs::write(
            input.join("a.bin"),
            b"prefix https://example.org/a suffix\n",
        )
        .unwrap();
        fs::write(
            input.join("nested/b.bin"),
            b"aHR0cHM6Ly9leGFtcGxlLm9yZy8=\n",
        )
        .unwrap();
        let root = temp.path().join("batch");
        let output = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(&input)
            .args(["--recursive", "--jobs", "2", "--output-dir"])
            .arg(&root)
            .args(flags)
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
        Self { _temp: temp, root }
    }
    fn read(&self) -> reader::Result<ValidatedBatch> {
        reader::read(&self.root, Limits::default(), CancellationToken::default())
    }
    fn manifest(&self) -> Value {
        read_json(&self.root.join("manifest.json"))
    }
    fn journal(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("files.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn write_journal(&self, rows: Vec<Value>) {
        fs::write(
            self.root.join("files.jsonl"),
            rows.into_iter()
                .map(|v| format!("{v}\n"))
                .collect::<String>(),
        )
        .unwrap();
    }
    fn report(&self) -> PathBuf {
        let location = self
            .journal()
            .iter()
            .find_map(|r| {
                r["outcome"]["report"]["location"]
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap();
        self.root.join(location)
    }
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn failure(f: &Fixture) {
    let result = f.read();
    assert!(result.is_err(), "malformed batch accepted");
}

#[test]
fn real_completed_batches_roundtrip_modes_and_preserve_source_bytes() {
    for flags in [
        vec![],
        vec!["-s"],
        vec!["-s", "--no-decode"],
        vec!["-s", "--max-string-bytes", "8"],
        vec!["-s", "--entropy", "--entropy-window", "8"],
        vec!["-s", "--offset", "2", "--length", "20"],
        vec!["--include", "**/*.bin", "--max-depth", "0"],
        vec!["--include", "absent"],
    ] {
        let fixture = Fixture::new(&flags);
        let before = fs::read(fixture.root.join("manifest.json")).unwrap();
        let batch = fixture.read().unwrap_or_else(|e| panic!("{flags:?}: {e}"));
        let mut entries = Vec::new();
        batch
            .visit_entries(|entry| {
                entries.push(entry.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entries.len() as u64,
            batch.manifest().counters.observed_entries
        );
        assert!(batch.imported_bytes() > 0);
        assert!(batch.scratch_high_water_bytes() > 0);
        batch.verify_unchanged().unwrap();
        assert_eq!(
            fs::read(fixture.root.join("manifest.json")).unwrap(),
            before
        );
    }
}

#[test]
fn incomplete_and_claimed_batches_are_rejected() {
    let f = Fixture::new(&[]);
    let mut m = f.manifest();
    m["status"] = json!("incomplete");
    write_json(&f.root.join("manifest.json"), &m);
    failure(&f);
    let f = Fixture::new(&[]);
    fs::write(f.root.join(".binsith.lock"), b"stale").unwrap();
    failure(&f);
}

#[test]
fn journal_reconciliation_rejects_gaps_duplicates_wrong_paths_and_missing_terminals() {
    for mutation in 0..6 {
        let f = Fixture::new(&[]);
        let mut rows = f.journal();
        match mutation {
            0 => rows[0]["sequence"] = json!(2),
            1 => rows[0]["batch_id"] = json!("different"),
            2 => {
                rows.pop();
            }
            3 => {
                rows.push(rows.last().unwrap().clone());
                let n = rows.len();
                rows[n - 1]["sequence"] = json!(n);
            }
            4 => {
                for row in &mut rows {
                    row["entry_id"] = json!(2);
                }
            }
            5 => {
                let i = rows
                    .iter()
                    .position(|r| r["record_type"] == "terminal")
                    .unwrap();
                rows[i]["display_path"] = json!("other");
            }
            _ => unreachable!(),
        }
        f.write_journal(rows);
        failure(&f);
    }
}

#[test]
fn report_range_configuration_hash_coverage_and_completion_are_validated() {
    for mutation in 0..8 {
        let f = Fixture::new(&["-s"]);
        let path = f.report();
        let mut value = read_json(&path);
        match mutation {
            0 => value["processing_complete"] = json!(false),
            1 => value["file_summary"]["sha256"] = json!("no"),
            2 => value["scan_range"]["offset"] = json!(999),
            3 => value["metadata"]["configuration"]["strings"] = json!(false),
            4 => value["analysis_coverage"]["limitations"]["truncated_strings"] = json!(100),
            5 => value["strings"][0]["offset"] = json!(u64::MAX),
            6 => value["file_summary"]["file_path"] = json!("unrelated"),
            7 => {
                value.as_object_mut().unwrap().remove("strings");
            }
            _ => unreachable!(),
        }
        write_json(&path, &value);
        failure(&f);
    }
}

#[test]
fn missing_reports_torn_journals_bad_diagnostics_and_counters_fail() {
    let f = Fixture::new(&[]);
    fs::remove_file(f.report()).unwrap();
    failure(&f);
    let f = Fixture::new(&[]);
    let p = f.root.join("files.jsonl");
    let mut bytes = fs::read(&p).unwrap();
    bytes.pop();
    fs::write(p, bytes).unwrap();
    failure(&f);
    let f = Fixture::new(&[]);
    fs::write(f.root.join("errors.jsonl"), b"{}\n").unwrap();
    failure(&f);
    let f = Fixture::new(&[]);
    let mut m = f.manifest();
    m["counters"]["discovery_errors"] = json!(1);
    write_json(&f.root.join("manifest.json"), &m);
    failure(&f);
}

#[test]
fn duplicate_keys_in_known_or_unknown_objects_and_deep_extensions_fail() {
    for payload in [r#""unknown":{"a":1,"a":2},"#, r#""complete":true,"#] {
        let f = Fixture::new(&[]);
        let path = f.report();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(path, format!("{{{payload}{}", &text[1..])).unwrap();
        failure(&f);
    }
    let f = Fixture::new(&[]);
    let path = f.report();
    let text = fs::read_to_string(&path).unwrap();
    let nested = format!("{}0{}", "[".repeat(66), "]".repeat(66));
    fs::write(path, format!("{{\"unknown\":{nested},{}", &text[1..])).unwrap();
    failure(&f);
}

#[test]
fn additive_report_fields_and_property_reordering_are_accepted() {
    let f = Fixture::new(&["-s"]);
    let path = f.report();
    let mut value = read_json(&path);
    value["future_metadata"] = json!([{"nested":[true,null,1.5]},"extension"]);
    write_json(&path, &value);
    f.read().unwrap();
}

#[test]
fn source_mutation_after_validation_is_detected() {
    let f = Fixture::new(&[]);
    let batch = f.read().unwrap();
    fs::write(f.report(), b"{}").unwrap();
    assert!(batch.verify_unchanged().is_err());
}

#[test]
fn resource_limits_and_cancellation_fail_without_publication() {
    let f = Fixture::new(&[]);
    for limits in [
        Limits {
            manifest_bytes: 8,
            ..Default::default()
        },
        Limits {
            line_bytes: 8,
            ..Default::default()
        },
        Limits {
            entries: 1,
            ..Default::default()
        },
        Limits {
            journal_records: 1,
            ..Default::default()
        },
        Limits {
            import_bytes: 4,
            ..Default::default()
        },
        Limits {
            scratch_bytes: 10,
            ..Default::default()
        },
        Limits {
            sort_buffer_bytes: 8,
            ..Default::default()
        },
    ] {
        assert!(reader::read(&f.root, limits, CancellationToken::default()).is_err());
    }
    let token = CancellationToken::default();
    token.cancel();
    assert_eq!(
        reader::read(&f.root, Limits::default(), token)
            .err()
            .unwrap()
            .exit_code(),
        130
    );
    assert_eq!(
        reader::read(
            &f.root,
            Limits {
                import_bytes: 4,
                ..Default::default()
            },
            CancellationToken::default()
        )
        .err()
        .unwrap()
        .exit_code(),
        2
    );
}

#[cfg(unix)]
#[test]
fn linked_roots_and_shards_are_never_followed() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new(&[]);
    let alias = f._temp.path().join("alias");
    symlink(&f.root, &alias).unwrap();
    assert!(reader::read(&alias, Limits::default(), CancellationToken::default()).is_err());
    let path = f.report();
    let shard = path.parent().unwrap();
    let moved = f._temp.path().join("outside");
    fs::rename(shard, &moved).unwrap();
    symlink(&moved, shard).unwrap();
    failure(&f);
}

#[test]
fn report_location_escape_is_rejected_before_open() {
    let f = Fixture::new(&[]);
    let mut rows = f.journal();
    let terminal = rows
        .iter_mut()
        .find(|r| r["record_type"] == "terminal")
        .unwrap();
    terminal["outcome"]["report"]["location"] = json!("../../outside");
    f.write_journal(rows);
    failure(&f);
}

#[test]
fn orphan_reports_are_counted_without_adoption_or_sample_access() {
    let f = Fixture::new(&[]);
    let report = f.report();
    let orphan = report.parent().unwrap().join("orphan.json");
    fs::write(&orphan, b"not a valid report and never parsed").unwrap();
    // Source samples and display-only roots are not required by import.
    fs::remove_dir_all(f._temp.path().join("samples")).unwrap();
    let batch = f.read().unwrap();
    assert_eq!(batch.unreferenced_artifact_entries(), 1);
    assert_eq!(batch.manifest().counters.complete, 2);
}

#[test]
fn diagnostic_linkage_and_failed_files_are_reconciled() {
    let f = Fixture::new(&["--offset", "34"]);
    f.read().unwrap();
    let p = f.root.join("errors.jsonl");
    let mut rows: Vec<Value> = fs::read_to_string(&p)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!rows.is_empty());
    rows[0]["entry_id"] = json!(999);
    fs::write(
        p,
        rows.into_iter()
            .map(|r| format!("{r}\n"))
            .collect::<String>(),
    )
    .unwrap();
    failure(&f);
}

#[test]
fn new_claim_after_validation_prevents_final_verification() {
    let f = Fixture::new(&[]);
    let batch = f.read().unwrap();
    fs::write(f.root.join(".binsith.lock"), b"new writer").unwrap();
    assert!(batch.verify_unchanged().is_err());
}

#[test]
fn selected_native_encoding_must_agree_with_the_journal() {
    let f = Fixture::new(&["--include", "**"]);
    let mut m = f.manifest();
    m["selection"]["native_encoding"] = json!(if cfg!(windows) {
        "unix-bytes"
    } else {
        "windows-utf16"
    });
    write_json(&f.root.join("manifest.json"), &m);
    failure(&f);
}

#[test]
fn native_utf16_findings_and_embedded_passes_are_supported() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = temp.path().join("samples");
    fs::create_dir(&input).unwrap();
    let bytes: Vec<u8> = "https://example.org/utf16"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    fs::write(input.join("utf16"), bytes).unwrap();
    for (i, flags) in [
        vec!["-s", "--scan-utf16"],
        vec!["-s", "--encoding", "utf16le"],
    ]
    .into_iter()
    .enumerate()
    {
        let output = temp.path().join(format!("out-{i}"));
        let result = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(&input)
            .args(["--output-dir"])
            .arg(&output)
            .args(flags)
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        reader::read(&output, Limits::default(), CancellationToken::default()).unwrap();
    }
}

#[test]
fn released_v05_fixture_is_accepted_without_original_samples() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/batch/released-v0.5");
    let batch = reader::read(&root, Limits::default(), CancellationToken::default()).unwrap();
    assert_eq!(batch.manifest().build.version, "0.5.0");
    assert_eq!(batch.manifest().counters.complete, 1);
    assert_eq!(batch.manifest().counters.files_with_indicators, Some(1));
}

#[test]
fn journal_arrival_order_does_not_change_canonical_inventory() {
    let f = Fixture::new(&[]);
    let paths = |batch: ValidatedBatch| {
        let mut paths = Vec::new();
        batch
            .visit_entries(|e| {
                paths.push(e.path.report_id());
                Ok(())
            })
            .unwrap();
        paths
    };
    let before = paths(f.read().unwrap());
    let rows = f.journal();
    let mut reordered: Vec<_> = rows
        .iter()
        .rev()
        .filter(|r| r["record_type"] == "admission")
        .cloned()
        .collect();
    reordered.extend(
        rows.into_iter()
            .rev()
            .filter(|r| r["record_type"] == "terminal"),
    );
    for (i, row) in reordered.iter_mut().enumerate() {
        row["sequence"] = json!(i + 1);
    }
    f.write_journal(reordered);
    assert_eq!(paths(f.read().unwrap()), before);
}

#[test]
fn aliased_report_files_are_rejected_even_with_consistent_display_fields() {
    let f = Fixture::new(&[]);
    let mut rows = f.journal();
    let reports: Vec<_> = rows
        .iter()
        .filter(|r| r["record_type"] == "terminal")
        .cloned()
        .collect();
    let first = &reports[0];
    let second = &reports[1];
    let first_path = f
        .root
        .join(first["outcome"]["report"]["location"].as_str().unwrap());
    let second_path = f
        .root
        .join(second["outcome"]["report"]["location"].as_str().unwrap());
    fs::remove_file(&second_path).unwrap();
    fs::hard_link(&first_path, &second_path).unwrap();
    for row in &mut rows {
        if row["entry_id"] == second["entry_id"] {
            row["display_path"] = first["display_path"].clone();
            if row["record_type"] == "terminal" {
                row["outcome"]["report"]["selected_bytes"] =
                    first["outcome"]["report"]["selected_bytes"].clone();
            }
        }
    }
    f.write_journal(rows);
    assert!(f.read().err().unwrap().to_string().contains("alias"));
}

#[test]
fn large_finding_details_stream_beyond_the_per_field_capture_budget() {
    use std::io::Write;
    let f = Fixture::new(&["-s"]);
    let (path, mut report, mut finding) = f
        .journal()
        .iter()
        .filter_map(|row| {
            let path = f.root.join(row["outcome"]["report"]["location"].as_str()?);
            let report = read_json(&path);
            let finding = report["strings"]
                .as_array()?
                .iter()
                .find(|f| f["match_details"].as_array().is_some_and(|a| !a.is_empty()))?
                .clone();
            Some((path, report, finding))
        })
        .next()
        .unwrap();
    let mut detail = finding["match_details"][0].clone();
    assert!(detail.is_object());
    detail["future_extension"] = json!("x".repeat(1024));
    finding.as_object_mut().unwrap().remove("match_details");
    report.as_object_mut().unwrap().remove("strings");
    let report = serde_json::to_vec(&report).unwrap();
    let finding = serde_json::to_vec(&finding).unwrap();
    let detail = serde_json::to_vec(&detail).unwrap();
    let mut output = std::io::BufWriter::new(fs::File::create(&path).unwrap());
    output.write_all(&report[..report.len() - 1]).unwrap();
    output.write_all(b",\"strings\":[").unwrap();
    output.write_all(&finding[..finding.len() - 1]).unwrap();
    output.write_all(b",\"match_details\":[").unwrap();
    for n in 0..14000 {
        if n > 0 {
            output.write_all(b",").unwrap();
        }
        output.write_all(&detail).unwrap();
    }
    output.write_all(b"]}]}").unwrap();
    output.flush().unwrap();
    drop(output);
    assert!(fs::metadata(&path).unwrap().len() > 16 * 1024 * 1024);
    f.read().unwrap();
}
