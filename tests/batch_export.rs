use binsith::{
    batch::{
        export::{self, Options},
        reader,
    },
    scanner::CancellationToken,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
struct Fixture {
    temp: tempfile::TempDir,
    batch: PathBuf,
}
impl Fixture {
    fn new(flags: &[&str]) -> Self {
        Self::with_samples(
            flags,
            &[
                (
                    "a.bin",
                    "https://example.org/a https://example.org/a\naHR0cHM6Ly9leGFtcGxlLm9yZy9h\n",
                ),
                ("b.bin", "https://example.org/a\n"),
            ],
        )
    }
    fn with_samples(flags: &[&str], samples: &[(&str, &str)]) -> Self {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let input = temp.path().join("samples");
        fs::create_dir(&input).unwrap();
        for (name, contents) in samples {
            let path = input.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let batch = temp.path().join("batch");
        let output = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(&input)
            .args(["--output-dir"])
            .arg(&batch)
            .args(flags)
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
        Self { temp, batch }
    }
    fn destination(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }
    fn run(&self, name: &str, options: Options) -> reader::Result<u8> {
        export::run(
            &self.batch,
            &self.destination(name),
            options,
            CancellationToken::default(),
            |_| Ok(()),
        )
    }
    fn reports(&self) -> Vec<PathBuf> {
        fs::read_to_string(self.batch.join("files.jsonl"))
            .unwrap()
            .lines()
            .filter_map(|line| {
                let v: Value = serde_json::from_str(line).unwrap();
                v["outcome"]["report"]["location"]
                    .as_str()
                    .map(|p| self.batch.join(p))
            })
            .collect()
    }
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write(path: impl AsRef<Path>, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn export_json(f: &Fixture, name: &str) -> Value {
    read(f.destination(name).join("indicators.json"))
}
fn urls(v: &Value) -> Vec<&Value> {
    v["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["value"] == "https://example.org/a")
        .collect()
}
#[test]
fn cli_combines_primary_and_decoded_provenance_and_binds_artifacts() {
    let f = Fixture::new(&["-s"]);
    let output = Command::new(env!("CARGO_BIN_EXE_binsith"))
        .args(["--batch-input"])
        .arg(&f.batch)
        .args(["--output-dir"])
        .arg(f.destination("out"))
        .args(["--batch-csv", "-q"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let v = export_json(&f, "out");
    let indicators = urls(&v);
    assert!(!indicators.is_empty());
    let url = indicators[0];
    assert_eq!(url["observed_occurrences"], 4);
    assert_eq!(url["distinct_file_entries"], 2);
    assert_eq!(url["locations"].as_array().unwrap().len(), 4);
    assert_eq!(url["locations"][0]["decode_depth"], 0);
    assert_eq!(url["locations"][2]["decode_depth"], 1);
    assert!(url["locations"][2]["decoded_offset"].is_number());
    assert!(!url.to_string().contains("evidence"));
    let manifest = read(f.destination("out").join("manifest.json"));
    assert_eq!(manifest["exit_code"], 0);
    for (name, receipt) in manifest["artifacts"].as_object().unwrap() {
        let bytes = fs::read(f.destination("out").join(name)).unwrap();
        assert_eq!(receipt["bytes"], bytes.len() as u64);
        assert_eq!(receipt["sha256"], format!("{:x}", Sha256::digest(bytes)));
    }
    assert_eq!(
        manifest["input_manifest_sha256"],
        format!(
            "{:x}",
            Sha256::digest(fs::read(f.batch.join("manifest.json")).unwrap())
        )
    );
    let summary = read(f.destination("out").join("summary.json"));
    assert_eq!(v["counts"], summary["counts"]);
    assert_eq!(v["coverage"], summary["coverage"]);
    assert!(
        !fs::read_to_string(f.destination("out").join("summary.json"))
            .unwrap()
            .contains(f.temp.path().to_str().unwrap())
    );
    assert!(!f.destination("out").join(".manifest.pending").exists());
}
#[test]
fn reordered_object_fields_and_journal_arrival_preserve_payloads() {
    let f = Fixture::new(&["-s"]);
    f.run("before", Options::default()).unwrap();
    // serde_json's sorted object keys put decoded_layers before primary details
    // and metadata after arrays. Rewriting therefore exercises field independence.
    for path in f.reports() {
        write(&path, &read(&path));
    }
    let path = f.batch.join("files.jsonl");
    let mut rows: Vec<Value> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Reverse file groups while preserving each admission-before-terminal pair.
    rows.sort_by_key(|v| {
        (
            std::cmp::Reverse(v["entry_id"].as_u64().unwrap()),
            v["sequence"].as_u64().unwrap(),
        )
    });
    for (i, v) in rows.iter_mut().enumerate() {
        v["sequence"] = json!(i as u64 + 1);
    }
    fs::write(
        path,
        rows.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
    f.run("after", Options::default()).unwrap();
    assert_eq!(export_json(&f, "before"), export_json(&f, "after"));
    assert_eq!(summary_json(&f, "before"), summary_json(&f, "after"));
}
#[test]
fn summary_only_is_unavailable_and_empty_is_zero() {
    let f = Fixture::new(&[]);
    assert_eq!(f.run("summary", Options::default()).unwrap(), 0);
    let v = export_json(&f, "summary");
    assert!(v["counts"]["observed_occurrences"].is_null());
    assert_eq!(v["coverage"]["aggregation"], "not_analyzed");
    let f = Fixture::new(&["--include", "absent"]);
    assert_eq!(f.run("empty", Options::default()).unwrap(), 0);
    let v = export_json(&f, "empty");
    assert_eq!(v["counts"]["observed_occurrences"], 0);
    assert_eq!(v["counts"]["total_unique_keys"], 0);
    assert_eq!(v["coverage"]["selection"], "explicit_policy");
    assert_eq!(v["scope"]["selection"]["includes"], json!(["absent"]));
}
#[test]
fn location_caps_preserve_exact_observation_and_file_counts() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.locations_per_key = 1;
    assert_eq!(f.run("out", options).unwrap(), 1);
    let v = export_json(&f, "out");
    let url = urls(&v)[0];
    assert_eq!(url["distinct_file_entries"], 2);
    assert_eq!(url["observed_occurrences"], 4);
    assert_eq!(url["location_observations_omitted"], 3);
    assert_eq!(url["locations"].as_array().unwrap().len(), 1);
    assert_eq!(v["coverage"]["aggregation"], "limited");
}
#[test]
fn key_saturation_continues_counting_existing_keys_and_reports_unknown_total() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.keys = 1;
    assert_eq!(f.run("out", options).unwrap(), 1);
    let v = export_json(&f, "out");
    assert_eq!(v["counts"]["retained_unique_keys"], 1);
    assert!(v["counts"]["total_unique_keys"].is_null());
    let i = &v["indicators"][0];
    assert!(i["observed_occurrences"].as_u64().unwrap() > 1);
    let c = &v["counts"];
    assert_eq!(
        c["observed_occurrences"].as_u64().unwrap(),
        i["observed_occurrences"].as_u64().unwrap()
            + c["filtered_observations"].as_u64().unwrap()
            + c["unretained_key_observations"].as_u64().unwrap()
    );
}
#[test]
fn filter_is_applied_before_key_admission() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options {
        validation: export::ValidationFilter::Validated,
        ..Default::default()
    };
    options.limits.keys = 0;
    let code = f.run("out", options).unwrap();
    let v = export_json(&f, "out");
    assert_eq!(v["counts"]["retained_unique_keys"], 0);
    let c = &v["counts"];
    assert_eq!(
        c["observed_occurrences"].as_u64().unwrap(),
        c["filtered_observations"].as_u64().unwrap()
            + c["unretained_key_observations"].as_u64().unwrap()
    );
    assert_eq!(
        code,
        u8::from(c["unretained_key_observations"].as_u64().unwrap() > 0)
    );
}
#[test]
fn source_limits_degrade_status_and_preserve_original_count_units() {
    let f = Fixture::new(&["-s", "--max-string-bytes", "8"]);
    assert_eq!(f.run("out", Options::default()).unwrap(), 1);
    let v = export_json(&f, "out");
    assert_eq!(v["coverage"]["scan"], "limited");
    assert!(v["counts"]["source_counters"]["limited"].as_u64().unwrap() > 0);
}
#[test]
fn rejects_existing_overlapping_and_symlink_destinations_without_overwrite() {
    let f = Fixture::new(&["-s"]);
    let existing = f.destination("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), "original").unwrap();
    for destination in [&existing, &f.batch, &f.batch.join("nested"), f.temp.path()] {
        assert_eq!(
            export::run(
                &f.batch,
                destination,
                Options::default(),
                CancellationToken::default(),
                |_| Ok(())
            )
            .unwrap_err()
            .exit_code(),
            2
        );
    }
    assert_eq!(
        fs::read_to_string(existing.join("keep")).unwrap(),
        "original"
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&existing, f.destination("link")).unwrap();
        assert!(export::run(
            &f.batch,
            &f.destination("link/out"),
            Options::default(),
            CancellationToken::default(),
            |_| Ok(())
        )
        .is_err());
        assert!(!existing.join("out").exists());
    }
}
#[test]
fn failures_and_interrupts_never_publish_completion() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.bundle_bytes = 100;
    assert_eq!(f.run("small", options).unwrap_err().exit_code(), 1);
    assert!(!f.destination("small").join("manifest.json").exists());
    let token = CancellationToken::default();
    token.cancel();
    assert_eq!(
        export::run(
            &f.batch,
            &f.destination("cancel"),
            Options::default(),
            token,
            |_| Ok(())
        )
        .unwrap_err()
        .exit_code(),
        130
    );
    assert!(!f.destination("cancel").exists());
    assert_eq!(
        export::run(
            &f.batch,
            &f.destination("stderr"),
            Options::default(),
            CancellationToken::default(),
            |_| Err(std::io::Error::other("closed stderr"))
        )
        .unwrap_err()
        .exit_code(),
        1
    );
    assert!(!f.destination("stderr").exists());
}
#[test]
fn rejects_explicit_scan_flags_and_batch_flags_without_batch_input() {
    let f = Fixture::new(&["-s"]);
    for flags in [
        vec!["-s"],
        vec!["--offset", "0"],
        vec!["--max-string-bytes", "1048576"],
        vec!["--recursive"],
        vec!["--jobs", "1"],
        vec!["--patterns", "missing"],
        vec!["--include", "*"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg("--batch-input")
            .arg(&f.batch)
            .arg("--output-dir")
            .arg(f.destination("invalid"))
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(out.stdout.is_empty());
        assert!(!f.destination("invalid").exists());
    }
    for flags in [vec!["--batch-csv"], vec!["--batch-validation", "all"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(f.temp.path().join("samples/a.bin"))
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{out:?}");
    }
    let literals = f.destination("literals");
    fs::create_dir(&literals).unwrap();
    for name in ["export", "summary", "batch", "--batch-input"] {
        fs::write(literals.join(name), "sample").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .current_dir(&literals)
            .args(["-q", "--", name])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }
}
#[test]
fn source_changed_before_publication_is_rejected() {
    let f = Fixture::new(&["-s"]);
    let result = export::run(
        &f.batch,
        &f.destination("out"),
        Options::default(),
        CancellationToken::default(),
        |message| {
            if message.starts_with("Writing") {
                fs::write(f.batch.join(".binsith.lock"), "new claim")?;
            }
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().exit_code(), 2);
    assert!(!f.destination("out").join("manifest.json").exists());
}
#[test]
fn released_v05_batch_exports_without_original_samples() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/batch/released-v0.5");
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    assert_eq!(
        export::run(
            &source,
            &t.path().join("out"),
            Options::default(),
            CancellationToken::default(),
            |_| Ok(())
        )
        .unwrap(),
        0
    );
    assert!(!read(t.path().join("out/indicators.json"))["indicators"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn validation_conflicts_are_separate_keys_and_csv_keeps_raw_values() {
    let f = Fixture::new(&["-s"]);
    // Recorded validations are observations, not authority. Both statuses remain
    // actionable, so the source report's actionable flag remains consistent.
    for (i, path) in f.reports().iter().enumerate() {
        let mut v = read(path);
        for finding in v["strings"].as_array_mut().unwrap() {
            for detail in finding["match_details"].as_array_mut().unwrap() {
                if detail["text"] == "https://example.org/a" {
                    detail["validation"]["status"] =
                        json!(if i == 0 { "candidate" } else { "validated" });
                    detail["text"] = json!("=FORMULA,\"quoted\"\r\nnext");
                }
            }
        }
        write(path, &v);
    }
    assert_eq!(
        f.run(
            "out",
            Options {
                csv: true,
                ..Default::default()
            }
        )
        .unwrap(),
        0
    );
    let v = export_json(&f, "out");
    let items: Vec<_> = v["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["value"] == "=FORMULA,\"quoted\"\r\nnext")
        .collect();
    assert!(items.iter().any(|i| i["validation_status"] == "candidate"));
    assert!(items.iter().any(|i| i["validation_status"] == "validated"));
    assert!(items.iter().all(|i| i["distinct_file_entries"] == 1));
    let csv = fs::read_to_string(f.destination("out").join("indicators.csv")).unwrap();
    assert!(csv.contains("\"=FORMULA,\"\"quoted\"\"\r\nnext\""));
}
#[test]
fn reason_and_global_location_budgets_are_explicit_limitations() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.reason_bytes = 0;
    options.limits.location_bytes = 0;
    assert_eq!(f.run("out", options).unwrap(), 1);
    let v = export_json(&f, "out");
    for i in v["indicators"].as_array().unwrap() {
        assert!(i["locations"].as_array().unwrap().is_empty());
        assert_eq!(
            i["location_observations_omitted"],
            i["observed_occurrences"]
        );
        assert_eq!(i["reason_observations_omitted"], i["observed_occurrences"]);
    }
}
#[test]
fn scratch_and_reread_byte_limits_abort_without_a_bundle() {
    let f = Fixture::new(&["-s"]);
    let batch = reader::read(
        &f.batch,
        reader::Limits::default(),
        CancellationToken::default(),
    )
    .unwrap();
    let mut options = Options::default();
    options.reader_limits.import_bytes = batch.imported_bytes();
    assert_eq!(f.run("bytes", options).unwrap_err().exit_code(), 2);
    assert!(!f.destination("bytes").exists());
    let mut options = Options::default();
    options.reader_limits.scratch_bytes = 1;
    assert_eq!(f.run("scratch", options).unwrap_err().exit_code(), 1);
    assert!(!f.destination("scratch").exists());
}
#[test]
fn malformed_import_does_not_create_output() {
    let f = Fixture::new(&["-s"]);
    fs::write(
        f.reports()[0].clone(),
        b"{\"strings\": [], \"strings\": []}",
    )
    .unwrap();
    assert_eq!(f.run("out", Options::default()).unwrap_err().exit_code(), 2);
    assert!(!f.destination("out").exists());
}
#[cfg(unix)]
#[test]
fn bundle_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new(&["-s"]);
    f.run("out", Options::default()).unwrap();
    assert_eq!(
        fs::metadata(f.destination("out"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    for name in ["manifest.json", "indicators.json", "summary.json"] {
        assert_eq!(
            fs::metadata(f.destination("out").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

#[test]
fn released_batch_matches_json_and_csv_golden_payloads() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/batch");
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let out = t.path().join("out");
    export::run(
        &fixtures.join("released-v0.5"),
        &out,
        Options {
            csv: true,
            ..Default::default()
        },
        CancellationToken::default(),
        |_| Ok(()),
    )
    .unwrap();
    for name in ["indicators.json", "summary.json"] {
        assert_eq!(
            read(out.join(name)),
            read(fixtures.join("export-v1").join(name))
        );
    }
    assert_eq!(
        fs::read(out.join("indicators.csv")).unwrap(),
        fs::read(fixtures.join("export-v1/indicators.csv")).unwrap()
    );
}

#[test]
fn a_large_single_finding_spills_details_without_collecting_the_array() {
    use std::io::Write;
    let f = Fixture::new(&["-s"]);
    let path = f
        .reports()
        .into_iter()
        .find(|p| read(p)["file_summary"]["file_path"] == "b.bin")
        .unwrap();
    let mut report = read(&path);
    let mut finding = report["strings"][0].clone();
    let mut detail = finding["match_details"][0].clone();
    detail["future_extension"] = json!("x".repeat(1024));
    let category = detail["pattern"].clone();
    let value = detail["text"].clone();
    finding.as_object_mut().unwrap().remove("match_details");
    report.as_object_mut().unwrap().remove("strings");
    let report = serde_json::to_vec(&report).unwrap();
    let finding = serde_json::to_vec(&finding).unwrap();
    let detail = serde_json::to_vec(&detail).unwrap();
    let mut out = std::io::BufWriter::new(fs::File::create(&path).unwrap());
    out.write_all(&report[..report.len() - 1]).unwrap();
    out.write_all(b",\"strings\":[").unwrap();
    out.write_all(&finding[..finding.len() - 1]).unwrap();
    out.write_all(b",\"match_details\":[").unwrap();
    for i in 0..14000 {
        if i > 0 {
            out.write_all(b",").unwrap();
        }
        out.write_all(&detail).unwrap();
    }
    out.write_all(b"]}]}").unwrap();
    out.flush().unwrap();
    drop(out);
    assert!(fs::metadata(path).unwrap().len() > 16 * 1024 * 1024);
    assert_eq!(f.run("out", Options::default()).unwrap(), 1);
    let v = export_json(&f, "out");
    let i = v["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["category"] == category && i["value"] == value)
        .unwrap();
    assert_eq!(i["observed_occurrences"], 14003);
    assert_eq!(i["distinct_file_entries"], 2);
    assert_eq!(i["locations"].as_array().unwrap().len(), 64);
    assert_eq!(i["location_observations_omitted"], 14003 - 64);
}

#[test]
fn publication_collision_never_replaces_an_existing_manifest() {
    let f = Fixture::new(&["-s"]);
    let destination = f.destination("out");
    let result = export::run(
        &f.batch,
        &destination,
        Options::default(),
        CancellationToken::default(),
        |message| {
            if message.starts_with("Checking") {
                fs::write(destination.join("manifest.json"), "do not replace")?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read_to_string(destination.join("manifest.json")).unwrap(),
        "do not replace"
    );
}
#[test]
fn cancellation_or_diagnostic_failure_at_final_check_leaves_no_completion() {
    let f = Fixture::new(&["-s"]);
    for interrupt in [false, true] {
        let token = CancellationToken::default();
        let destination = f.destination(if interrupt { "interrupt" } else { "diagnostic" });
        let result = export::run(
            &f.batch,
            &destination,
            Options::default(),
            token.clone(),
            |message| {
                if message.starts_with("Checking") {
                    if interrupt {
                        token.cancel();
                    } else {
                        return Err(std::io::Error::other("closed diagnostics"));
                    }
                }
                Ok(())
            },
        );
        assert_eq!(
            result.unwrap_err().exit_code(),
            if interrupt { 130 } else { 1 }
        );
        assert!(destination.join("indicators.json").exists());
        assert!(!destination.join("manifest.json").exists());
    }
}

fn summary_json(f: &Fixture, name: &str) -> Value {
    read(f.destination(name).join("summary.json"))
}
#[test]
fn summary_ranks_distinct_entries_before_occurrences_and_navigates_reports() {
    let repeated = "https://example.org/only-a\n".repeat(10);
    let first = format!("{repeated}https://example.org/shared\n");
    let f = Fixture::with_samples(
        &["-s"],
        &[("a.bin", &first), ("b.bin", "https://example.org/shared\n")],
    );
    // Export operates with original samples absent.
    fs::remove_dir_all(f.temp.path().join("samples")).unwrap();
    f.run("out", Options::default()).unwrap();
    let summary = summary_json(&f, "out");
    let indicators = export_json(&f, "out");
    let ranked = summary["ranking"]["entries"].as_array().unwrap();
    let shared = ranked
        .iter()
        .position(|i| i["value"] == "https://example.org/shared")
        .unwrap();
    let single = ranked
        .iter()
        .position(|i| i["value"] == "https://example.org/only-a")
        .unwrap();
    assert!(shared < single);
    assert_eq!(ranked[shared]["distinct_file_entries"], 2);
    assert_eq!(ranked[single]["observed_occurrences"], 10);
    let expected_shared = indicators["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["distinct_file_entries"].as_u64().unwrap() > 1)
        .count();
    assert_eq!(summary["ranking"]["retained_shared_keys"], expected_shared);
    for (n, item) in ranked.iter().enumerate() {
        assert_eq!(item["rank"], n + 1);
        let source = &indicators["indicators"][item["indicator_index"].as_u64().unwrap() as usize];
        for key in [
            "category",
            "value",
            "validation_status",
            "distinct_file_entries",
            "observed_occurrences",
        ] {
            assert_eq!(item[key], source[key]);
        }
        let samples = item["source_samples"].as_array().unwrap();
        assert_eq!(
            samples.len() as u64 + item["source_entries_not_shown"].as_u64().unwrap(),
            item["distinct_file_entries"].as_u64().unwrap()
        );
        for location in samples {
            let path = f.batch.join(location["report_location"].as_str().unwrap());
            assert!(path.is_file());
            assert!(path.file_stem().unwrap() == location["report_id"].as_str().unwrap());
            assert!(read(path)["processing_complete"].as_bool().unwrap());
            assert!(source["locations"].as_array().unwrap().contains(location));
        }
    }
    for pair in ranked.windows(2) {
        if pair[0]["distinct_file_entries"] == pair[1]["distinct_file_entries"] {
            let tuple = |v: &Value| {
                ["category", "value", "validation_status"]
                    .map(|k| v[k].as_str().unwrap().to_owned())
            };
            assert!(tuple(&pair[0]) < tuple(&pair[1]));
        }
    }
}
#[test]
fn summary_presentation_caps_are_explicit_and_do_not_limit_the_index() {
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.summary_keys = 1;
    options.limits.summary_sources_per_key = 1;
    assert_eq!(f.run("out", options).unwrap(), 0);
    let s = summary_json(&f, "out");
    let keys = export_json(&f, "out")["indicators"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(s["ranking"]["keys_not_shown"], keys - 1);
    assert_eq!(
        s["ranking"]["entries"][0]["source_samples"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(s["ranking"]["entries"][0]["source_entries_not_shown"], 1);
    assert_eq!(s["coverage"]["aggregation"], "complete");
    assert_eq!(s["ranking"]["scope"], "retained_keys");
    let mut options = Options::default();
    options.limits.locations_per_key = 0;
    assert_eq!(f.run("no-locations", options).unwrap(), 1);
    let s = summary_json(&f, "no-locations");
    for item in s["ranking"]["entries"].as_array().unwrap() {
        assert!(item["source_samples"].as_array().unwrap().is_empty());
        assert_eq!(
            item["source_entries_not_shown"],
            item["distinct_file_entries"]
        );
    }
}
#[test]
fn summary_selected_bytes_count_ranges_and_keep_failed_sizes_unknown() {
    let f = Fixture::new(&["-s", "--offset", "2", "--length", "5"]);
    f.run("range", Options::default()).unwrap();
    let s = summary_json(&f, "range");
    assert_eq!(
        s["counts"]["selected_bytes"],
        json!({"reported_total": 10, "reported_entries": 2, "unreported_eligible_entries": 0, "eligible_total": 10})
    );
    let f = Fixture::new(&["--offset", "30"]);
    assert_eq!(f.run("partial", Options::default()).unwrap(), 1);
    let s = summary_json(&f, "partial");
    let bytes = &s["counts"]["selected_bytes"];
    assert_eq!(bytes["reported_entries"], 1);
    assert_eq!(bytes["unreported_eligible_entries"], 1);
    assert!(bytes["eligible_total"].is_null());
    assert_eq!(s["coverage"]["scan"], "incomplete");
    assert_eq!(s["coverage"]["string_analysis"], "not_analyzed");
    assert!(s["ranking"]["retained_shared_keys"].is_null());
    assert!(s["outcome_reasons"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["outcome"] == "failed" && r["observed_entries"] == 1));
}
#[test]
fn selection_scenario_explains_policy_skips_without_inventing_descendant_counts() {
    let f = Fixture::with_samples(
        &[
            "-s",
            "--recursive",
            "--exclude",
            "cache/",
            "--max-depth",
            "1",
            "--max-file-bytes",
            "40",
        ],
        &[
            ("a.bin", "https://example.org/a\n"),
            ("nested/b.bin", "https://example.org/a\n"),
            ("cache/ignored.bin", "https://example.org/a\n"),
            ("nested/deep/ignored.bin", "https://example.org/a\n"),
            (
                "large.bin",
                "https://example.org/this-file-is-too-large-for-the-configured-size-cap\n",
            ),
        ],
    );
    assert_eq!(f.run("out", Options::default()).unwrap(), 0);
    let s = summary_json(&f, "out");
    assert_eq!(s["counts"]["source_counters"]["complete"], 2);
    assert_eq!(s["counts"]["source_counters"]["policy_skipped"], 3);
    assert_eq!(s["coverage"]["selection"], "explicit_policy");
    let reasons = s["outcome_reasons"]["entries"].as_array().unwrap();
    for reason in ["selection_excluded", "selection_depth", "selection_size"] {
        assert!(reasons.iter().any(|r| r["outcome"] == "skipped"
            && r["reason"] == reason
            && r["observed_entries"] == 1));
    }
    assert_eq!(
        s["outcome_reasons"]["unvisited_descendants"],
        "unknown_not_counted"
    );
    let mut options = Options::default();
    options.limits.summary_reason_keys = 0;
    assert_eq!(f.run("capped", options).unwrap(), 0);
    let s = summary_json(&f, "capped");
    assert_eq!(s["outcome_reasons"]["unretained_reason_entries"], 3);
    assert!(s["outcome_reasons"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
}
#[test]
fn summary_preserves_empty_unanalyzed_and_saturated_states() {
    let f = Fixture::new(&[]);
    f.run("out", Options::default()).unwrap();
    let s = summary_json(&f, "out");
    for name in [
        "retained_keys_considered",
        "retained_shared_keys",
        "keys_not_shown",
    ] {
        assert!(s["ranking"][name].is_null());
    }
    let f = Fixture::new(&["--include", "absent"]);
    f.run("out", Options::default()).unwrap();
    let s = summary_json(&f, "out");
    assert_eq!(s["ranking"]["retained_shared_keys"], 0);
    assert_eq!(s["counts"]["selected_bytes"]["eligible_total"], 0);
    let f = Fixture::new(&["-s"]);
    let mut options = Options::default();
    options.limits.keys = 1;
    assert_eq!(f.run("out", options).unwrap(), 1);
    let s = summary_json(&f, "out");
    assert_eq!(s["ranking"]["key_admission_saturated"], true);
    assert_eq!(s["ranking"]["retained_keys_considered"], 1);
    assert!(s["counts"]["total_unique_keys"].is_null());
}

#[test]
fn selected_byte_total_overflow_rejects_the_bundle() {
    let f = Fixture::new(&[]);
    for p in f.reports() {
        let mut v = read(&p);
        v["file_summary"]["size_bytes"] = json!(u64::MAX);
        v["scan_range"]["length"] = json!(u64::MAX);
        write(&p, &v);
    }
    let p = f.batch.join("files.jsonl");
    let lines: Vec<_> = fs::read_to_string(&p)
        .unwrap()
        .lines()
        .map(|line| {
            let mut v: Value = serde_json::from_str(line).unwrap();
            if v["outcome"]["report"].is_object() {
                v["outcome"]["report"]["selected_bytes"] = json!(u64::MAX);
            }
            format!("{v}\n")
        })
        .collect();
    fs::write(p, lines.concat()).unwrap();
    let error = f.run("out", Options::default()).unwrap_err();
    assert_eq!(error.exit_code(), 2);
    assert!(error.to_string().contains("counter overflow"));
    assert!(!f.destination("out").exists());
}
