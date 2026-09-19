//
// VULNEX -BinSith-
//
// File: batch_contract.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use binsith::batch::{
    Counters, ErrorRecord, Event, ExitStatus, JournalRecord, Outcome, RelativePath,
};
use serde_json::{json, Value};
use std::path::Path;

#[test]
fn path_identity_matches_independent_golden_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/batch/paths.json")).unwrap();
    for vector in vectors {
        let path: RelativePath = serde_json::from_value(vector["path"].clone()).unwrap();
        assert_eq!(path.report_id(), vector["report_id"]);
        assert_eq!(path.report_location(), vector["location"]);
        assert_eq!(serde_json::to_value(path).unwrap(), vector["path"]);
    }
}

fn encoded_path(raw: &[u8], windows: bool) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine};
    json!({"encoding": if windows { "windows-utf16le-base64" } else { "unix-bytes-base64" },
           "value": STANDARD.encode(raw)})
}

#[test]
fn unsafe_or_ambiguous_paths_are_rejected_on_every_host() {
    for value in [
        "",
        "/absolute",
        "../escape",
        "a/../b",
        "./a",
        "a/./b",
        "a//b",
        "a/",
        "a\0b",
    ] {
        assert!(
            serde_json::from_value::<RelativePath>(encoded_path(value.as_bytes(), false)).is_err(),
            "{value:?}"
        );
    }
    for value in [
        "",
        "C:\\file",
        "C:file",
        "\\\\host\\share",
        "\\root",
        "a\\..\\b",
        "a/../b",
        "a\\\\b",
        "a:stream",
        "a\0b",
    ] {
        let bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            serde_json::from_value::<RelativePath>(encoded_path(&bytes, true)).is_err(),
            "{value:?}"
        );
    }
    assert!(serde_json::from_value::<RelativePath>(encoded_path(&[1], true)).is_err());
    assert!(serde_json::from_value::<RelativePath>(
        json!({"encoding":"unix-bytes-base64", "value":"!"})
    )
    .is_err());
}

#[test]
fn native_paths_use_lossless_encoding_and_generated_destinations() {
    let a = RelativePath::from_relative(Path::new("a")).unwrap();
    let b = RelativePath::from_relative(Path::new("a.json").join("b").as_path()).unwrap();
    assert_ne!(a.report_location(), b.report_location());
    assert_eq!(a.report_location().split('/').count(), 3);
    assert!(a.report_location().is_ascii());
    assert!(RelativePath::from_relative(Path::new("../outside")).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let native = std::ffi::OsStr::from_bytes(b"non-utf8-\xff.bin");
        let path = RelativePath::from_relative(Path::new(native)).unwrap();
        let wire = serde_json::to_value(path).unwrap();
        assert_eq!(wire, encoded_path(b"non-utf8-\xff.bin", false));
    }
}

#[test]
fn journals_roundtrip_all_outcomes_and_accept_additive_fields() {
    let mut outcomes = Vec::new();
    for (index, line) in include_str!("fixtures/batch/files.jsonl")
        .lines()
        .enumerate()
    {
        let mut value: Value = serde_json::from_str(line).unwrap();
        let record: JournalRecord = serde_json::from_value(value.clone()).unwrap();
        record.validate().unwrap();
        assert_eq!(record.sequence, index as u64 + 1);
        assert_eq!(serde_json::to_value(&record).unwrap(), value);
        if let Event::Terminal { outcome } = &record.event {
            outcomes.push(outcome.clone());
        }
        value["future_metadata"] = json!({"ignored": true});
        assert_eq!(
            serde_json::from_value::<JournalRecord>(value).unwrap(),
            record
        );
    }
    assert_eq!(outcomes.len(), 5);
    assert!(
        matches!(&outcomes[0], Outcome::Complete { report } if report.has_actionable_indicators == Some(false))
    );
    assert!(
        matches!(&outcomes[1], Outcome::Limited { report } if report.has_actionable_indicators == Some(true))
    );
    let error: ErrorRecord =
        serde_json::from_str(include_str!("fixtures/batch/errors.jsonl")).unwrap();
    assert_eq!(error.entry_id, Some(3));
    assert_eq!(error.code, "permission_denied");
}

#[test]
fn unsupported_versions_missing_required_fields_and_torn_records_fail() {
    let line = include_str!("fixtures/batch/files.jsonl")
        .lines()
        .next()
        .unwrap();
    let base: Value = serde_json::from_str(line).unwrap();
    for version in [json!(0), json!(2), json!("1"), json!(-1)] {
        let mut value = base.clone();
        value["schema_version"] = version;
        assert!(serde_json::from_value::<JournalRecord>(value).is_err());
    }
    for field in [
        "schema_version",
        "batch_id",
        "sequence",
        "entry_id",
        "path",
        "display_path",
        "record_type",
    ] {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<JournalRecord>(value).is_err(),
            "{field}"
        );
    }
    assert!(serde_json::from_str::<JournalRecord>(&line[..line.len() - 1]).is_err());
}

#[test]
fn publication_identity_cannot_point_to_a_different_report() {
    let line = include_str!("fixtures/batch/files.jsonl")
        .lines()
        .nth(1)
        .unwrap();
    for field in ["report_id", "location"] {
        let mut value: Value = serde_json::from_str(line).unwrap();
        value["outcome"]["report"][field] = json!("../elsewhere");
        let record: JournalRecord = serde_json::from_value(value).unwrap();
        assert!(record.validate().is_err());
    }
}

#[test]
fn checkpoint_counters_reject_overflow_and_inconsistent_coverage() {
    let mut counters = Counters {
        observed_entries: 5,
        eligible: 4,
        policy_skipped: 1,
        complete: 1,
        limited: 1,
        failed: 1,
        cancelled: 1,
        files_with_indicators: Some(1),
        limited_files_with_indicators: Some(1),
        ..Default::default()
    };
    counters.validate().unwrap();
    counters.limited_files_with_indicators = None;
    assert!(counters.validate().is_err());
    counters.limited_files_with_indicators = Some(2);
    assert!(counters.validate().is_err());
    counters.limited_files_with_indicators = Some(1);
    counters.active = 1;
    assert!(counters.validate().is_err());
    let overflow = Counters {
        queued: u64::MAX,
        active: 1,
        ..Default::default()
    };
    assert!(overflow.validate().is_err());
}

#[test]
fn exit_policy_distinguishes_empty_failed_limited_and_interrupted_batches() {
    let empty = Counters::default();
    assert_eq!(ExitStatus::for_execution(&empty, true, false).code(), 0);
    assert_eq!(ExitStatus::for_execution(&empty, false, false).code(), 1);
    let skipped = Counters {
        observed_entries: 1,
        policy_skipped: 1,
        ..Default::default()
    };
    assert_eq!(ExitStatus::for_execution(&skipped, true, false).code(), 0);
    for counters in [
        Counters {
            discovery_errors: 1,
            ..Default::default()
        },
        Counters {
            observed_entries: 1,
            eligible: 1,
            limited: 1,
            ..Default::default()
        },
        Counters {
            observed_entries: 1,
            eligible: 1,
            failed: 1,
            ..Default::default()
        },
        Counters {
            observed_entries: 1,
            eligible: 1,
            cancelled: 1,
            ..Default::default()
        },
        Counters {
            observed_entries: 1,
            eligible: 1,
            active: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(ExitStatus::for_execution(&counters, true, false).code(), 1);
        assert_eq!(ExitStatus::for_execution(&counters, true, true).code(), 130);
    }
    assert_eq!(ExitStatus::SetupFailure.code(), 2);
    let hit = Counters {
        observed_entries: 1,
        eligible: 1,
        complete: 1,
        files_with_indicators: Some(1),
        limited_files_with_indicators: Some(0),
        ..Default::default()
    };
    assert_eq!(ExitStatus::for_execution(&hit, true, false).code(), 0);
}

#[test]
fn not_analyzed_is_explicit_null_not_an_absent_contract_field() {
    let line = include_str!("fixtures/batch/files.jsonl")
        .lines()
        .nth(1)
        .unwrap();
    let mut value: Value = serde_json::from_str(line).unwrap();
    value["outcome"]["report"]["has_actionable_indicators"] = Value::Null;
    assert!(serde_json::from_value::<JournalRecord>(value.clone()).is_ok());
    value["outcome"]["report"]
        .as_object_mut()
        .unwrap()
        .remove("has_actionable_indicators");
    assert!(serde_json::from_value::<JournalRecord>(value).is_err());
    for field in ["files_with_indicators", "limited_files_with_indicators"] {
        let mut value = serde_json::to_value(Counters::default()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Counters>(value).is_err());
    }
}

fn interrupted_manifest() -> binsith::batch::Manifest {
    serde_json::from_str(include_str!("fixtures/batch/manifest-interrupted.json")).unwrap()
}

#[test]
fn manifest_fixtures_roundtrip_and_distinguish_empty_completion_from_interruption() {
    use binsith::batch::{BatchStatus, Manifest};
    for data in [
        include_str!("fixtures/batch/manifest-interrupted.json"),
        include_str!("fixtures/batch/manifest-empty.json"),
    ] {
        let value: Value = serde_json::from_str(data).unwrap();
        let manifest: Manifest = serde_json::from_value(value.clone()).unwrap();
        manifest.validate().unwrap();
        assert_eq!(serde_json::to_value(&manifest).unwrap(), value);
        let mut extended = value;
        extended["future_field"] = json!(true);
        assert_eq!(
            serde_json::from_value::<Manifest>(extended).unwrap(),
            manifest
        );
    }
    let mut manifest = interrupted_manifest();
    manifest.status = BatchStatus::Complete;
    assert!(manifest.validate().is_err());
    manifest.discovery_complete = true;
    manifest.discovery_finished_unix_ms = Some(1005);
    manifest.stop_reasons.clear();
    // Orderly completion may contain file failures or limited reports, but no cancellations.
    manifest.counters.failed += manifest.counters.cancelled;
    manifest.counters.cancelled = 0;
    manifest.validate().unwrap();
    assert_eq!(
        ExitStatus::for_execution(&manifest.counters, true, false).code(),
        1
    );
    // Wall-clock rollback is legal: elapsed_ms has its own monotonic clock.
    manifest.finished_unix_ms = Some(0);
    manifest.validate().unwrap();
}

#[test]
fn manifest_rejects_false_completion_missing_fields_and_unsafe_artifact_paths() {
    use binsith::batch::Manifest;
    let empty: Value =
        serde_json::from_str(include_str!("fixtures/batch/manifest-empty.json")).unwrap();
    for (field, replacement) in [
        ("discovery_complete", json!(false)),
        ("finished_unix_ms", Value::Null),
        ("elapsed_ms", Value::Null),
        ("discovery_started_unix_ms", Value::Null),
        ("discovery_finished_unix_ms", Value::Null),
        ("stop_reasons", json!(["internal_error"])),
    ] {
        let mut value = empty.clone();
        value[field] = replacement;
        let parsed: Manifest = serde_json::from_value(value).unwrap();
        assert!(parsed.validate().is_err(), "{field}");
    }
    for field in [
        "schema_version",
        "build",
        "configuration",
        "discovery_started_unix_ms",
        "discovery_finished_unix_ms",
        "finished_unix_ms",
        "elapsed_ms",
        "enumeration_policy",
        "counters",
        "artifacts",
        "status",
    ] {
        let mut value = empty.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<Manifest>(value).is_err(),
            "{field}"
        );
    }
    for field in ["files", "errors", "reports"] {
        let mut value = empty.clone();
        value["artifacts"][field] = json!("../outside");
        assert!(serde_json::from_value::<Manifest>(value)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut value = empty;
    value["enumeration_policy"] = json!("future_policy");
    assert!(serde_json::from_value::<Manifest>(value).is_err());
}

#[test]
fn frozen_configuration_rejects_invalid_ranges_limits_and_analysis_counters() {
    let base = interrupted_manifest();
    let mut config = base.configuration.analysis.clone();
    config.offset = u64::MAX;
    config.length = Some(1);
    assert!(config.validate().is_err());
    for threshold in [f64::NAN, f64::INFINITY, -1.0, 8.1] {
        let mut config = base.configuration.analysis.clone();
        config.entropy_threshold = threshold;
        assert!(config.validate().is_err());
    }
    for (field, replacement) in [
        ("max_string_bytes", json!(3)),
        ("min_length", json!(0)),
        ("entropy_window", json!(0)),
        ("decode_depth", json!(9)),
        ("encoding", json!("unknown")),
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        value["configuration"]["analysis"][field] = replacement;
        assert!(serde_json::from_value::<binsith::batch::Manifest>(value)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut manifest = base.clone();
    manifest.configuration.analysis.strings = false;
    assert!(manifest.validate().is_err());
    let mut manifest = base.clone();
    manifest.configuration.jobs = usize::MAX;
    assert!(manifest.validate().is_err());
    let mut manifest = base;
    manifest.configuration.patterns_sha256 = "not-a-fingerprint".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn effective_pattern_fingerprint_is_delimited_ordered_and_matches_independent_fixture() {
    use binsith::batch::pattern_fingerprint;
    assert_eq!(
        pattern_fingerprint([("URL", "https?://[^ ]+")]),
        interrupted_manifest().configuration.patterns_sha256
    );
    assert_ne!(
        pattern_fingerprint([("ab", "c")]),
        pattern_fingerprint([("a", "bc")])
    );
    assert_ne!(
        pattern_fingerprint([("a", "x"), ("b", "y")]),
        pattern_fingerprint([("b", "y"), ("a", "x")])
    );
}

#[test]
fn fixture_journal_outcomes_and_error_linkage_match_manifest() {
    use std::collections::{HashMap, HashSet};
    let manifest = interrupted_manifest();
    let mut admissions = HashMap::new();
    let mut terminal_ids = HashSet::new();
    let mut observed = Counters {
        files_with_indicators: Some(0),
        limited_files_with_indicators: Some(0),
        ..Default::default()
    };
    let error: ErrorRecord =
        serde_json::from_str(include_str!("fixtures/batch/errors.jsonl")).unwrap();
    let mut linked_errors = 0;
    for (i, line) in include_str!("fixtures/batch/files.jsonl")
        .lines()
        .enumerate()
    {
        let record: JournalRecord = serde_json::from_str(line).unwrap();
        record.validate().unwrap();
        assert_eq!(record.sequence, i as u64 + 1);
        assert_eq!(record.batch_id, manifest.batch_id);
        match &record.event {
            Event::Admission => {
                assert!(admissions
                    .insert(record.entry_id, record.path.clone())
                    .is_none());
                observed.eligible += 1;
                observed.observed_entries += 1;
            }
            Event::Terminal { outcome } => {
                assert!(
                    terminal_ids.insert(record.entry_id),
                    "duplicate terminal outcome"
                );
                if !matches!(outcome, Outcome::Skipped { .. }) {
                    assert_eq!(
                        admissions.remove(&record.entry_id).as_ref(),
                        Some(&record.path)
                    );
                }
                match outcome {
                    Outcome::Complete { report } | Outcome::Limited { report } => {
                        let hit = report
                            .has_actionable_indicators
                            .expect("frozen strings config")
                            as u64;
                        *observed.files_with_indicators.as_mut().unwrap() += hit;
                        if matches!(outcome, Outcome::Limited { .. }) {
                            observed.limited += 1;
                            *observed.limited_files_with_indicators.as_mut().unwrap() += hit;
                        } else {
                            observed.complete += 1;
                        }
                    }
                    Outcome::Failed { reason } => {
                        observed.failed += 1;
                        assert_eq!(error.entry_id, Some(record.entry_id));
                        assert_eq!(error.batch_id, record.batch_id);
                        assert_eq!(&error.code, reason);
                        linked_errors += 1;
                    }
                    Outcome::Cancelled { .. } => observed.cancelled += 1,
                    Outcome::Skipped { .. } => {
                        observed.policy_skipped += 1;
                        observed.observed_entries += 1;
                    }
                }
            }
        }
    }
    assert!(admissions.is_empty());
    assert_eq!(linked_errors, 1);
    observed.validate().unwrap();
    assert_eq!(observed, manifest.counters);
}

#[test]
fn diagnostics_reject_wrong_batch_entry_and_nonterminal_links() {
    use binsith::batch::ErrorScope;
    let records: Vec<JournalRecord> = include_str!("fixtures/batch/files.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut error: ErrorRecord =
        serde_json::from_str(include_str!("fixtures/batch/errors.jsonl")).unwrap();
    error
        .validate_link("fixture-batch", Some(&records[5]))
        .unwrap();
    assert!(error
        .validate_link("other-batch", Some(&records[5]))
        .is_err());
    assert!(error
        .validate_link("fixture-batch", Some(&records[4]))
        .is_err());
    assert!(error
        .validate_link("fixture-batch", Some(&records[1]))
        .is_err());
    assert!(error.validate_link("fixture-batch", None).is_err());
    error.code = "different_failure".into();
    assert!(error
        .validate_link("fixture-batch", Some(&records[5]))
        .is_err());
    error.scope = ErrorScope::Discovery;
    assert!(error.validate_link("fixture-batch", None).is_err());
    error.entry_id = None;
    error.validate_link("fixture-batch", None).unwrap();
}
