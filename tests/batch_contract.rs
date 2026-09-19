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
        matches!(&outcomes[0], Outcome::Complete { report } if report.has_actionable_indicators.is_none())
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
    assert!(value["outcome"]["report"]["has_actionable_indicators"].is_null());
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
