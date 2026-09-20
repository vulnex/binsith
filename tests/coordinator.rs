//
// VULNEX -BinSith-
//
// File: coordinator.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use binsith::batch::{
    coordinator::{Coordinator, CoordinatorCode, StopReason},
    output::{OutputClaim, PublishedReport},
    roots::resolve_roots,
    *,
};
use std::{fs, io::Write, path::Path};
fn fixture(strings: bool) -> (tempfile::TempDir, OutputClaim, Coordinator) {
    configured_fixture(strings, false)
}
fn configured_fixture(
    strings: bool,
    fail_fast: bool,
) -> (tempfile::TempDir, OutputClaim, Coordinator) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    let roots = resolve_roots(&base.join("input"), &base.join("output")).unwrap();
    let output = OutputClaim::acquire(&roots).unwrap();
    let template: Manifest =
        serde_json::from_str(include_str!("fixtures/batch/manifest-empty.json")).unwrap();
    let mut config = template.configuration;
    config.analysis.strings = strings;
    config.fail_fast = fail_fast;
    let coordinator = Coordinator::start(
        output.clone(),
        "test-batch".into(),
        template.build,
        config,
        roots.input(),
    )
    .unwrap();
    (temp, output, coordinator)
}
fn path(name: &str) -> RelativePath {
    RelativePath::from_relative(Path::new(name)).unwrap()
}
fn manifest(output: &OutputClaim) -> Manifest {
    serde_json::from_slice(&fs::read(output.root().join("manifest.json")).unwrap()).unwrap()
}
fn records(output: &OutputClaim) -> Vec<JournalRecord> {
    fs::read_to_string(output.root().join("files.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn report(output: &OutputClaim, name: &str, indicators: Option<bool>) -> (Report, PublishedReport) {
    let mut pending = output.begin_report(&path(name)).unwrap();
    pending.write_all(b"{\"complete\":true}").unwrap();
    let receipt = pending.publish(|| Ok(())).unwrap();
    (
        Report {
            report_id: receipt.report_id().into(),
            location: receipt.location().into(),
            selected_bytes: 10,
            duration_ms: 1,
            has_actionable_indicators: indicators,
        },
        receipt,
    )
}
fn error(scope: ErrorScope, id: Option<u64>, code: &str) -> ErrorRecord {
    ErrorRecord {
        schema_version: SchemaVersion,
        batch_id: "test-batch".into(),
        entry_id: id,
        scope,
        display_path: Some("sample\nname".into()),
        stage: "read".into(),
        code: code.into(),
        message: "controlled error\nwith newline".into(),
    }
}

#[test]
fn initializes_incomplete_artifacts_then_finishes_an_empty_batch() {
    let (_temp, output, mut coordinator) = fixture(false);
    let initial = manifest(&output);
    initial.validate().unwrap();
    assert_eq!(initial.status, BatchStatus::Incomplete);
    assert!(initial.discovery_started_unix_ms.is_none());
    assert_eq!(fs::read(output.root().join("files.jsonl")).unwrap(), b"");
    assert_eq!(fs::read(output.root().join("errors.jsonl")).unwrap(), b"");
    coordinator.begin_discovery().unwrap();
    coordinator.end_discovery(true).unwrap();
    assert_eq!(coordinator.finish().unwrap(), ExitStatus::Success);
    let complete = manifest(&output);
    complete.validate().unwrap();
    assert_eq!(complete.status, BatchStatus::Complete);
    assert!(complete.elapsed_ms.is_some());
    assert!(complete.finished_unix_ms.is_some());
    assert_eq!(
        coordinator.checkpoint().unwrap_err().code,
        CoordinatorCode::Closed
    );
}

#[test]
fn journals_mixed_outcomes_with_contiguous_sequences_and_committed_counters() {
    let (_temp, output, mut coordinator) = fixture(true);
    coordinator.begin_discovery().unwrap();
    let skip = coordinator
        .skip(path("directory"), "directory".into(), "subdirectory".into())
        .unwrap();
    let ids: Vec<_> = ["good", "limited", "failed"]
        .iter()
        .map(|name| coordinator.admit(path(name), name.to_string()).unwrap())
        .collect();
    for id in &ids {
        coordinator.activate(*id).unwrap();
    }
    coordinator
        .diagnostic(error(ErrorScope::Discovery, None, "permission_denied"))
        .unwrap();
    coordinator.end_discovery(true).unwrap();
    let (good, receipt) = report(&output, "good", Some(true));
    coordinator
        .terminal(
            ids[0],
            Outcome::Complete { report: good },
            None,
            Some(receipt),
        )
        .unwrap();
    let (limited, receipt) = report(&output, "limited", Some(true));
    coordinator
        .terminal(
            ids[1],
            Outcome::Limited { report: limited },
            Some(error(ErrorScope::File, Some(ids[1]), "analysis_limited")),
            Some(receipt),
        )
        .unwrap();
    coordinator
        .terminal(
            ids[2],
            Outcome::Failed {
                reason: "read_failed".into(),
            },
            Some(error(ErrorScope::File, Some(ids[2]), "read_failed")),
            None,
        )
        .unwrap();
    assert_eq!(coordinator.unresolved_count(), 0);
    assert_eq!(coordinator.finish().unwrap(), ExitStatus::ExecutionFailure);
    let state = manifest(&output);
    state.validate().unwrap();
    assert_eq!(state.status, BatchStatus::Complete);
    assert_eq!(
        (
            state.counters.observed_entries,
            state.counters.eligible,
            state.counters.policy_skipped
        ),
        (4, 3, 1)
    );
    assert_eq!(
        (
            state.counters.complete,
            state.counters.limited,
            state.counters.failed,
            state.counters.discovery_errors
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(state.counters.files_with_indicators, Some(2));
    assert_eq!(state.counters.limited_files_with_indicators, Some(1));
    let journal = records(&output);
    assert_eq!(journal.len(), 7);
    assert_eq!(journal[0].entry_id, skip);
    for (index, record) in journal.iter().enumerate() {
        record.validate().unwrap();
        assert_eq!(record.sequence, index as u64 + 1);
    }
    for id in ids {
        assert_eq!(journal.iter().filter(|r| r.entry_id == id).count(), 2);
    }
    let diagnostics: Vec<ErrorRecord> = fs::read_to_string(output.root().join("errors.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(diagnostics.len(), 3); // Embedded newlines never create extra records.
    for diagnostic in diagnostics {
        let terminal = diagnostic.entry_id.and_then(|id| {
            journal
                .iter()
                .find(|r| r.entry_id == id && matches!(r.event, Event::Terminal { .. }))
        });
        diagnostic.validate_link("test-batch", terminal).unwrap();
    }
}

#[test]
fn interruption_cancels_queued_and_active_entries_without_claiming_completion() {
    let (_temp, output, mut coordinator) = fixture(false);
    coordinator.begin_discovery().unwrap();
    let active = coordinator.admit(path("active"), "active".into()).unwrap();
    let queued = coordinator.admit(path("queued"), "queued".into()).unwrap();
    coordinator.activate(active).unwrap();
    coordinator.stop(StopReason::Interrupted).unwrap();
    coordinator.end_discovery(false).unwrap();
    for id in [active, queued] {
        coordinator
            .terminal(
                id,
                Outcome::Cancelled {
                    reason: "interrupted".into(),
                },
                None,
                None,
            )
            .unwrap();
    }
    assert_eq!(coordinator.finish().unwrap(), ExitStatus::Interrupted);
    let state = manifest(&output);
    state.validate().unwrap();
    assert_eq!(state.status, BatchStatus::Incomplete);
    assert_eq!(state.counters.cancelled, 2);
    assert_eq!(state.counters.files_with_indicators, None);
    assert!(!state.discovery_complete);
}

#[test]
fn queue_capacity_is_backpressure_without_ids_or_journal_side_effects() {
    let (_temp, output, mut coordinator) = fixture(false);
    coordinator.begin_discovery().unwrap();
    let limit = coordinator.manifest().configuration.work_queue_capacity;
    for i in 0..limit {
        coordinator
            .admit(path(&format!("file-{i}")), i.to_string())
            .unwrap();
    }
    assert_eq!(
        coordinator
            .admit(path("overflow"), "overflow".into())
            .unwrap_err()
            .code,
        CoordinatorCode::Capacity
    );
    assert_eq!(records(&output).len(), limit);
    coordinator.activate(1).unwrap();
    assert_eq!(
        coordinator.admit(path("next"), "next".into()).unwrap(),
        limit as u64 + 1
    );
    assert_eq!(coordinator.unresolved_count(), limit + 1);
    coordinator.checkpoint().unwrap();
    manifest(&output).validate().unwrap();
}

#[test]
fn unknown_duplicate_and_premature_finish_events_fail_closed() {
    for scenario in ["unknown", "duplicate", "finish"] {
        let (_temp, output, mut coordinator) = fixture(false);
        coordinator.begin_discovery().unwrap();
        let id = coordinator.admit(path("sample"), "sample".into()).unwrap();
        coordinator.activate(id).unwrap();
        let result = match scenario {
            "unknown" => coordinator.activate(999),
            "duplicate" => coordinator.activate(id),
            _ => coordinator.finish().map(|_| ()),
        };
        assert_eq!(result.unwrap_err().code, CoordinatorCode::InvalidEvent);
        assert_eq!(
            coordinator.finish().unwrap_err().code,
            CoordinatorCode::Closed
        );
        assert_eq!(manifest(&output).status, BatchStatus::Incomplete);
        assert_eq!(records(&output).len(), 1);
    }
}

#[test]
fn receipts_from_another_claim_cannot_create_successful_journal_records() {
    let (_temp, output, mut coordinator) = fixture(false);
    let (_other_temp, other_output, _other_coordinator) = fixture(false);
    coordinator.begin_discovery().unwrap();
    let id = coordinator.admit(path("sample"), "sample".into()).unwrap();
    coordinator.activate(id).unwrap();
    let (value, receipt) = report(&other_output, "sample", None);
    assert_eq!(
        coordinator
            .terminal(id, Outcome::Complete { report: value }, None, Some(receipt))
            .unwrap_err()
            .code,
        CoordinatorCode::Storage
    );
    assert_eq!(records(&output).len(), 1);
    assert_eq!(coordinator.manifest().counters.complete, 0);
}

#[test]
fn modified_journals_or_manifest_are_not_overwritten_or_marked_complete() {
    for name in ["files.jsonl", "errors.jsonl", "manifest.json"] {
        let (_temp, output, mut coordinator) = fixture(false);
        coordinator.begin_discovery().unwrap();
        coordinator.end_discovery(true).unwrap();
        let destination = output.root().join(name);
        fs::write(&destination, b"foreign or truncated data").unwrap();
        assert_eq!(
            coordinator.finish().unwrap_err().code,
            CoordinatorCode::Storage
        );
        assert_eq!(fs::read(destination).unwrap(), b"foreign or truncated data");
        if name != "manifest.json" {
            assert_eq!(manifest(&output).status, BatchStatus::Incomplete);
        }
    }
}

#[test]
fn initialization_failure_removes_only_owned_setup_journals() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    let roots = resolve_roots(&base.join("input"), &base.join("output")).unwrap();
    let output = OutputClaim::acquire(&roots).unwrap();
    fs::write(output.root().join("errors.jsonl"), b"pre-existing").unwrap();
    let template: Manifest =
        serde_json::from_str(include_str!("fixtures/batch/manifest-empty.json")).unwrap();
    assert!(Coordinator::start(
        output.clone(),
        "batch".into(),
        template.build,
        template.configuration,
        roots.input()
    )
    .is_err());
    assert!(!output.root().join("files.jsonl").exists());
    assert!(!output.root().join("manifest.json").exists());
    assert_eq!(
        fs::read(output.root().join("errors.jsonl")).unwrap(),
        b"pre-existing"
    );
}

#[test]
fn a_modified_published_report_cannot_supply_a_success_receipt() {
    let (_temp, output, mut coordinator) = fixture(false);
    coordinator.begin_discovery().unwrap();
    let id = coordinator.admit(path("sample"), "sample".into()).unwrap();
    coordinator.activate(id).unwrap();
    let (value, receipt) = report(&output, "sample", None);
    fs::write(
        output.root().join(receipt.location()),
        b"replaced report bytes",
    )
    .unwrap();
    assert_eq!(
        coordinator
            .terminal(id, Outcome::Complete { report: value }, None, Some(receipt))
            .unwrap_err()
            .code,
        CoordinatorCode::Storage
    );
    assert_eq!(records(&output).len(), 1);
    assert_eq!(coordinator.manifest().counters.complete, 0);
}

#[test]
fn batch_diagnostics_prevent_success_even_without_file_failures() {
    let (_temp, output, mut coordinator) = fixture(false);
    coordinator.begin_discovery().unwrap();
    coordinator
        .diagnostic(error(ErrorScope::Batch, None, "worker_failed"))
        .unwrap();
    coordinator.end_discovery(false).unwrap();
    assert_eq!(coordinator.finish().unwrap(), ExitStatus::ExecutionFailure);
    assert_eq!(manifest(&output).status, BatchStatus::Incomplete);
    assert!(manifest(&output)
        .stop_reasons
        .contains(&"internal_error".into()));
}

#[test]
fn fail_fast_stops_on_failure_but_not_on_limited_analysis() {
    for failed in [false, true] {
        let (_temp, output, mut coordinator) = configured_fixture(true, true);
        coordinator.begin_discovery().unwrap();
        let id = coordinator.admit(path("sample"), "sample".into()).unwrap();
        let queued = if failed {
            Some(coordinator.admit(path("queued"), "queued".into()).unwrap())
        } else {
            None
        };
        coordinator.activate(id).unwrap();
        if failed {
            coordinator
                .terminal(
                    id,
                    Outcome::Failed {
                        reason: "read_failed".into(),
                    },
                    Some(error(ErrorScope::File, Some(id), "read_failed")),
                    None,
                )
                .unwrap();
            assert!(coordinator
                .manifest()
                .stop_reasons
                .contains(&"fail_fast".into()));
            coordinator.end_discovery(false).unwrap();
            coordinator
                .terminal(
                    queued.unwrap(),
                    Outcome::Cancelled {
                        reason: "fail_fast".into(),
                    },
                    None,
                    None,
                )
                .unwrap();
        } else {
            let (value, receipt) = report(&output, "sample", Some(false));
            coordinator
                .terminal(id, Outcome::Limited { report: value }, None, Some(receipt))
                .unwrap();
            assert!(coordinator.manifest().stop_reasons.is_empty());
            coordinator.end_discovery(true).unwrap();
        }
        assert_eq!(coordinator.finish().unwrap(), ExitStatus::ExecutionFailure);
        assert_eq!(
            manifest(&output).status,
            if failed {
                BatchStatus::Incomplete
            } else {
                BatchStatus::Complete
            }
        );
    }
}
