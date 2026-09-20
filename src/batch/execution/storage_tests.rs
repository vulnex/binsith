use super::*;
use crate::batch::faults::{self, Action, Journal, Plan, Point, Step};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn fixture(count: usize) -> (tempfile::TempDir, FrozenBatch) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    for i in 0..count {
        fs::write(
            base.join("input").join(format!("sample-{i}")),
            b"https://example.com\0",
        )
        .unwrap();
    }
    let batch = super::super::preflight::storage_fixture(&base.join("input"), &base.join("output"));
    (temp, batch)
}
fn manifest(root: &Path) -> Manifest {
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    manifest.validate().unwrap();
    manifest
}
fn files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                result.extend(files(&path));
            } else {
                result.push(path);
            }
        }
    }
    result
}
fn reports(root: &Path) -> Vec<PathBuf> {
    files(&root.join("results"))
        .into_iter()
        .filter(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        .collect()
}
fn records(root: &Path) -> Vec<JournalRecord> {
    fs::read_to_string(root.join("files.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn no_temporaries(root: &Path) {
    for path in files(root) {
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            !name.starts_with(".pending-")
                && !name.starts_with(".manifest-")
                && name != ".binsith.lock",
            "leftover {}",
            path.display()
        );
    }
}
fn status(result: Result<ExecutionResult, ExecutionError>) -> ExitStatus {
    match result {
        Ok(r) => r.status,
        Err(e) => e.status,
    }
}

#[test]
fn report_and_snapshot_storage_full_never_publish_success_and_join_cleanly() {
    for point in [
        Point::ReportCreate,
        Point::ReportWrite,
        Point::ReportPartial,
        Point::ReportFlush,
        Point::ReportPublish,
        Point::SnapshotCreate,
        Point::SnapshotWrite,
    ] {
        let (_temp, batch) = fixture(3);
        let plan = Plan::new(point, 1, Action::Full);
        let _guard = faults::install(Some(plan.clone()));
        assert_eq!(
            status(run(&batch, CancellationToken::default())),
            ExitStatus::ExecutionFailure,
            "{point:?}"
        );
        assert!(plan.fired(), "unused fault {point:?}");
        let root = batch.roots().output();
        let m = manifest(root);
        assert_eq!(m.status, BatchStatus::Incomplete);
        assert_eq!(
            m.counters.complete + m.counters.limited + m.counters.active + m.counters.queued,
            0
        );
        assert!(m.counters.cancelled >= 2);
        assert!(reports(root).is_empty());
        let errors = fs::read_to_string(root.join("errors.jsonl")).unwrap();
        assert!(errors.contains("storage full"));
        if matches!(point, Point::SnapshotCreate | Point::SnapshotWrite) {
            let diagnostic: ErrorRecord = serde_json::from_str(errors.trim()).unwrap();
            assert_eq!(diagnostic.code, "temporary_storage");
        }
        no_temporaries(root);
    }
}

#[test]
fn journal_write_torn_tail_and_flush_failures_leave_incomplete_checkpoint() {
    for kind in [Journal::Admission, Journal::Terminal, Journal::Diagnostic] {
        for step in [Step::Write, Step::Partial, Step::Flush, Step::Flushed] {
            let (_temp, mut batch) = fixture(3);
            if kind == Journal::Diagnostic {
                // A per-file range failure requires a diagnostic after its failed terminal.
                batch.test_offset(100);
            }
            let plan = Plan::new(Point::Journal(kind, step), 1, Action::Full);
            let _guard = faults::install(Some(plan.clone()));
            assert_eq!(
                status(run(&batch, CancellationToken::default())),
                ExitStatus::ExecutionFailure,
                "{kind:?}/{step:?}"
            );
            assert!(plan.fired(), "unused {kind:?}/{step:?}");
            assert_eq!(
                plan.hits(),
                1,
                "a failed journal operation must not be retried"
            );
            let root = batch.roots().output();
            assert_eq!(manifest(root).status, BatchStatus::Incomplete);
            let journal = root.join(if kind == Journal::Diagnostic {
                "errors.jsonl"
            } else {
                "files.jsonl"
            });
            let bytes = fs::read(journal).unwrap();
            if step == Step::Partial {
                assert!(!bytes.ends_with(b"\n"));
                assert!(serde_json::from_slice::<serde_json::Value>(
                    bytes.rsplit(|b| *b == b'\n').next().unwrap()
                )
                .is_err());
            } else {
                for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
                    serde_json::from_slice::<serde_json::Value>(line).unwrap();
                }
            }
            // A report can be an orphan after publication; it is never discarded
            // merely because its terminal record failed to become acknowledged.
            if kind == Journal::Terminal {
                assert_eq!(reports(root).len(), 1);
            }
            no_temporaries(root);
        }
    }
}

#[test]
fn manifest_storage_failures_preserve_previous_snapshot_and_clean_setup() {
    for point in [
        Point::ManifestCreate,
        Point::ManifestWrite,
        Point::ManifestFlush,
        Point::ManifestReplace,
    ] {
        for occurrence in [1, 2] {
            let (_temp, batch) = fixture(1);
            let plan = Plan::new(point, occurrence, Action::Full);
            let _guard = faults::install(Some(plan.clone()));
            let expected = if occurrence == 1 {
                ExitStatus::SetupFailure
            } else {
                ExitStatus::ExecutionFailure
            };
            assert_eq!(status(run(&batch, CancellationToken::default())), expected);
            assert!(plan.fired());
            let root = batch.roots().output();
            if occurrence == 1 {
                assert!(files(root).is_empty(), "setup artifacts survived {point:?}");
            } else {
                let m = manifest(root);
                assert_eq!(m.status, BatchStatus::Incomplete);
                assert_eq!(m.discovery_started_unix_ms, None);
                assert_eq!(m.counters.observed_entries, 0);
            }
            no_temporaries(root);
        }
    }
    let (_temp, batch) = fixture(1);
    let plan = Plan::new(Point::FinalManifestReplace, 1, Action::Full);
    let _guard = faults::install(Some(plan.clone()));
    assert_eq!(
        status(run(&batch, CancellationToken::default())),
        ExitStatus::ExecutionFailure
    );
    assert!(plan.fired());
    assert_eq!(
        manifest(batch.roots().output()).status,
        BatchStatus::Incomplete
    );
    assert_eq!(reports(batch.roots().output()).len(), 1);
    assert!(matches!(
        records(batch.roots().output()).last().unwrap().event,
        Event::Terminal {
            outcome: Outcome::Complete { .. }
        }
    ));
    no_temporaries(batch.roots().output());
}

#[test]
fn later_report_failure_preserves_earlier_committed_report_and_terminal() {
    let (_temp, batch) = fixture(3);
    let plan = Plan::new(Point::ReportCreate, 2, Action::Full);
    let _guard = faults::install(Some(plan.clone()));
    assert_eq!(
        status(run(&batch, CancellationToken::default())),
        ExitStatus::ExecutionFailure
    );
    assert!(plan.fired());
    let root = batch.roots().output();
    assert_eq!(manifest(root).counters.complete, 1);
    assert_eq!(reports(root).len(), 1);
    let data: serde_json::Value =
        serde_json::from_slice(&fs::read(&reports(root)[0]).unwrap()).unwrap();
    assert_eq!(data["file_summary"]["size_bytes"], 20);
    assert_eq!(
        records(root)
            .iter()
            .filter(|r| matches!(
                r.event,
                Event::Terminal {
                    outcome: Outcome::Complete { .. }
                }
            ))
            .count(),
        1
    );
    no_temporaries(root);
}

#[test]
fn publication_collision_preserves_foreign_bytes_and_stops_execution() {
    let (_temp, batch) = fixture(1);
    let relative = RelativePath::from_relative(Path::new("sample-0")).unwrap();
    let destination = batch.roots().output().join(relative.report_location());
    let plan = Plan::new(
        Point::ReportPublish,
        1,
        Action::Collision(destination.clone()),
    );
    let _guard = faults::install(Some(plan.clone()));
    assert_eq!(
        status(run(&batch, CancellationToken::default())),
        ExitStatus::ExecutionFailure
    );
    assert!(plan.fired());
    assert_eq!(
        fs::read(destination).unwrap(),
        b"foreign report: preserve these bytes"
    );
    assert_eq!(manifest(batch.roots().output()).counters.complete, 0);
    let error: ErrorRecord = serde_json::from_str(
        fs::read_to_string(batch.roots().output().join("errors.jsonl"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(error.code, "report_collision");
    assert_eq!(
        manifest(batch.roots().output()).status,
        BatchStatus::Incomplete
    );
    no_temporaries(batch.roots().output());
}

fn crash_point(name: &str) -> Point {
    match name {
        "before_publish" => Point::ReportPublish,
        "after_publish" => Point::ReportPublished,
        "after_terminal" => Point::Journal(Journal::Terminal, Step::Flushed),
        "before_complete" => Point::FinalManifestReplace,
        _ => panic!("unknown crash boundary"),
    }
}
#[test]
fn crash_child() {
    let Ok(base) = std::env::var("BINSITH_STORAGE_TEST_CHILD") else {
        return;
    };
    let base = PathBuf::from(base);
    let point = crash_point(&std::env::var("BINSITH_STORAGE_TEST_POINT").unwrap());
    let batch = super::super::preflight::storage_fixture(&base.join("input"), &base.join("output"));
    let _guard = faults::install(Some(Plan::new(point, 1, Action::Crash)));
    let _ = run(&batch, CancellationToken::default());
    panic!("crash boundary was not reached");
}
#[test]
fn process_crashes_preserve_incomplete_artifacts_and_never_reuse_output() {
    for boundary in [
        "before_publish",
        "after_publish",
        "after_terminal",
        "before_complete",
    ] {
        let (_temp, batch) = fixture(1);
        let root = batch.roots().output();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "batch::execution::storage_tests::crash_child",
                "--nocapture",
            ])
            .env("BINSITH_STORAGE_TEST_CHILD", root.parent().unwrap())
            .env("BINSITH_STORAGE_TEST_POINT", boundary)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("crash subprocess timed out: {boundary}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(99), "{boundary}: {output:?}");
        assert_eq!(manifest(root).status, BatchStatus::Incomplete);
        assert!(root.join(".binsith.lock").exists()); // No Drop cleanup ran.
        let entries = records(root);
        let terminal_count = entries
            .iter()
            .filter(|r| matches!(r.event, Event::Terminal { .. }))
            .count();
        assert_eq!(
            reports(root).len(),
            usize::from(boundary != "before_publish")
        );
        assert_eq!(
            terminal_count,
            usize::from(matches!(boundary, "after_terminal" | "before_complete"))
        );
        assert_eq!(
            files(root).iter().any(|p| p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".pending-")),
            boundary == "before_publish"
        );
        for path in reports(root) {
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(report["processing_complete"], true);
        }
        let before: Vec<_> = files(root)
            .iter()
            .map(|p| (p.clone(), fs::read(p).unwrap()))
            .collect();
        assert_eq!(
            status(run(&batch, CancellationToken::default())),
            ExitStatus::SetupFailure
        );
        for (path, bytes) in before {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}
