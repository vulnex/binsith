use super::*;
use crate::batch::faults::{self, Action, Gate, Plan, Point};
use std::{fs, path::Path};
fn fixture(jobs: usize, count: usize) -> (tempfile::TempDir, FrozenBatch, u64) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    let mut total = 0;
    for i in 0..count {
        let bytes = vec![i as u8; 65_536 + i];
        total += bytes.len() as u64;
        fs::write(base.join("input").join(format!("sample-{i}")), bytes).unwrap();
    }
    let mut batch = preflight::storage_fixture(&base.join("input"), &base.join("output"));
    batch.test_jobs(jobs);
    (temp, batch, total)
}
fn manifest(root: &Path) -> Manifest {
    serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap()
}
fn records(root: &Path) -> Vec<JournalRecord> {
    fs::read_to_string(root.join("files.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn workers_queue_and_discovery_are_bounded_with_lossless_terminal_delivery() {
    let (_temp, batch, total) = fixture(4, 40);
    let gate = Arc::new(Gate::default());
    let plan = Plan::new(Point::ScanStart, 4, Action::Gate(gate.clone()));
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _faults = faults::install(Some(plan));
            run(&batch, CancellationToken::default())
        });
        let concurrent = gate.wait_for(4);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut bounded = false;
        while concurrent && Instant::now() < deadline {
            let m = manifest(batch.roots().output());
            if m.counters.active == 4 && m.counters.queued == 8 {
                bounded = m.counters.observed_entries == 12 && !m.discovery_complete;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        gate.release();
        let result = handle.join().unwrap().unwrap();
        assert!(
            concurrent,
            "four actual workers did not reach the scan barrier"
        );
        assert!(bounded, "discovery must stop with N active and 2N queued");
        assert_eq!(result.status, ExitStatus::Success);
        // Hundreds of source-progress updates coalesce without adding events or
        // double-counting snapshot/entropy passes or re-used worker slots.
        assert_eq!(result.selected_bytes_read, total);
        assert_eq!(result.counters.complete, 40);
    });
    let entries = records(batch.roots().output());
    assert_eq!(entries.len(), 80);
    let mut admitted = std::collections::HashSet::new();
    let mut terminal = std::collections::HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence, index as u64 + 1);
        match &entry.event {
            Event::Admission => {
                assert!(admitted.insert(entry.entry_id));
            }
            Event::Terminal {
                outcome: Outcome::Complete { report },
            } => {
                assert!(admitted.contains(&entry.entry_id));
                assert!(terminal.insert(entry.entry_id));
                let report: serde_json::Value = serde_json::from_slice(
                    &fs::read(batch.roots().output().join(&report.location)).unwrap(),
                )
                .unwrap();
                assert_eq!(report["processing_complete"], true);
            }
            _ => panic!("unexpected outcome"),
        }
    }
    assert_eq!(admitted, terminal);
}

#[test]
fn partial_pool_startup_failure_joins_workers_before_discovery() {
    let (_temp, batch, _) = fixture(4, 20);
    let plan = Plan::new(Point::WorkerSpawn, 3, Action::Full);
    let _faults = faults::install(Some(plan.clone()));
    let result = run(&batch, CancellationToken::default()).unwrap_err();
    assert!(plan.fired());
    assert_eq!(result.status, ExitStatus::SetupFailure);
    assert!(result.message.contains("cannot start scan worker 2"));
    let m = manifest(batch.roots().output());
    assert_eq!(m.discovery_started_unix_ms, None);
    assert_eq!(m.status, BatchStatus::Incomplete);
    assert!(records(batch.roots().output()).is_empty());
    assert!(!batch.roots().output().join(".binsith.lock").exists());
}

#[test]
fn internal_pool_cancellation_does_not_mark_the_caller_interrupted() {
    let (_temp, batch, _) = fixture(4, 20);
    let plan = Plan::new(Point::ReportCreate, 1, Action::Full);
    let _faults = faults::install(Some(plan.clone()));
    let caller = CancellationToken::default();
    let result = run(&batch, caller.clone()).unwrap();
    assert!(plan.fired());
    assert_eq!(result.status, ExitStatus::ExecutionFailure);
    assert!(!caller.is_cancelled());
    let m = manifest(batch.roots().output());
    assert!(!m.stop_reasons.contains(&"interrupted".into()));
    assert_eq!(m.counters.active + m.counters.queued, 0);
    assert_eq!(m.status, BatchStatus::Incomplete);
    assert_eq!(
        records(batch.roots().output()).len() as u64,
        m.counters.eligible * 2
    );
}

#[test]
fn cancellation_children_inherit_parent_stop_without_cancelling_siblings() {
    let caller = CancellationToken::default();
    let first = caller.child();
    let second = caller.child();
    let grandchild = second.child();
    first.cancel();
    assert!(first.is_cancelled());
    assert!(!caller.is_cancelled() && !second.is_cancelled() && !grandchild.is_cancelled());
    caller.cancel();
    assert!(second.is_cancelled() && grandchild.is_cancelled());
}
