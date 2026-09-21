//! Every scenario runs in a killable subprocess. Gates control the race windows;
//! elapsed-time sleeps only poll already observable state, never create the race.
use super::*;
use crate::batch::faults::{self, Action, Gate, Journal, Plan, Point, Step};
use std::{
    collections::HashSet,
    fs,
    path::Path,
    process::{Child, Command, Output, Stdio},
};

fn fixture(base: &Path) -> FrozenBatch {
    fs::create_dir(base.join("input")).unwrap();
    for i in 0..40 {
        fs::write(
            base.join("input").join(format!("sample-{i}")),
            b"https://example.com\0",
        )
        .unwrap();
    }
    let mut batch = preflight::storage_fixture(&base.join("input"), &base.join("output"));
    batch.test_jobs(4);
    batch
}
fn manifest(root: &Path) -> Manifest {
    serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap()
}
fn entries(root: &Path) -> Vec<JournalRecord> {
    fs::read_to_string(root.join("files.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn reports(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(shards) = fs::read_dir(root.join("results")) {
        for shard in shards {
            for file in fs::read_dir(shard.unwrap().path()).unwrap() {
                let path = file.unwrap().path();
                assert!(
                    !path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".pending-"),
                    "owned temporary survived orderly shutdown"
                );
                files.push(path);
            }
        }
    }
    for path in &files {
        let report: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(report["processing_complete"], true);
    }
    files
}
fn journal_invariants(root: &Path, settled: bool) {
    let m = manifest(root);
    m.validate().unwrap();
    let mut admitted = HashSet::new();
    let mut admitted_reports = HashSet::new();
    let mut terminal = HashSet::new();
    for (index, entry) in entries(root).iter().enumerate() {
        entry.validate().unwrap();
        assert_eq!(entry.sequence, index as u64 + 1);
        match entry.event {
            Event::Admission => {
                assert!(admitted.insert(entry.entry_id));
                admitted_reports.insert(root.join(entry.path.report_location()));
            }
            Event::Terminal { .. } => {
                assert!(admitted.contains(&entry.entry_id));
                assert!(terminal.insert(entry.entry_id));
            }
        }
    }
    if settled {
        assert_eq!(admitted, terminal);
        assert_eq!(m.counters.active + m.counters.queued, 0);
    }
    assert!(!root.join(".binsith.lock").exists());
    for report in reports(root) {
        assert!(
            admitted_reports.contains(&report),
            "published report has no admission"
        );
    }
}
fn wait_until(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(7);
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn saturated(base: &Path, scenario: &str) {
    let mut batch = fixture(base);
    if scenario.starts_with("fail_fast") || scenario == "limited" {
        batch.test_fail_fast();
    }
    if scenario.starts_with("fail_fast") {
        batch.test_offset(100);
    }
    if scenario == "limited" {
        batch.test_limited_strings();
    }
    let start = Arc::new(Gate::default());
    let coordinator = Arc::new(Gate::default());
    let attempting = Arc::new(Gate::default());
    let sent = Arc::new(Gate::default());
    let mut plan = Plan::new(Point::ScanStart, 4, Action::Gate(start.clone()))
        .and(Plan::new(
            Point::QueueSaturated,
            1,
            Action::Gate(coordinator.clone()),
        ))
        .and(Plan::new(
            Point::BeforeTerminalSend,
            4,
            Action::Observe(attempting.clone()),
        ))
        .and(Plan::new(
            Point::AfterTerminalSend,
            4,
            Action::Observe(sent.clone()),
        ))
        .with_event_capacity(1);
    match scenario {
        "journal" => {
            plan = plan.and(Plan::new(
                Point::Journal(Journal::Terminal, Step::Write),
                1,
                Action::Full,
            ))
        }
        "coordinator" => plan = plan.and(Plan::new(Point::QueueSaturated, 1, Action::Full)),
        "worker_exit" => plan = plan.and(Plan::new(Point::BeforeTerminalSend, 1, Action::Panic)),
        _ => {}
    }
    let token = CancellationToken::default();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _faults = faults::install(Some(plan));
            run(&batch, token.clone())
        });
        assert!(start.wait_for(4));
        assert!(coordinator.wait_for(1));
        // Exactly N active + 2N queued, with no terminal yet.
        assert_eq!(entries(batch.roots().output()).len(), 12);
        start.release();
        assert!(attempting.wait_for(4));
        assert!(sent.wait_for(1));
        assert_eq!(
            sent.count(),
            1,
            "coordinator is blocked; the capacity-one result queue must be full"
        );
        if matches!(scenario, "interrupt" | "fail_fast_interrupt") {
            token.cancel();
        }
        let published_before_stop: Vec<_> = reports(batch.roots().output())
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        coordinator.release();
        let result = handle.join().unwrap();
        let root = batch.roots().output();
        match scenario {
            "journal" | "coordinator" | "worker_exit" => {
                assert_eq!(result.unwrap_err().status, ExitStatus::ExecutionFailure);
                assert_eq!(manifest(root).status, BatchStatus::Incomplete);
                assert_eq!(published_before_stop.len(), 4);
                for (path, bytes) in &published_before_stop {
                    assert_eq!(
                        fs::read(path).unwrap(),
                        *bytes,
                        "published artifact changed during shutdown"
                    );
                }
                // A worker exiting outside the scan guard may still be unwinding
                // when another outcome arrives. Other publications can win that
                // observation race; they must remain valid, admitted orphans.
                if scenario != "worker_exit" {
                    assert_eq!(reports(root).len(), 4);
                }
                journal_invariants(root, false);
            }
            "interrupt" => {
                let result = result.unwrap();
                assert_eq!(result.status, ExitStatus::Interrupted);
                assert_eq!(result.counters.complete, 4);
                assert_eq!(result.counters.cancelled, 8);
                journal_invariants(root, true);
            }
            "fail_fast" | "fail_fast_interrupt" => {
                let result = result.unwrap();
                assert_eq!(
                    result.status,
                    if scenario.ends_with("interrupt") {
                        ExitStatus::Interrupted
                    } else {
                        ExitStatus::ExecutionFailure
                    }
                );
                assert_eq!(
                    result.counters.failed, 4,
                    "active scans finish under fail-fast"
                );
                assert_eq!(result.counters.cancelled, 8);
                assert!(manifest(root).stop_reasons.contains(&"fail_fast".into()));
                if scenario.ends_with("interrupt") {
                    assert!(manifest(root).stop_reasons.contains(&"interrupted".into()));
                }
                journal_invariants(root, true);
            }
            "limited" => {
                let result = result.unwrap();
                assert_eq!(result.status, ExitStatus::ExecutionFailure);
                assert_eq!(result.counters.limited, 40);
                assert_eq!(result.counters.cancelled, 0);
                assert_eq!(manifest(root).status, BatchStatus::Complete);
                assert!(manifest(root).stop_reasons.is_empty());
                journal_invariants(root, true);
            }
            _ => {
                let result = result.unwrap();
                assert_eq!(result.status, ExitStatus::Success);
                assert_eq!(result.counters.complete, 40);
                journal_invariants(root, true);
            }
        }
    });
}

fn panic_with_slow_output(base: &Path) {
    let batch = fixture(base);
    let start = Arc::new(Gate::default());
    let coordinator = Arc::new(Gate::default());
    let slow = Arc::new(Gate::default());
    let plan = Plan::new(Point::ScanStart, 4, Action::Gate(start.clone()))
        .and(Plan::new(Point::ScanStart, 1, Action::Panic))
        .and(Plan::new(
            Point::QueueSaturated,
            1,
            Action::Gate(coordinator.clone()),
        ))
        .and(Plan::new(Point::ReportWrite, 3, Action::Gate(slow.clone())))
        .with_event_capacity(1);
    let token = CancellationToken::default();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _faults = faults::install(Some(plan));
            run(&batch, token.clone())
        });
        assert!(start.wait_for(4));
        assert!(coordinator.wait_for(1));
        start.release();
        assert!(slow.wait_for(3));
        coordinator.release();
        assert!(wait_until(|| manifest(batch.roots().output())
            .stop_reasons
            .contains(&"internal_error".into())));
        slow.release();
        let result = handle.join().unwrap().unwrap();
        assert_eq!(result.status, ExitStatus::ExecutionFailure);
        assert!(!token.is_cancelled());
        assert_eq!(result.counters.cancelled, 12);
        assert_eq!(
            manifest(batch.roots().output()).status,
            BatchStatus::Incomplete
        );
        assert!(
            fs::read_to_string(batch.roots().output().join("errors.jsonl"))
                .unwrap()
                .contains("worker_panic")
        );
        journal_invariants(batch.roots().output(), true);
        assert!(reports(batch.roots().output()).is_empty());
    });
}

fn signal_child(base: &Path, scenario: &str) {
    let batch = fixture(base);
    let token = CancellationToken::default();
    let handler = crate::batch::signals::InterruptHandler::install(token.clone()).unwrap();
    let slow = Arc::new(Gate::default());
    let mut plan =
        Plan::new(Point::ReportWrite, 4, Action::Gate(slow.clone())).with_event_capacity(1);
    if scenario == "signal_journal" {
        plan = plan.and(Plan::new(
            Point::Journal(Journal::Terminal, Step::Write),
            1,
            Action::Full,
        ));
    }
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _faults = faults::install(Some(plan));
            run(&batch, token.clone())
        });
        assert!(slow.wait_for(4));
        assert!(wait_until(|| {
            let m = manifest(batch.roots().output());
            m.counters.active == 4 && m.counters.queued == 8
        }));
        fs::write(base.join("ready"), b"ready").unwrap();
        assert!(wait_until(|| handler.is_interrupted()));
        assert!(wait_until(|| manifest(batch.roots().output())
            .stop_reasons
            .contains(&"interrupted".into())));
        if scenario == "signal_second" {
            fs::write(
                base.join("first_interrupt"),
                b"first signal acknowledged while output remains blocked",
            )
            .unwrap();
            // Only the actual second signal handler can end this child. The parent
            // deadline kills a regression instead of hanging the test harness.
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
        slow.release();
        let result = handle.join().unwrap();
        if scenario == "signal_journal" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().counters.cancelled, 12);
            journal_invariants(batch.roots().output(), true);
        }
        assert_eq!(
            manifest(batch.roots().output()).status,
            BatchStatus::Incomplete
        );
        assert!(!batch.roots().output().join(".binsith.lock").exists());
        // Same exit precedence as folder_run: user interruption wins over I/O failure.
        assert!(handler.is_interrupted());
        std::process::exit(130);
    });
}

#[test]
fn stress_child() {
    let Ok(base) = std::env::var("BINSITH_SHUTDOWN_TEST_CHILD") else {
        return;
    };
    let scenario = std::env::var("BINSITH_SHUTDOWN_TEST_SCENARIO").unwrap();
    let base = Path::new(&base);
    if scenario.starts_with("signal_") {
        signal_child(base, &scenario);
    } else if scenario == "panic_slow" {
        panic_with_slow_output(base);
    } else {
        saturated(base, &scenario);
    }
}
fn spawn(base: &Path, scenario: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "batch::execution::shutdown_tests::stress_child",
            "--nocapture",
        ])
        .env("BINSITH_SHUTDOWN_TEST_CHILD", base)
        .env("BINSITH_SHUTDOWN_TEST_SCENARIO", scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
fn finish(mut child: Child, scenario: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(25);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("shutdown scenario {scenario} timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}
#[test]
fn bounded_channels_stop_and_failure_matrix_has_no_deadlocks() {
    for scenario in [
        "normal",
        "interrupt",
        "journal",
        "coordinator",
        "worker_exit",
        "fail_fast",
        "fail_fast_interrupt",
        "limited",
        "panic_slow",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let output = finish(spawn(&base, scenario), scenario);
        assert!(output.status.success(), "{scenario}: {output:?}");
    }
}
#[cfg(unix)]
#[test]
fn first_and_second_sigint_follow_cli_policy_with_blocked_output() {
    for scenario in ["signal_first", "signal_second", "signal_journal"] {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let mut child = spawn(&base, scenario);
        if !wait_until(|| base.join("ready").exists()) {
            let _ = child.kill();
            panic!(
                "{scenario}: child did not reach signal barrier: {:?}",
                child.wait_with_output().unwrap()
            );
        }
        assert!(Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success());
        if scenario == "signal_second" {
            if !wait_until(|| base.join("first_interrupt").exists()) {
                let _ = child.kill();
                panic!(
                    "first signal not acknowledged: {:?}",
                    child.wait_with_output().unwrap()
                );
            }
            assert!(Command::new("kill")
                .args(["-INT", &child.id().to_string()])
                .status()
                .unwrap()
                .success());
        }
        let output = finish(child, scenario);
        assert_eq!(output.status.code(), Some(130), "{scenario}: {output:?}");
        let root = base.join("output");
        let m = manifest(&root);
        m.validate().unwrap();
        assert_eq!(m.status, BatchStatus::Incomplete);
        assert!(m.stop_reasons.contains(&"interrupted".into()));
        assert_eq!(
            root.join(".binsith.lock").exists(),
            scenario == "signal_second"
        );
    }
}
