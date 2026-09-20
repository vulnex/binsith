//! Bounded worker execution. The coordinator owns discovery, journals and stop state;
//! the worker owns only its checked input, scan state and temporary report.
use super::{
    cli::ProgressMode,
    coordinator::{Coordinator, StopReason},
    discovery::{Discovery, DiscoveryEvent},
    input::Candidate,
    output::{OutputClaim, OutputStage, PublishedReport},
    preflight::FrozenBatch,
    *,
};
use crate::scanner::{self, CancellationToken, ScanErrorKind, ScanRequest};
use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct ExecutionError {
    pub status: ExitStatus,
    pub message: String,
}
#[derive(Debug)]
pub struct ExecutionResult {
    pub status: ExitStatus,
    pub counters: Counters,
    /// Source bytes consumed, including partial scans; extra analysis passes are excluded.
    pub selected_bytes_read: u64,
}
impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ExecutionError {}
struct Work {
    id: u64,
    candidate: Candidate,
}
enum ScanResult {
    Report(Outcome, PublishedReport),
    Failed(&'static str, String),
    Cancelled,
    Fatal(&'static str, String),
}
fn output_failure(error: super::output::OutputError) -> ScanResult {
    let code = match error.code {
        super::output::OutputCode::Collision => "report_collision",
        super::output::OutputCode::UnsafePath => "output_changed",
        _ => "report_io",
    };
    ScanResult::Fatal(code, error.to_string())
}
fn scan(
    candidate: &Candidate,
    batch: &FrozenBatch,
    output: &OutputClaim,
    token: &CancellationToken,
    patterns: &[(String, regex::Regex)],
    progress: &AtomicU64,
) -> ScanResult {
    let started = Instant::now();
    #[cfg(test)]
    if let Err(error) = super::faults::hit(super::faults::Point::ScanStart) {
        return ScanResult::Fatal("internal_error", error.to_string());
    }
    if token.is_cancelled() {
        return ScanResult::Cancelled;
    }
    let mut input = match candidate.open() {
        Ok(input) => input,
        Err(e) => {
            return ScanResult::Failed(
                if e.to_string() == "file_changed" {
                    "file_changed"
                } else {
                    "input_open"
                },
                e.to_string(),
            )
        }
    };
    let config = &batch.configuration().analysis;
    let reader = match input.selected(config.offset, config.length) {
        Ok(reader) => reader,
        Err(e) => return ScanResult::Failed("input_range", e.to_string()),
    };
    let path = match candidate.record_path() {
        Ok(path) => path,
        Err(e) => return ScanResult::Fatal("internal_error", e.into()),
    };
    let mut report = match output.begin_report(&path) {
        Ok(report) => report,
        Err(e) => return output_failure(e),
    };
    let display = candidate.relative_path().to_string_lossy();
    let metadata = serde_json::json!({
        "tool": "binsith", "version": env!("CARGO_PKG_VERSION"),
        "revision": env!("BINSITH_REVISION"), "source_sha256": env!("BINSITH_SOURCE_SHA256"),
        "target": env!("BINSITH_TARGET"), "profile": env!("BINSITH_PROFILE"),
        "rustc": env!("BINSITH_RUSTC"), "configuration": config,
        "strings_enabled": config.strings, "effective_encoding": config.encoding,
        "decoding_enabled": config.strings && !config.no_decode && config.max_decode_bytes > 0 && config.decode_depth > 0,
        "patterns_sha256": batch.configuration().patterns_sha256,
        "patterns_hash_format": "SHA256 of compact JSON array of sorted [name, expression] pairs after category filtering"
    });
    let request = ScanRequest {
        display_path: &display,
        configuration: config,
        patterns,
        metadata: &metadata,
    };
    let outcome = match scanner::scan_selected(reader, &mut report, &request, token, |bytes| {
        progress.store(bytes, Ordering::Relaxed);
    }) {
        Ok(outcome) => outcome,
        Err(e) => {
            return match e.kind {
                ScanErrorKind::Cancelled => ScanResult::Cancelled,
                ScanErrorKind::Read => ScanResult::Failed("input_read", e.to_string()),
                kind => ScanResult::Fatal(
                    match kind {
                        ScanErrorKind::TemporaryStorage => "temporary_storage",
                        ScanErrorKind::Report => "report_io",
                        ScanErrorKind::Analysis => "analysis_error",
                        _ => "internal_error",
                    },
                    format!("{kind:?}: {e}"),
                ),
            }
        }
    };
    let publication = match report.publish(|| {
        if token.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        input.verify_unchanged()
    }) {
        Ok(publication) => publication,
        Err(e) if e.stage == OutputStage::ValidateInput => {
            return if token.is_cancelled() {
                ScanResult::Cancelled
            } else {
                ScanResult::Failed("file_changed", e.to_string())
            }
        }
        Err(e) => return output_failure(e),
    };
    let report = Report {
        report_id: publication.report_id().into(),
        location: publication.location().into(),
        selected_bytes: outcome.summary.size_bytes,
        duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        has_actionable_indicators: outcome.has_actionable_indicators,
    };
    ScanResult::Report(
        if outcome.coverage.limited() {
            Outcome::Limited { report }
        } else {
            Outcome::Complete { report }
        },
        publication,
    )
}
fn diagnostic(
    batch_id: &str,
    id: Option<u64>,
    scope: ErrorScope,
    display: Option<String>,
    stage: &str,
    code: &str,
    message: String,
) -> ErrorRecord {
    ErrorRecord {
        schema_version: SchemaVersion,
        batch_id: batch_id.into(),
        entry_id: id,
        scope,
        display_path: display,
        stage: stage.into(),
        code: code.into(),
        message,
    }
}

/// The caller may cancel from another thread (the CLI uses its first Ctrl+C).
/// All return paths cancel and join all workers before releasing output ownership.
pub fn run(
    batch: &FrozenBatch,
    cancellation: CancellationToken,
) -> Result<ExecutionResult, ExecutionError> {
    let setup = |e: String| ExecutionError {
        status: ExitStatus::SetupFailure,
        message: e,
    };
    let jobs = batch.configuration().jobs;
    if jobs == 0 || jobs.checked_mul(2) != Some(batch.configuration().work_queue_capacity) {
        return Err(setup("invalid worker count or queue capacity".into()));
    }
    let output = OutputClaim::acquire(batch.roots()).map_err(|e| setup(e.to_string()))?;
    let batch_id = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let build = BuildIdentity {
        version: env!("CARGO_PKG_VERSION").into(),
        revision: env!("BINSITH_REVISION").into(),
        source_sha256: env!("BINSITH_SOURCE_SHA256").into(),
        target: env!("BINSITH_TARGET").into(),
        profile: env!("BINSITH_PROFILE").into(),
    };
    let mut coordinator = Coordinator::start(
        output.clone(),
        batch_id.clone(),
        build,
        batch.configuration().clone(),
        batch.roots().input(),
    )
    .map_err(|e| setup(e.to_string()))?;
    std::thread::scope(|scope| {
        // Terminal events are lossless and bounded independently from byte progress.
        // Cap allocation even if an excessive --jobs request fails during thread creation.
        let (results, events) = mpsc::sync_channel(jobs.min(64));
        let worker_cancellation = cancellation.child();
        let mut sends = Vec::new();
        let mut workers = Vec::new();
        let mut progress_slots = Vec::new();
        for worker_id in 0..jobs {
            let (send, receive) = mpsc::sync_channel::<Work>(1);
            let results = results.clone();
            let output = output.clone();
            let token = worker_cancellation.clone();
            let progress = Arc::new(AtomicU64::new(0));
            progress_slots.push(progress.clone());
            #[cfg(test)]
            let faults = super::faults::current();
            let spawn = || {
                #[cfg(test)]
                super::faults::hit(super::faults::Point::WorkerSpawn)?;
                std::thread::Builder::new()
                    .name(format!("binsith-scan-{worker_id}"))
                    .spawn_scoped(scope, move || {
                        #[cfg(test)]
                        let _faults = super::faults::install(faults);
                        // Clones share compiled expressions but give each worker its own
                        // regex search handles. See the recorded FS-14 measurement.
                        let patterns = batch.patterns().to_vec();
                        while let Ok(work) = receive.recv() {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    scan(
                                        &work.candidate,
                                        batch,
                                        &output,
                                        &token,
                                        &patterns,
                                        &progress,
                                    )
                                }))
                                .unwrap_or_else(|_| {
                                    ScanResult::Fatal("worker_panic", "scan worker panicked".into())
                                });
                            if results
                                .send((
                                    worker_id,
                                    work.id,
                                    work.candidate
                                        .relative_path()
                                        .to_string_lossy()
                                        .into_owned(),
                                    result,
                                ))
                                .is_err()
                            {
                                break;
                            }
                        }
                    })
            };
            match spawn() {
                Ok(worker) => {
                    sends.push(send);
                    workers.push(worker);
                }
                Err(error) => {
                    worker_cancellation.cancel();
                    drop(sends);
                    drop(events);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(setup(format!(
                        "cannot start scan worker {worker_id}: {error}"
                    )));
                }
            }
        }
        drop(results);
        let mut selected_bytes_read = 0_u64;
        let execution = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut discovery = Discovery::new(
                batch.roots(),
                batch.configuration().recursive,
                cancellation.clone(),
            )?;
            coordinator.begin_discovery()?;
            let mut queue = VecDeque::new();
            let mut active = vec![None; jobs];
            let mut ended = false;
            let mut progress = Instant::now();
            loop {
                if cancellation.is_cancelled()
                    && !coordinator
                        .manifest()
                        .stop_reasons
                        .iter()
                        .any(|r| r == "interrupted")
                {
                    coordinator.stop(StopReason::Interrupted)?;
                }
                let stopping = !coordinator.manifest().stop_reasons.is_empty();
                if stopping {
                    if !ended {
                        discovery.stop();
                        coordinator.end_discovery(false)?;
                        ended = true;
                    }
                    while let Some(Work { id, .. }) = queue.pop_front() {
                        coordinator.terminal(
                            id,
                            Outcome::Cancelled {
                                reason: "batch_stopped".into(),
                            },
                            None,
                            None,
                        )?;
                    }
                }
                if !stopping && !ended && queue.len() < batch.configuration().work_queue_capacity {
                    let event = discovery.next();
                    // Filesystem lookups may block; do not admit their result after an interrupt.
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    match event {
                        Some(DiscoveryEvent::File(candidate)) => {
                            // Check again after a potentially blocking filesystem lookup.
                            if cancellation.is_cancelled() {
                                continue;
                            }
                            let id = coordinator.admit(
                                candidate.record_path()?,
                                candidate.relative_path().to_string_lossy().into_owned(),
                            )?;
                            queue.push_back(Work { id, candidate });
                        }
                        Some(DiscoveryEvent::Skipped { relative, reason }) => {
                            let reason = match reason {
                                discovery::SkipReason::Subdirectory => "subdirectory",
                                discovery::SkipReason::Link => "link",
                                discovery::SkipReason::SpecialFile => "special_file",
                                discovery::SkipReason::OutputTree => "output_tree",
                            };
                            coordinator.skip(
                                RelativePath::from_relative(&relative)?,
                                relative.to_string_lossy().into_owned(),
                                reason.into(),
                            )?;
                        }
                        Some(DiscoveryEvent::Error {
                            relative,
                            error,
                            fatal,
                        }) => {
                            coordinator.diagnostic(diagnostic(
                                &batch_id,
                                None,
                                ErrorScope::Discovery,
                                Some(relative.to_string_lossy().into_owned()),
                                "discovery",
                                "discovery_error",
                                error.to_string(),
                            ))?;
                            if fatal {
                                coordinator.stop(StopReason::DiscoveryStopped)?;
                            }
                        }
                        None => {
                            coordinator.end_discovery(discovery.discovery_complete())?;
                            ended = true;
                        }
                    }
                    // Fill the bounded queue before dispatching the first scan.
                    if active.iter().all(Option::is_none)
                        && !ended
                        && queue.len() < batch.configuration().work_queue_capacity
                    {
                        continue;
                    }
                }
                if coordinator.manifest().stop_reasons.is_empty() && !cancellation.is_cancelled() {
                    for (worker, slot) in active.iter_mut().enumerate() {
                        if slot.is_none() {
                            if let Some(work) = queue.pop_front() {
                                coordinator.activate(work.id)?;
                                *slot = Some(work.id);
                                progress_slots[worker].store(0, Ordering::Relaxed);
                                sends[worker].send(work)?;
                            }
                        }
                    }
                }
                if active.iter().any(Option::is_some) {
                    let wait = if !ended && queue.len() < batch.configuration().work_queue_capacity
                    {
                        Duration::ZERO
                    } else {
                        Duration::from_millis(50)
                    };
                    match events.recv_timeout(wait) {
                        Ok((worker, id, display, result)) => {
                            if active.get(worker).copied().flatten() != Some(id) {
                                return Err("unexpected worker entry".into());
                            }
                            selected_bytes_read = selected_bytes_read
                                .saturating_add(progress_slots[worker].swap(0, Ordering::Relaxed));
                            // Preserve publication wins, but record interruption before cancelled outcomes.
                            if cancellation.is_cancelled() {
                                coordinator.stop(StopReason::Interrupted)?;
                            }
                            match result {
                                ScanResult::Report(outcome, publication) => {
                                    coordinator.terminal(id, outcome, None, Some(publication))?
                                }
                                ScanResult::Failed(code, message) => {
                                    let error = diagnostic(
                                        &batch_id,
                                        Some(id),
                                        ErrorScope::File,
                                        Some(display),
                                        "scan",
                                        code,
                                        message,
                                    );
                                    coordinator.terminal(
                                        id,
                                        Outcome::Failed {
                                            reason: code.into(),
                                        },
                                        Some(error),
                                        None,
                                    )?;
                                }
                                ScanResult::Cancelled => coordinator.terminal(
                                    id,
                                    Outcome::Cancelled {
                                        reason: "batch_stopped".into(),
                                    },
                                    None,
                                    None,
                                )?,
                                ScanResult::Fatal(code, message) => {
                                    worker_cancellation.cancel();
                                    eprintln!("binsith: fatal batch error: {message:?}");
                                    coordinator.diagnostic(diagnostic(
                                        &batch_id,
                                        None,
                                        ErrorScope::Batch,
                                        None,
                                        "scan",
                                        code,
                                        message,
                                    ))?;
                                    coordinator.terminal(
                                        id,
                                        Outcome::Cancelled {
                                            reason: code.into(),
                                        },
                                        None,
                                        None,
                                    )?;
                                }
                            }
                            active[worker] = None;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if workers.iter().any(|worker| worker.is_finished()) {
                    return Err("scan worker terminated unexpectedly".into());
                }
                coordinator.checkpoint_if_due()?;
                if batch.folder().progress != ProgressMode::Disabled
                    && progress.elapsed() >= Duration::from_secs(1)
                {
                    let c = &coordinator.manifest().counters;
                    eprintln!(
                        "Batch: {} active, {} queued, {} complete, {} limited, {} failed; {} selected bytes read",
                        c.active, c.queued, c.complete, c.limited, c.failed,
                        progress_slots.iter().fold(selected_bytes_read, |total, slot| total.saturating_add(slot.load(Ordering::Relaxed)))
                    );
                    progress = Instant::now();
                }
                if ended && active.iter().all(Option::is_none) && queue.is_empty() {
                    // Check stop state once more before the final completion checkpoint.
                    if cancellation.is_cancelled() {
                        coordinator.stop(StopReason::Interrupted)?;
                    }
                    return Ok(());
                }
            }
        })();
        if execution.is_err() {
            worker_cancellation.cancel();
        }
        drop(sends);
        drop(events); // Unblock a result send even when journal writes failed.
        let panicked = workers
            .into_iter()
            .map(|worker| worker.join().is_err())
            .fold(false, |any, failed| any | failed);
        let execution = if panicked {
            Err("scan worker panicked".into())
        } else {
            execution
        };
        let execution = execution.and_then(|()| {
            // Completion is published only after the scan workers have actually joined.
            if cancellation.is_cancelled() {
                coordinator.stop(StopReason::Interrupted)?;
            }
            let status = coordinator.finish()?;
            Ok(ExecutionResult {
                status,
                counters: coordinator.manifest().counters.clone(),
                selected_bytes_read,
            })
        });
        execution.map_err(|e| {
            // Best effort only: a poisoned/unusable journal must never be retried.
            let _ = coordinator.diagnostic(diagnostic(
                &batch_id,
                None,
                ErrorScope::Batch,
                None,
                "execution",
                "internal_error",
                e.to_string(),
            ));
            ExecutionError {
                status: ExitStatus::ExecutionFailure,
                message: e.to_string(),
            }
        })
    })
}

#[cfg(test)]
mod storage_tests;

#[cfg(test)]
mod regex_bench;

#[cfg(test)]
mod pool_tests;
