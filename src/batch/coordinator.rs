//
// VULNEX -BinSith-
//
// File: batch/coordinator.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::{
    output::{OutputClaim, OwnedJournal, PublishedFile, PublishedReport},
    *,
};
use std::{
    collections::HashMap,
    fmt, io,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Every successful journal operation includes its flush. Implementations must
/// not report success for a partial record. A failed call is never retried here.
pub trait JournalStore {
    fn initialize(&mut self, manifest: &Manifest) -> io::Result<()>;
    fn append_file(&mut self, record: &JournalRecord) -> io::Result<()>;
    fn append_error(&mut self, error: &ErrorRecord) -> io::Result<()>;
    fn checkpoint(&mut self, manifest: &Manifest) -> io::Result<()>;
    fn verify_publication(&mut self, receipt: &PublishedReport) -> io::Result<()>;
}

pub struct DiskStore {
    output: OutputClaim,
    files: Option<OwnedJournal>,
    errors: Option<OwnedJournal>,
    manifest: Option<PublishedFile>,
}
impl DiskStore {
    pub fn new(output: OutputClaim) -> Self {
        Self {
            output,
            files: None,
            errors: None,
            manifest: None,
        }
    }
}
impl JournalStore for DiskStore {
    fn initialize(&mut self, manifest: &Manifest) -> io::Result<()> {
        if self.files.is_some() || self.errors.is_some() || self.manifest.is_some() {
            return Err(io::Error::other("store already initialized"));
        }
        // Locals remove only owned setup journals if a subsequent step fails.
        let mut files = self.output.create_journal(false)?;
        let mut errors = self.output.create_journal(true)?;
        let identity = self.output.write_manifest(manifest, None)?;
        files.retain();
        errors.retain();
        self.files = Some(files);
        self.errors = Some(errors);
        self.manifest = Some(identity);
        Ok(())
    }
    fn append_file(&mut self, record: &JournalRecord) -> io::Result<()> {
        self.files
            .as_mut()
            .ok_or_else(|| io::Error::other("store not initialized"))?
            .append(record)
    }
    fn append_error(&mut self, error: &ErrorRecord) -> io::Result<()> {
        self.errors
            .as_mut()
            .ok_or_else(|| io::Error::other("store not initialized"))?
            .append(error)
    }
    fn checkpoint(&mut self, manifest: &Manifest) -> io::Result<()> {
        self.files
            .as_ref()
            .ok_or_else(|| io::Error::other("store not initialized"))?
            .verify()?;
        self.errors
            .as_ref()
            .ok_or_else(|| io::Error::other("store not initialized"))?
            .verify()?;
        let previous = self
            .manifest
            .as_ref()
            .ok_or_else(|| io::Error::other("store not initialized"))?;
        self.manifest = Some(self.output.write_manifest(manifest, Some(previous))?);
        Ok(())
    }
    fn verify_publication(&mut self, receipt: &PublishedReport) -> io::Result<()> {
        receipt.verify_owner(&self.output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorCode {
    InvalidEvent,
    Capacity,
    Storage,
    Closed,
}
#[derive(Debug)]
pub struct CoordinatorError {
    pub code: CoordinatorCode,
    pub stage: &'static str,
    message: String,
}
impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}/{}: {}", self.code, self.stage, self.message)
    }
}
impl std::error::Error for CoordinatorError {}
type Result<T> = std::result::Result<T, CoordinatorError>;

#[derive(Clone, Copy, Debug)]
pub enum StopReason {
    Interrupted,
    FailFast,
    InternalError,
    DiscoveryStopped,
}
impl StopReason {
    fn label(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::FailFast => "fail_fast",
            Self::InternalError => "internal_error",
            Self::DiscoveryStopped => "discovery_stopped",
        }
    }
}
#[derive(Clone)]
struct Entry {
    path: RelativePath,
    display: String,
    active: bool,
}

/// Single-writer state machine. Memory tracks at most queue_capacity + jobs
/// unresolved entries. Completed paths/findings/outcomes are never retained.
pub struct Coordinator<S: JournalStore = DiskStore> {
    store: S,
    manifest: Manifest,
    checkpointed_counters: Counters,
    pending: HashMap<u64, Entry>,
    next_id: u64,
    next_sequence: u64,
    clock: Instant,
    last_checkpoint: Instant,
    poisoned: bool,
    closed: bool,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn increment(value: &mut u64) -> std::result::Result<(), &'static str> {
    *value = value.checked_add(1).ok_or("counter overflow")?;
    Ok(())
}

impl Coordinator<DiskStore> {
    pub fn start(
        output: OutputClaim,
        batch_id: String,
        build: BuildIdentity,
        configuration: BatchConfiguration,
        input_root: &Path,
    ) -> Result<Self> {
        let counters = Counters {
            files_with_indicators: configuration.analysis.strings.then_some(0),
            limited_files_with_indicators: configuration.analysis.strings.then_some(0),
            ..Default::default()
        };
        let manifest = Manifest {
            schema_version: SchemaVersion,
            batch_id,
            build,
            configuration,
            input_root_display: input_root.to_string_lossy().into_owned(),
            output_root_display: output.root().to_string_lossy().into_owned(),
            enumeration_policy: EnumerationPolicy::ObservedEntriesV1,
            started_unix_ms: now(),
            discovery_started_unix_ms: None,
            discovery_finished_unix_ms: None,
            finished_unix_ms: None,
            elapsed_ms: None,
            discovery_complete: false,
            status: BatchStatus::Incomplete,
            stop_reasons: vec![],
            counters,
            artifacts: ArtifactLocations::default(),
        };
        Self::with_store(DiskStore::new(output), manifest)
    }
}
impl<S: JournalStore> Coordinator<S> {
    /// Only pristine manifests are accepted; resuming or replaying a journal is
    /// deliberately outside this API. The store seam supports deterministic faults.
    pub fn with_store(mut store: S, manifest: Manifest) -> Result<Self> {
        let empty = Counters {
            files_with_indicators: manifest.configuration.analysis.strings.then_some(0),
            limited_files_with_indicators: manifest.configuration.analysis.strings.then_some(0),
            ..Default::default()
        };
        if manifest.validate().is_err()
            || manifest.counters != empty
            || manifest.status != BatchStatus::Incomplete
            || manifest.discovery_started_unix_ms.is_some()
            || manifest.discovery_finished_unix_ms.is_some()
            || manifest.finished_unix_ms.is_some()
            || manifest.elapsed_ms.is_some()
            || manifest.discovery_complete
            || !manifest.stop_reasons.is_empty()
        {
            return Err(CoordinatorError {
                code: CoordinatorCode::InvalidEvent,
                stage: "initialize",
                message: "expected pristine valid manifest".into(),
            });
        }
        store.initialize(&manifest).map_err(|e| CoordinatorError {
            code: CoordinatorCode::Storage,
            stage: "initialize",
            message: e.to_string(),
        })?;
        let checkpointed_counters = manifest.counters.clone();
        Ok(Self {
            store,
            manifest,
            checkpointed_counters,
            pending: HashMap::new(),
            next_id: 1,
            next_sequence: 1,
            clock: Instant::now(),
            last_checkpoint: Instant::now(),
            poisoned: false,
            closed: false,
        })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn unresolved_count(&self) -> usize {
        self.pending.len()
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned || self.closed {
            return Err(CoordinatorError {
                code: CoordinatorCode::Closed,
                stage: "state",
                message: "coordinator is closed or failed".into(),
            });
        }
        Ok(())
    }
    fn reason(&mut self, reason: &str) {
        if !self.manifest.stop_reasons.iter().any(|s| s == reason) {
            self.manifest.stop_reasons.push(reason.into());
        }
    }
    fn invalid<T>(&mut self, message: impl Into<String>) -> Result<T> {
        self.poisoned = true;
        self.reason("internal_error");
        Err(CoordinatorError {
            code: CoordinatorCode::InvalidEvent,
            stage: "state",
            message: message.into(),
        })
    }
    fn storage(
        &mut self,
        stage: &'static str,
        action: impl FnOnce(&mut S) -> io::Result<()>,
    ) -> Result<()> {
        if let Err(error) = action(&mut self.store) {
            self.poisoned = true;
            self.reason("output_failed");
            return Err(CoordinatorError {
                code: CoordinatorCode::Storage,
                stage,
                message: error.to_string(),
            });
        }
        Ok(())
    }
    fn discovering(&mut self) -> Result<()> {
        self.ready()?;
        if self.manifest.discovery_started_unix_ms.is_none()
            || self.manifest.discovery_finished_unix_ms.is_some()
            || !self.manifest.stop_reasons.is_empty()
        {
            return self.invalid("admission/discovery event outside active discovery");
        }
        Ok(())
    }
    pub fn checkpoint(&mut self) -> Result<()> {
        self.ready()?;
        let snapshot = self.manifest.clone();
        if let Err(error) = snapshot.validate() {
            return self.invalid(error);
        }
        self.storage("checkpoint", |store| store.checkpoint(&snapshot))?;
        self.checkpointed_counters = snapshot.counters;
        self.last_checkpoint = Instant::now();
        Ok(())
    }
    /// Call from the coordinator event loop as well as on events, so idle workers
    /// do not prevent a periodic checkpoint. The default interval is one second.
    /// Only counters change between mandatory lifecycle checkpoints; rewriting an
    /// identical manifest on idle ticks adds storage work without fresher state.
    pub fn checkpoint_if_due(&mut self) -> Result<bool> {
        self.ready()?;
        if self.manifest.counters != self.checkpointed_counters
            && self.last_checkpoint.elapsed() >= Duration::from_secs(1)
        {
            self.checkpoint()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub fn begin_discovery(&mut self) -> Result<()> {
        self.ready()?;
        if self.manifest.discovery_started_unix_ms.is_some()
            || !self.manifest.stop_reasons.is_empty()
        {
            return self.invalid("discovery already started or stopped");
        }
        self.manifest.discovery_started_unix_ms = Some(now());
        self.checkpoint()
    }
    pub fn end_discovery(&mut self, complete: bool) -> Result<()> {
        self.ready()?;
        if self.manifest.discovery_started_unix_ms.is_none()
            || self.manifest.discovery_finished_unix_ms.is_some()
        {
            return self.invalid("invalid discovery completion");
        }
        self.manifest.discovery_finished_unix_ms = Some(now());
        self.manifest.discovery_complete = complete;
        if !complete {
            self.reason(StopReason::DiscoveryStopped.label());
        }
        self.checkpoint()
    }
    pub fn stop(&mut self, reason: StopReason) -> Result<()> {
        self.ready()?;
        self.reason(reason.label());
        self.checkpoint()
    }
    fn reserve(&mut self) -> Result<(u64, u64)> {
        match (
            self.next_id.checked_add(1),
            self.next_sequence.checked_add(1),
        ) {
            (Some(id), Some(sequence)) => Ok((id, sequence)),
            _ => self.invalid("journal identifier overflow"),
        }
    }
    pub fn admit(&mut self, path: RelativePath, display: String) -> Result<u64> {
        self.discovering()?;
        if self.manifest.counters.queued >= self.manifest.configuration.work_queue_capacity as u64 {
            return Err(CoordinatorError {
                code: CoordinatorCode::Capacity,
                stage: "admit",
                message: "work queue is full".into(),
            });
        }
        let (next_id, next_sequence) = self.reserve()?;
        let mut counters = self.manifest.counters.clone();
        for value in [
            &mut counters.observed_entries,
            &mut counters.eligible,
            &mut counters.queued,
        ] {
            if let Err(error) = increment(value) {
                return self.invalid(error);
            }
        }
        let id = self.next_id;
        let record = JournalRecord {
            schema_version: SchemaVersion,
            batch_id: self.manifest.batch_id.clone(),
            sequence: self.next_sequence,
            entry_id: id,
            path: path.clone(),
            display_path: display.clone(),
            event: Event::Admission,
        };
        self.storage("admission", |store| store.append_file(&record))?;
        self.manifest.counters = counters;
        self.next_id = next_id;
        self.next_sequence = next_sequence;
        self.pending.insert(
            id,
            Entry {
                path,
                display,
                active: false,
            },
        );
        self.checkpoint_if_due()?;
        Ok(id)
    }
    pub fn activate(&mut self, id: u64) -> Result<()> {
        self.ready()?;
        if !self.manifest.stop_reasons.is_empty() {
            return self.invalid("cannot activate after stop");
        }
        let Some(entry) = self.pending.get(&id) else {
            return self.invalid("unknown admission");
        };
        if entry.active {
            return self.invalid("admission already active");
        }
        if self.manifest.counters.active >= self.manifest.configuration.jobs as u64 {
            return Err(CoordinatorError {
                code: CoordinatorCode::Capacity,
                stage: "activate",
                message: "worker capacity reached".into(),
            });
        }
        self.pending.get_mut(&id).unwrap().active = true;
        self.manifest.counters.queued -= 1;
        self.manifest.counters.active += 1;
        self.checkpoint_if_due()?;
        Ok(())
    }
    pub fn skip(&mut self, path: RelativePath, display: String, reason: String) -> Result<u64> {
        self.discovering()?;
        let (next_id, next_sequence) = self.reserve()?;
        let id = self.next_id;
        let record = JournalRecord {
            schema_version: SchemaVersion,
            batch_id: self.manifest.batch_id.clone(),
            sequence: self.next_sequence,
            entry_id: id,
            path,
            display_path: display,
            event: Event::Terminal {
                outcome: Outcome::Skipped { reason },
            },
        };
        if let Err(error) = record.validate() {
            return self.invalid(error);
        }
        let mut counters = self.manifest.counters.clone();
        for value in [&mut counters.observed_entries, &mut counters.policy_skipped] {
            if let Err(error) = increment(value) {
                return self.invalid(error);
            }
        }
        self.storage("skip", |store| store.append_file(&record))?;
        self.manifest.counters = counters;
        self.next_id = next_id;
        self.next_sequence = next_sequence;
        self.checkpoint_if_due()?;
        Ok(id)
    }
    pub fn terminal(
        &mut self,
        id: u64,
        outcome: Outcome,
        diagnostic: Option<ErrorRecord>,
        publication: Option<PublishedReport>,
    ) -> Result<()> {
        self.ready()?;
        let Some(entry) = self.pending.get(&id).cloned() else {
            return self.invalid("unknown or already terminal admission");
        };
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return self.invalid("journal sequence overflow");
        };
        let record = JournalRecord {
            schema_version: SchemaVersion,
            batch_id: self.manifest.batch_id.clone(),
            sequence: self.next_sequence,
            entry_id: id,
            path: entry.path,
            display_path: entry.display,
            event: Event::Terminal {
                outcome: outcome.clone(),
            },
        };
        if let Err(error) = record.validate() {
            return self.invalid(error);
        }
        if let Some(error) = &diagnostic {
            if let Err(message) = error.validate_link(&self.manifest.batch_id, Some(&record)) {
                return self.invalid(message);
            }
        }
        let mut counters = self.manifest.counters.clone();
        if entry.active {
            counters.active -= 1;
        } else {
            counters.queued -= 1;
        }
        let terminal_count = match &outcome {
            Outcome::Complete { report } | Outcome::Limited { report } => {
                if !entry.active
                    || report.has_actionable_indicators.is_some()
                        != self.manifest.configuration.analysis.strings
                {
                    return self.invalid("report state or indicator semantics disagree");
                }
                let Some(receipt) = &publication else {
                    return self.invalid("successful outcome requires publication receipt");
                };
                if receipt.report_id != report.report_id || receipt.location != report.location {
                    return self.invalid("publication receipt does not match outcome");
                }
                self.storage("publication", |store| store.verify_publication(receipt))?;
                if report.has_actionable_indicators == Some(true) {
                    if let Err(error) = increment(counters.files_with_indicators.as_mut().unwrap())
                    {
                        return self.invalid(error);
                    }
                    if matches!(outcome, Outcome::Limited { .. }) {
                        if let Err(error) =
                            increment(counters.limited_files_with_indicators.as_mut().unwrap())
                        {
                            return self.invalid(error);
                        }
                    }
                }
                if matches!(outcome, Outcome::Limited { .. }) {
                    &mut counters.limited
                } else {
                    &mut counters.complete
                }
            }
            Outcome::Failed { .. } => {
                if !entry.active || publication.is_some() || diagnostic.is_none() {
                    return self.invalid("failed outcome requires active entry and linked diagnostic, without publication");
                }
                &mut counters.failed
            }
            Outcome::Cancelled { .. } => {
                if publication.is_some() || self.manifest.stop_reasons.is_empty() {
                    return self.invalid("cancellation requires stop state and no report");
                }
                &mut counters.cancelled
            }
            Outcome::Skipped { .. } => {
                return self.invalid("eligible admission cannot become a policy skip")
            }
        };
        if let Err(error) = increment(terminal_count) {
            return self.invalid(error);
        }
        if let Err(error) = counters.validate() {
            return self.invalid(error);
        }
        self.storage("terminal", |store| store.append_file(&record))?;
        if let Some(error) = &diagnostic {
            self.storage("diagnostic", |store| store.append_error(error))?;
        }
        self.manifest.counters = counters;
        self.next_sequence = next_sequence;
        self.pending.remove(&id);
        if self.manifest.configuration.fail_fast && matches!(outcome, Outcome::Failed { .. }) {
            self.reason(StopReason::FailFast.label());
            self.checkpoint()?;
        } else {
            self.checkpoint_if_due()?;
        }
        Ok(())
    }
    pub fn diagnostic(&mut self, error: ErrorRecord) -> Result<()> {
        self.ready()?;
        if let Err(message) = error.validate_link(&self.manifest.batch_id, None) {
            return self.invalid(message);
        }
        let mut counters = self.manifest.counters.clone();
        if error.scope == ErrorScope::Discovery {
            self.discovering()?;
            if let Err(error) = increment(&mut counters.discovery_errors) {
                return self.invalid(error);
            }
        }
        self.storage("diagnostic", |store| store.append_error(&error))?;
        self.manifest.counters = counters;
        if error.scope == ErrorScope::Batch {
            self.reason(StopReason::InternalError.label());
            self.checkpoint()?;
        } else if self.manifest.configuration.fail_fast {
            self.reason(StopReason::FailFast.label());
            self.checkpoint()?;
        } else {
            self.checkpoint_if_due()?;
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<ExitStatus> {
        self.ready()?;
        if !self.pending.is_empty()
            || (!self.manifest.discovery_complete && self.manifest.stop_reasons.is_empty())
        {
            return self
                .invalid("cannot finish with unresolved admissions or unfinished discovery");
        }
        let mut final_manifest = self.manifest.clone();
        final_manifest.finished_unix_ms = Some(now());
        final_manifest.elapsed_ms =
            Some(self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        if final_manifest.discovery_complete && final_manifest.stop_reasons.is_empty() {
            final_manifest.status = BatchStatus::Complete;
        }
        if let Err(error) = final_manifest.validate() {
            return self.invalid(error);
        }
        self.storage("finish", |store| store.checkpoint(&final_manifest))?;
        self.manifest = final_manifest;
        self.closed = true;
        Ok(ExitStatus::for_execution(
            &self.manifest.counters,
            self.manifest.status == BatchStatus::Complete,
            self.manifest
                .stop_reasons
                .iter()
                .any(|s| s == "interrupted"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs, rc::Rc};
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        AdmissionBefore,
        AdmissionAfter,
        TerminalBefore,
        TerminalAfter,
        DiagnosticAfter,
        Checkpoint,
    }
    struct FaultStore {
        disk: DiskStore,
        fault: Rc<Cell<Option<Fault>>>,
    }
    impl FaultStore {
        fn take(&self, fault: Fault) -> bool {
            if self.fault.get() == Some(fault) {
                self.fault.set(None);
                true
            } else {
                false
            }
        }
    }
    fn failure() -> io::Error {
        io::Error::other("injected storage failure")
    }
    impl JournalStore for FaultStore {
        fn initialize(&mut self, manifest: &Manifest) -> io::Result<()> {
            self.disk.initialize(manifest)
        }
        fn append_file(&mut self, record: &JournalRecord) -> io::Result<()> {
            let (before, after) = if matches!(record.event, Event::Admission) {
                (Fault::AdmissionBefore, Fault::AdmissionAfter)
            } else {
                (Fault::TerminalBefore, Fault::TerminalAfter)
            };
            if self.take(before) {
                return Err(failure());
            }
            self.disk.append_file(record)?;
            // Simulates a late flush/verification error after bytes reached disk.
            if self.take(after) {
                return Err(failure());
            }
            Ok(())
        }
        fn append_error(&mut self, error: &ErrorRecord) -> io::Result<()> {
            self.disk.append_error(error)?;
            if self.take(Fault::DiagnosticAfter) {
                return Err(failure());
            }
            Ok(())
        }
        fn checkpoint(&mut self, manifest: &Manifest) -> io::Result<()> {
            if self.take(Fault::Checkpoint) {
                return Err(failure());
            }
            self.disk.checkpoint(manifest)
        }
        fn verify_publication(&mut self, receipt: &PublishedReport) -> io::Result<()> {
            self.disk.verify_publication(receipt)
        }
    }
    fn fixture() -> (
        tempfile::TempDir,
        OutputClaim,
        Coordinator<FaultStore>,
        Rc<Cell<Option<Fault>>>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir(base.join("input")).unwrap();
        let roots = roots::resolve_roots(&base.join("input"), &base.join("output")).unwrap();
        let output = OutputClaim::acquire(&roots).unwrap();
        let mut manifest: Manifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/batch/manifest-empty.json"
        ))
        .unwrap();
        manifest.status = BatchStatus::Incomplete;
        manifest.discovery_complete = false;
        manifest.discovery_started_unix_ms = None;
        manifest.discovery_finished_unix_ms = None;
        manifest.finished_unix_ms = None;
        manifest.elapsed_ms = None;
        manifest.input_root_display = roots.input().to_string_lossy().into_owned();
        manifest.output_root_display = output.root().to_string_lossy().into_owned();
        let fault = Rc::new(Cell::new(None));
        let coordinator = Coordinator::with_store(
            FaultStore {
                disk: DiskStore::new(output.clone()),
                fault: fault.clone(),
            },
            manifest,
        )
        .unwrap();
        (temp, output, coordinator, fault)
    }
    fn path() -> RelativePath {
        RelativePath::from_relative(Path::new("sample")).unwrap()
    }
    fn diagnostic(id: u64) -> ErrorRecord {
        ErrorRecord {
            schema_version: SchemaVersion,
            batch_id: "empty-batch".into(),
            entry_id: Some(id),
            scope: ErrorScope::File,
            display_path: Some("sample".into()),
            stage: "read".into(),
            code: "read_failed".into(),
            message: "read failed".into(),
        }
    }
    fn line_count(output: &OutputClaim) -> usize {
        fs::read_to_string(output.root().join("files.jsonl"))
            .unwrap()
            .lines()
            .count()
    }
    fn assert_incomplete(output: &OutputClaim) {
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(output.root().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.status, BatchStatus::Incomplete);
    }

    #[test]
    fn admission_failure_never_acknowledges_or_retries_even_after_bytes_were_written() {
        for fault_kind in [Fault::AdmissionBefore, Fault::AdmissionAfter] {
            let (_temp, output, mut coordinator, fault) = fixture();
            coordinator.begin_discovery().unwrap();
            fault.set(Some(fault_kind));
            assert_eq!(
                coordinator.admit(path(), "sample".into()).unwrap_err().code,
                CoordinatorCode::Storage
            );
            assert_eq!(coordinator.manifest().counters.eligible, 0);
            assert_eq!(coordinator.unresolved_count(), 0);
            assert_eq!(
                line_count(&output),
                usize::from(fault_kind == Fault::AdmissionAfter)
            );
            assert_eq!(
                coordinator.admit(path(), "sample".into()).unwrap_err().code,
                CoordinatorCode::Closed
            );
            assert_incomplete(&output);
        }
    }

    #[test]
    fn terminal_and_diagnostic_failures_do_not_advance_counters_or_allow_completion() {
        for fault_kind in [
            Fault::TerminalBefore,
            Fault::TerminalAfter,
            Fault::DiagnosticAfter,
        ] {
            let (_temp, output, mut coordinator, fault) = fixture();
            coordinator.begin_discovery().unwrap();
            let id = coordinator.admit(path(), "sample".into()).unwrap();
            coordinator.activate(id).unwrap();
            coordinator.end_discovery(true).unwrap();
            fault.set(Some(fault_kind));
            assert_eq!(
                coordinator
                    .terminal(
                        id,
                        Outcome::Failed {
                            reason: "read_failed".into()
                        },
                        Some(diagnostic(id)),
                        None
                    )
                    .unwrap_err()
                    .code,
                CoordinatorCode::Storage
            );
            assert_eq!(coordinator.manifest().counters.failed, 0);
            assert_eq!(coordinator.manifest().counters.active, 1);
            assert_eq!(coordinator.unresolved_count(), 1);
            assert_eq!(
                line_count(&output),
                if fault_kind == Fault::TerminalBefore {
                    1
                } else {
                    2
                }
            );
            assert_eq!(
                coordinator.finish().unwrap_err().code,
                CoordinatorCode::Closed
            );
            assert_incomplete(&output);
        }
    }

    #[test]
    fn final_checkpoint_failure_preserves_previous_incomplete_snapshot() {
        let (_temp, output, mut coordinator, fault) = fixture();
        coordinator.begin_discovery().unwrap();
        coordinator.end_discovery(true).unwrap();
        let before = fs::read(output.root().join("manifest.json")).unwrap();
        fault.set(Some(Fault::Checkpoint));
        assert_eq!(
            coordinator.finish().unwrap_err().code,
            CoordinatorCode::Storage
        );
        assert_eq!(
            fs::read(output.root().join("manifest.json")).unwrap(),
            before
        );
        assert_eq!(coordinator.manifest().status, BatchStatus::Incomplete);
    }

    #[test]
    fn duplicate_terminals_and_wrong_diagnostic_links_are_fatal_without_new_records() {
        for duplicate in [false, true] {
            let (_temp, output, mut coordinator, _fault) = fixture();
            coordinator.begin_discovery().unwrap();
            let id = coordinator.admit(path(), "sample".into()).unwrap();
            coordinator.activate(id).unwrap();
            if duplicate {
                coordinator
                    .terminal(
                        id,
                        Outcome::Failed {
                            reason: "read_failed".into(),
                        },
                        Some(diagnostic(id)),
                        None,
                    )
                    .unwrap();
            }
            let bad_id = if duplicate { id } else { id + 1 };
            assert_eq!(
                coordinator
                    .terminal(
                        id,
                        Outcome::Failed {
                            reason: "read_failed".into()
                        },
                        Some(diagnostic(bad_id)),
                        None
                    )
                    .unwrap_err()
                    .code,
                CoordinatorCode::InvalidEvent
            );
            assert_eq!(line_count(&output), if duplicate { 2 } else { 1 });
            assert_eq!(
                coordinator.finish().unwrap_err().code,
                CoordinatorCode::Closed
            );
        }
    }

    #[test]
    fn identifier_overflow_and_missing_publication_never_write_terminal_success() {
        for overflow in [false, true] {
            let (_temp, output, mut coordinator, _fault) = fixture();
            coordinator.begin_discovery().unwrap();
            if overflow {
                coordinator.next_sequence = u64::MAX;
                assert_eq!(
                    coordinator.admit(path(), "sample".into()).unwrap_err().code,
                    CoordinatorCode::InvalidEvent
                );
                assert_eq!(line_count(&output), 0);
            } else {
                let id = coordinator.admit(path(), "sample".into()).unwrap();
                coordinator.activate(id).unwrap();
                let report = Report {
                    report_id: path().report_id(),
                    location: path().report_location(),
                    selected_bytes: 0,
                    duration_ms: 0,
                    has_actionable_indicators: None,
                };
                assert_eq!(
                    coordinator
                        .terminal(id, Outcome::Complete { report }, None, None)
                        .unwrap_err()
                        .code,
                    CoordinatorCode::InvalidEvent
                );
                assert_eq!(line_count(&output), 1);
            }
            assert_incomplete(&output);
        }
    }
    #[test]
    fn checkpoints_replace_manifest_while_readers_hold_previous_snapshots() {
        use std::io::Read;

        let (_temp, output, mut coordinator, _fault) = fixture();
        let path = output.root().join("manifest.json");
        let original = fs::read(&path).unwrap();
        let mut reader = fs::File::open(&path).unwrap();
        coordinator.begin_discovery().unwrap();
        let current = fs::read(&path).unwrap();
        assert_ne!(current, original);
        let mut second_reader = fs::File::open(&path).unwrap();
        coordinator.checkpoint().unwrap();
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        retained.clear();
        second_reader.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, current);
        assert_eq!(fs::read(&path).unwrap(), current);
    }

    #[test]
    fn due_checkpoints_record_live_state_without_sleeping() {
        let (_temp, output, mut coordinator, _fault) = fixture();
        coordinator.begin_discovery().unwrap();
        let id = coordinator.admit(path(), "sample".into()).unwrap();
        coordinator.activate(id).unwrap();
        coordinator.last_checkpoint = Instant::now() - Duration::from_secs(2);
        assert!(coordinator.checkpoint_if_due().unwrap());
        let saved: Manifest =
            serde_json::from_slice(&fs::read(output.root().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(saved.counters.active, 1);
        assert_eq!(saved.status, BatchStatus::Incomplete);
        saved.validate().unwrap();
    }

    #[test]
    fn idle_timer_does_not_hide_explicit_checkpoint_failure() {
        let (_temp, _output, mut coordinator, fault) = fixture();
        coordinator.begin_discovery().unwrap();
        coordinator.last_checkpoint = Instant::now() - Duration::from_secs(2);
        fault.set(Some(Fault::Checkpoint));
        assert!(!coordinator.checkpoint_if_due().unwrap());
        assert!(matches!(fault.get(), Some(Fault::Checkpoint)));
        assert!(coordinator.checkpoint().is_err());
        assert!(fault.get().is_none());
        assert!(coordinator.checkpoint_if_due().is_err());
    }

    #[test]
    fn due_checkpoints_skip_unchanged_state_but_record_new_counters() {
        let (_temp, output, mut coordinator, _fault) = fixture();
        coordinator.begin_discovery().unwrap();
        let id = coordinator.admit(path(), "sample".into()).unwrap();
        coordinator.activate(id).unwrap();
        coordinator.last_checkpoint = Instant::now() - Duration::from_secs(2);
        assert!(coordinator.checkpoint_if_due().unwrap());
        let previous = fs::read(output.root().join("manifest.json")).unwrap();
        coordinator.last_checkpoint = Instant::now() - Duration::from_secs(2);
        assert!(!coordinator.checkpoint_if_due().unwrap());
        assert_eq!(
            fs::read(output.root().join("manifest.json")).unwrap(),
            previous
        );
        // A new admission must still be checkpointed immediately when due.
        coordinator.admit(path(), "next".into()).unwrap();
        let saved: Manifest =
            serde_json::from_slice(&fs::read(output.root().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(saved.counters.queued, 1);
        assert_eq!(saved.counters.active, 1);
        saved.validate().unwrap();
    }
}
