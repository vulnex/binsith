//! Read-only validation of completed batch artifacts. This establishes structural
//! consistency, not authenticity, and never opens recorded sample-input paths.
//!
//! Default bounds: 1 MiB manifest, 256 KiB journal lines, 100,000 entries,
//! 400,000 records per journal, 8 GiB imported bytes, 2 MiB sort runs and 1 GiB
//! live scratch. JSON caps are 64 levels, 256 members per object, 256-byte keys,
//! 16 MiB serialized scalars, 4 MiB decoded strings and 16 MiB accounted capture
//! per metadata/detail field. Unknown extensions remain subject to these bounds.
//! Native identities are at most 32 KiB; orphan enumeration visits at most 100,256
//! result entries. These counters are not an OS-level RSS or time guarantee.
//!
//! Imports support manifest v1/v2 and report/journal v1 within these bounds.
//! Samples are not rescanned; metadata consistency does not authenticate findings.
//! Mutable filesystems are not snapshots, and blocked I/O may delay cancellation.
//! No command-line import/export operation is exposed yet.
mod fs;
mod json;
mod report;
mod sort;

use super::{input::Snapshot, *};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, BufRead, BufReader, Read},
    path::Path,
};

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Resource(&'static str),
    Io(io::Error),
    Interrupted,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) | Self::Resource(s) => f.write_str(s),
            Self::Io(e) => write!(f, "artifact I/O: {e}"),
            Self::Interrupted => f.write_str("artifact import interrupted"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            *e.into_inner().unwrap().downcast::<Error>().unwrap()
        } else {
            Self::Io(e)
        }
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        invalid("invalid serialized artifact")
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn invalid(message: &'static str) -> Error {
    Error::Invalid(message)
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::Resource(_) | Self::Io(_) => 1,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub manifest_bytes: usize,
    pub line_bytes: usize,
    pub entries: u64,
    pub journal_records: u64,
    pub import_bytes: u64,
    pub scratch_bytes: u64,
    pub sort_buffer_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            manifest_bytes: 1024 * 1024,
            line_bytes: 256 * 1024,
            entries: 100_000,
            journal_records: 400_000,
            import_bytes: 8 * 1024 * 1024 * 1024,
            scratch_bytes: 1024 * 1024 * 1024,
            sort_buffer_bytes: 2 * 1024 * 1024,
        }
    }
}
struct Budget {
    remaining: u64,
    read: u64,
    token: crate::scanner::CancellationToken,
}
impl Budget {
    fn check(&self) -> Result<()> {
        if self.token.is_cancelled() {
            Err(Error::Interrupted)
        } else {
            Ok(())
        }
    }
}
struct Counted<'a, R> {
    inner: R,
    budget: &'a mut Budget,
}
impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.budget.check().map_err(io::Error::other)?;
        if buffer.is_empty() {
            return Ok(0);
        }
        let take = buffer.len().min(
            self.budget
                .remaining
                .saturating_add(1)
                .min(usize::MAX as u64) as usize,
        );
        let n = self.inner.read(&mut buffer[..take])?;
        if n as u64 > self.budget.remaining {
            return Err(io::Error::other(invalid(
                "total import byte limit exceeded",
            )));
        }
        self.budget.remaining -= n as u64;
        self.budget.read += n as u64;
        Ok(n)
    }
}
fn line(reader: &mut impl BufRead, cap: usize) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(invalid("torn journal tail"))
            };
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if take > cap.saturating_sub(bytes.len()) {
            return Err(invalid("journal line limit exceeded"));
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if bytes.last() == Some(&b'\n') {
            return Ok(Some(bytes));
        }
    }
}
fn path_key(path: &RelativePath) -> Result<Vec<u8>> {
    let value = serde_json::to_value(path)?;
    let encoding = value["encoding"]
        .as_str()
        .ok_or_else(|| invalid("invalid native path encoding"))?;
    let bytes = STANDARD
        .decode(
            value["value"]
                .as_str()
                .ok_or_else(|| invalid("invalid native path"))?,
        )
        .map_err(|_| invalid("invalid native path"))?;
    if bytes.len() > 32768 {
        return Err(invalid("native path byte limit exceeded"));
    }
    let mut key = encoding.as_bytes().to_vec();
    key.push(0);
    key.extend(bytes);
    Ok(key)
}
fn report_ref(record: &JournalRecord) -> Option<&Report> {
    match &record.event {
        Event::Terminal {
            outcome: Outcome::Complete { report } | Outcome::Limited { report },
        } => Some(report),
        _ => None,
    }
}
#[derive(Serialize, Deserialize)]
struct Stamp {
    location: String,
    snapshot: Snapshot,
}

/// Validated inventory lives in private, automatically removed scratch files.
/// No source mutation or network action occurs. Call verify_unchanged immediately
/// before publishing a consumer's result; metadata checks are not a filesystem snapshot.
pub struct ValidatedBatch {
    manifest: Manifest,
    root: fs::Root,
    inventory: sort::Run,
    stamps: sort::Run,
    token: crate::scanner::CancellationToken,
    imported_bytes: u64,
    scratch_high_water: u64,
    unreferenced_artifact_entries: u64,
}
impl ValidatedBatch {
    /// Entries under results/ not linked by the journal. Unexpected directories
    /// count once; their descendants are deliberately not followed or counted.
    pub fn unreferenced_artifact_entries(&self) -> u64 {
        self.unreferenced_artifact_entries
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn imported_bytes(&self) -> u64 {
        self.imported_bytes
    }
    pub fn scratch_high_water_bytes(&self) -> u64 {
        self.scratch_high_water
    }
    /// Canonical lossless path order, including skips and failures. Records have
    /// been reconciled and every referenced report has passed validation.
    pub fn visit_entries(
        &self,
        mut visitor: impl FnMut(&JournalRecord) -> Result<()>,
    ) -> Result<()> {
        let mut input = self.inventory.reader()?;
        while let Some((_, bytes)) = sort::next(&mut input)? {
            if self.token.is_cancelled() {
                return Err(Error::Interrupted);
            }
            visitor(&serde_json::from_slice(&bytes)?)?;
        }
        Ok(())
    }
    pub fn verify_unchanged(&self) -> Result<()> {
        self.root.check()?;
        self.root.unclaimed()?;
        let mut input = self.stamps.reader()?;
        while let Some((_, bytes)) = sort::next(&mut input)? {
            if self.token.is_cancelled() {
                return Err(Error::Interrupted);
            }
            let stamp: Stamp = serde_json::from_slice(&bytes)?;
            self.root.verify(&stamp.location, &stamp.snapshot)?;
        }
        Ok(())
    }
}

/// Limits are explicit for embedding/tests; no CLI exists until export is ready.
pub fn read(
    root: &Path,
    limits: Limits,
    token: crate::scanner::CancellationToken,
) -> Result<ValidatedBatch> {
    let mut budget = Budget {
        remaining: limits.import_bytes,
        read: 0,
        token: token.clone(),
    };
    read_inner(root, limits, &mut budget)
}
fn read_inner(path: &Path, limits: Limits, budget: &mut Budget) -> Result<ValidatedBatch> {
    budget.check()?;
    if limits.manifest_bytes == 0
        || limits.manifest_bytes > 1024 * 1024
        || limits.line_bytes == 0
        || limits.line_bytes > 256 * 1024
        || limits.sort_buffer_bytes == 0
        || limits.sort_buffer_bytes > 2 * 1024 * 1024
        || limits.entries > 100_000
        || limits.journal_records > 400_000
    {
        return Err(invalid("unsupported reader limits"));
    }
    let root = fs::Root::open(path)?;
    root.unclaimed()?;
    let scratch = sort::Scratch::new(limits.scratch_bytes).with_cancellation(budget.token.clone());
    let sorter = || sort::Sort::new(scratch.clone(), limits.sort_buffer_bytes);
    let mut stamps = sorter();
    let opened = root.open_file("manifest.json")?;
    let mut bytes = Vec::new();
    Counted {
        inner: &opened.file,
        budget,
    }
    .take(limits.manifest_bytes as u64 + 1)
    .read_to_end(&mut bytes)?;
    if bytes.len() > limits.manifest_bytes {
        return Err(invalid("manifest byte limit exceeded"));
    }
    let manifest: Manifest = json::document(&bytes)?;
    manifest.validate().map_err(invalid)?;
    if manifest.status != BatchStatus::Complete {
        return Err(invalid("incomplete batch is not importable"));
    }
    if manifest.counters.observed_entries > limits.entries {
        return Err(invalid("batch entry limit exceeded"));
    }
    opened.verify()?;
    stamps.push(
        b"manifest.json".to_vec(),
        serde_json::to_vec(&Stamp {
            location: "manifest.json".into(),
            snapshot: opened.before,
        })?,
    )?;
    let mut events = sorter();
    let opened = root.open_file("files.jsonl")?;
    let mut lines = BufReader::new(Counted {
        inner: &opened.file,
        budget,
    });
    let mut sequence = 0_u64;
    let mut native_encoding = manifest
        .selection
        .as_ref()
        .map(|s| match s.native_encoding {
            selection::NativeEncoding::Unix => b"unix-bytes-base64".to_vec(),
            selection::NativeEncoding::Windows => b"windows-utf16le-base64".to_vec(),
        });
    while let Some(bytes) = line(&mut lines, limits.line_bytes)? {
        let record: JournalRecord = json::document(&bytes)?;
        record.validate().map_err(invalid)?;
        sequence += 1;
        if sequence > limits.journal_records
            || record.sequence != sequence
            || record.batch_id != manifest.batch_id
            || record.entry_id > limits.entries
        {
            return Err(invalid("invalid journal sequence, batch or entry limit"));
        }
        let native_key = path_key(&record.path)?;
        let encoding = native_key.split(|b| *b == 0).next().unwrap();
        if native_encoding
            .as_ref()
            .is_some_and(|expected| expected != encoding)
        {
            return Err(invalid("mixed or mismatched native path encodings"));
        }
        native_encoding.get_or_insert_with(|| encoding.to_vec());
        let mut key = record.entry_id.to_be_bytes().to_vec();
        key.extend(record.sequence.to_be_bytes());
        events.push(key, serde_json::to_vec(&record)?)?;
    }
    drop(lines);
    opened.verify()?;
    stamps.push(
        b"files.jsonl".to_vec(),
        serde_json::to_vec(&Stamp {
            location: "files.jsonl".into(),
            snapshot: opened.before,
        })?,
    )?;
    let events = events.finish()?;
    let mut diagnostics = sorter();
    let opened = root.open_file("errors.jsonl")?;
    let mut lines = BufReader::new(Counted {
        inner: &opened.file,
        budget,
    });
    let mut diagnostic_count = 0_u64;
    let mut discovery_errors = 0;
    while let Some(bytes) = line(&mut lines, limits.line_bytes)? {
        diagnostic_count += 1;
        if diagnostic_count > limits.journal_records {
            return Err(invalid("diagnostic record limit exceeded"));
        }
        let diagnostic: ErrorRecord = json::document(&bytes)?;
        if diagnostic.batch_id != manifest.batch_id {
            return Err(invalid("diagnostic batch mismatch"));
        }
        if diagnostic.scope == ErrorScope::Discovery || diagnostic.scope == ErrorScope::Batch {
            diagnostic
                .validate_link(&manifest.batch_id, None)
                .map_err(invalid)?;
            if diagnostic.scope == ErrorScope::Batch {
                return Err(invalid("completed batch has a fatal batch diagnostic"));
            }
            discovery_errors += 1;
        } else {
            let id = diagnostic
                .entry_id
                .ok_or_else(|| invalid("file diagnostic has no entry ID"))?;
            diagnostics.push(id.to_be_bytes().to_vec(), serde_json::to_vec(&diagnostic)?)?;
        }
    }
    drop(lines);
    opened.verify()?;
    stamps.push(
        b"errors.jsonl".to_vec(),
        serde_json::to_vec(&Stamp {
            location: "errors.jsonl".into(),
            snapshot: opened.before,
        })?,
    )?;
    let diagnostics = diagnostics.finish()?;
    let mut errors = diagnostics.reader()?;
    let mut error = sort::next(&mut errors)?;
    let mut input = events.reader()?;
    let mut next = sort::next(&mut input)?;
    let mut counts = Counters {
        discovery_errors,
        files_with_indicators: manifest.configuration.analysis.strings.then_some(0),
        limited_files_with_indicators: manifest.configuration.analysis.strings.then_some(0),
        ..Default::default()
    };
    let mut inventory = sorter();
    let mut expected_id = 1_u64;
    while let Some((_, bytes)) = next.take() {
        budget.check()?;
        let first: JournalRecord = serde_json::from_slice(&bytes)?;
        if first.entry_id != expected_id {
            return Err(invalid("duplicate or gapped journal entry ID"));
        }
        expected_id += 1;
        let terminal = if matches!(first.event, Event::Admission) {
            let (_, bytes) =
                sort::next(&mut input)?.ok_or_else(|| invalid("admission lacks terminal"))?;
            let terminal: JournalRecord = serde_json::from_slice(&bytes)?;
            if terminal.entry_id != first.entry_id
                || terminal.path != first.path
                || terminal.display_path != first.display_path
                || matches!(
                    terminal.event,
                    Event::Admission
                        | Event::Terminal {
                            outcome: Outcome::Skipped { .. }
                        }
                )
            {
                return Err(invalid("admission/terminal mismatch"));
            }
            counts.eligible += 1;
            terminal
        } else {
            if !matches!(
                first.event,
                Event::Terminal {
                    outcome: Outcome::Skipped { .. }
                }
            ) {
                return Err(invalid("terminal lacks admission"));
            }
            first
        };
        let Event::Terminal { outcome } = &terminal.event else {
            return Err(invalid("missing terminal"));
        };
        counts.observed_entries += 1;
        match outcome {
            Outcome::Skipped { .. } => counts.policy_skipped += 1,
            Outcome::Failed { .. } => counts.failed += 1,
            Outcome::Complete { report } | Outcome::Limited { report } => {
                let limited = matches!(outcome, Outcome::Limited { .. });
                if limited {
                    counts.limited += 1;
                } else {
                    counts.complete += 1;
                }
                if let Some(all) = &mut counts.files_with_indicators {
                    let hit = report
                        .has_actionable_indicators
                        .ok_or_else(|| invalid("missing indicator analysis state"))?;
                    *all += u64::from(hit);
                    if limited {
                        *counts.limited_files_with_indicators.as_mut().unwrap() += u64::from(hit);
                    }
                } else if report.has_actionable_indicators.is_some() {
                    return Err(invalid("unexpected indicator analysis state"));
                }
            }
            Outcome::Cancelled { .. } => {
                return Err(invalid("completed batch contains cancelled work"))
            }
        }
        let mut linked = 0_u64;
        while let Some((key, bytes)) = &error {
            if key.as_slice() > terminal.entry_id.to_be_bytes().as_slice() {
                break;
            }
            let diagnostic: ErrorRecord = serde_json::from_slice(bytes)?;
            if diagnostic
                .display_path
                .as_ref()
                .is_some_and(|path| path != &terminal.display_path)
            {
                return Err(invalid("diagnostic path disagrees with terminal"));
            }
            diagnostic
                .validate_link(&manifest.batch_id, Some(&terminal))
                .map_err(invalid)?;
            linked += 1;
            error = sort::next(&mut errors)?;
        }
        if matches!(outcome, Outcome::Failed { .. }) && linked == 0 {
            return Err(invalid("failed entry lacks diagnostic"));
        }
        inventory.push(path_key(&terminal.path)?, serde_json::to_vec(&terminal)?)?;
        next = sort::next(&mut input)?;
    }
    if error.is_some() {
        return Err(invalid("diagnostic references unknown entry"));
    }
    if counts != manifest.counters {
        return Err(invalid("manifest/journal counters disagree"));
    }
    let inventory = inventory.finish()?;
    drop(input);
    drop(errors);
    drop(events);
    drop(diagnostics);
    let mut aliases = sorter();
    let mut input = inventory.reader()?;
    let mut previous = None;
    while let Some((key, bytes)) = sort::next(&mut input)? {
        budget.check()?;
        if previous.as_ref() == Some(&key) {
            return Err(invalid("duplicate native entry path"));
        }
        previous = Some(key);
        let record: JournalRecord = serde_json::from_slice(&bytes)?;
        if let Some(report) = report_ref(&record) {
            let opened = root.open_file(&report.location)?;
            report::validate(
                BufReader::new(Counted {
                    inner: &opened.file,
                    budget,
                }),
                &manifest,
                &record,
            )?;
            opened.verify()?;
            aliases.push(opened.before.identity_key(), Vec::new())?;
            stamps.push(
                report.location.as_bytes().to_vec(),
                serde_json::to_vec(&Stamp {
                    location: report.location.clone(),
                    snapshot: opened.before,
                })?,
            )?;
        }
    }
    let aliases = aliases.finish()?;
    let mut input = aliases.reader()?;
    let mut previous = None;
    while let Some((key, _)) = sort::next(&mut input)? {
        if previous.as_ref() == Some(&key) {
            return Err(invalid("multiple reports alias the same file"));
        }
        previous = Some(key);
    }
    let stamps = stamps.finish()?;
    let mut discovered = sorter();
    let mut unknown = 0_u64;
    let mut enumerated = 0_u64;
    if root.directory_exists("results")? {
        root.names("results", |shard| {
            budget.check()?;
            enumerated += 1;
            if enumerated > 100256 {
                return Err(invalid("artifact enumeration limit exceeded"));
            }
            if let Some(shard) = shard.to_str().filter(|s| {
                s.len() == 2
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }) {
                root.names(&format!("results/{shard}"), |name| {
                    budget.check()?;
                    enumerated += 1;
                    if enumerated > 100256 {
                        return Err(invalid("artifact enumeration limit exceeded"));
                    }
                    if let Some(name) = name.to_str() {
                        discovered
                            .push(format!("results/{shard}/{name}").into_bytes(), Vec::new())?;
                    } else {
                        unknown += 1;
                    }
                    Ok(())
                })?;
            } else {
                unknown += 1;
            }
            Ok(())
        })?;
    }
    let discovered = discovered.finish()?;
    let mut actual = discovered.reader()?;
    let mut expected = stamps.reader()?;
    let mut wanted = sort::next(&mut expected)?;
    while let Some((path, _)) = sort::next(&mut actual)? {
        while wanted.as_ref().is_some_and(|(key, _)| key < &path) {
            wanted = sort::next(&mut expected)?;
        }
        if wanted.as_ref().is_none_or(|(key, _)| key != &path) {
            unknown += 1;
        }
    }
    let validated = ValidatedBatch {
        manifest,
        root,
        inventory,
        stamps,
        token: budget.token.clone(),
        imported_bytes: budget.read,
        scratch_high_water: scratch.high_water(),
        unreferenced_artifact_entries: unknown,
    };
    validated.verify_unchanged()?;
    Ok(validated)
}
