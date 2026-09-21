//
// VULNEX -BinSith-
//
// File: batch/output.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

#[cfg(test)]
use super::faults::{self, Journal, Point, Step};
use super::{
    input::{open_checked, Snapshot},
    roots::{directory_path, is_link, resolve_roots, ResolvedRoots},
    RelativePath,
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tempfile::NamedTempFile;

const CLAIM_FILE: &str = ".binsith.lock";

// Coalesce serde's small writes without retaining a whole (potentially large)
// record. Always finish the buffer before the caller's commit boundary, and
// discard it on error so Drop cannot retry a failed or partial write.
fn write_json_line(output: impl Write, value: &impl serde::Serialize) -> io::Result<()> {
    let mut buffered = io::BufWriter::with_capacity(8192, output);
    let result = (|| {
        serde_json::to_writer(&mut buffered, value)?;
        buffered.write_all(b"\n")?;
        buffered.flush()
    })();
    let _ = buffered.into_parts();
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStage {
    Claim,
    Prepare,
    Write,
    Flush,
    ValidateInput,
    Publish,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputCode {
    Io,
    UnsafePath,
    BusyOrNonempty,
    Collision,
}
#[derive(Debug)]
pub struct OutputError {
    pub stage: OutputStage,
    pub code: OutputCode,
    source: io::Error,
}
impl OutputError {
    fn io(stage: OutputStage, source: io::Error) -> Self {
        Self {
            stage,
            code: OutputCode::Io,
            source,
        }
    }
    pub fn io_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}
impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}/{:?}: {}", self.stage, self.code, self.source)
    }
}
impl Error for OutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
fn unsafe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "output path identity or type changed",
    )
}

fn private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn ensure_root(path: &Path) -> io::Result<()> {
    // Validate/create each prefix, never create_dir_all through unchecked links.
    let ancestors: Vec<_> = path.ancestors().collect();
    for component in ancestors.into_iter().rev() {
        match fs::symlink_metadata(component) {
            Ok(metadata) if !metadata.is_dir() || is_link(&metadata) => return Err(unsafe_path()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match private_directory(component) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(component)?;
                        if !metadata.is_dir() || is_link(&metadata) {
                            return Err(unsafe_path());
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn directory_snapshot(path: &Path) -> io::Result<Snapshot> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_link(&metadata) {
        return Err(unsafe_path());
    }
    Snapshot::observed(path, &metadata)
}
fn check_directory(path: &Path, expected: &Snapshot) -> io::Result<()> {
    if !directory_snapshot(path)?.same_identity(expected) {
        return Err(unsafe_path());
    }
    Ok(())
}
fn remove_empty_owned(path: &Path, expected: &Snapshot) {
    if check_directory(path, expected).is_ok() {
        let _ = fs::remove_dir(path);
    }
}

struct Claim {
    root: PathBuf,
    _root_guard: File,
    root_identity: Snapshot,
    lock: Option<File>,
    lock_identity: Snapshot,
    results: Option<Snapshot>,
    // Bounded by the 256 possible two-hex-digit shards, not report count.
    shards: Mutex<BTreeMap<String, Snapshot>>,
}
impl Claim {
    fn verify(&self) -> io::Result<()> {
        directory_path(&self.root, false)?;
        check_directory(&self.root, &self.root_identity)?;
        let lock_path = self.root.join(CLAIM_FILE);
        let metadata = fs::symlink_metadata(&lock_path)?;
        if is_link(&metadata)
            || !metadata.is_file()
            || !Snapshot::observed(&lock_path, &metadata)?.same_identity(&self.lock_identity)
        {
            return Err(unsafe_path());
        }
        if let Some(results) = &self.results {
            check_directory(&self.root.join("results"), results)?;
        }
        Ok(())
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        // A replaced root/claim is no longer ours. Preserve everything on doubt.
        if self.verify().is_err() {
            return;
        }
        let shards = self
            .shards
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        for (name, identity) in shards {
            remove_empty_owned(&self.root.join("results").join(name), identity);
        }
        if let Some(identity) = &self.results {
            remove_empty_owned(&self.root.join("results"), identity);
        }
        // Close our lock handle first so removal also works on Windows.
        self.lock.take();
        let _ = fs::remove_file(self.root.join(CLAIM_FILE));
        // Keep root/created parent directories, even when empty. No recursive deletion.
    }
}

/// Exclusive new/empty output ownership. Clones and pending reports extend its
/// lifetime. A crash leaves the claim or artifacts behind and reuse is rejected.
#[derive(Clone)]
pub struct OutputClaim(Arc<Claim>);
impl OutputClaim {
    pub fn acquire(roots: &ResolvedRoots) -> Result<Self, OutputError> {
        let stage = OutputStage::Claim;
        let roots = resolve_roots(roots.input(), roots.output()).map_err(|source| OutputError {
            stage,
            code: OutputCode::UnsafePath,
            source,
        })?;
        ensure_root(roots.output()).map_err(|e| OutputError::io(stage, e))?;
        let root_guard =
            open_checked(roots.output(), true).map_err(|e| OutputError::io(stage, e))?;
        let root_identity = Snapshot::opened(&root_guard).map_err(|e| OutputError::io(stage, e))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(roots.output().join(CLAIM_FILE))
            .map_err(|source| OutputError {
                stage,
                code: if source.kind() == io::ErrorKind::AlreadyExists {
                    OutputCode::BusyOrNonempty
                } else {
                    OutputCode::Io
                },
                source,
            })?;
        let lock_identity = match Snapshot::opened(&lock) {
            Ok(identity) => identity,
            // Cannot establish ownership safely: leave an incomplete claim for inspection.
            Err(error) => return Err(OutputError::io(stage, error)),
        };
        let mut claim = Claim {
            root: roots.output().to_owned(),
            _root_guard: root_guard,
            root_identity,
            lock: Some(lock),
            lock_identity,
            results: None,
            shards: Mutex::new(BTreeMap::new()),
        };
        claim.verify().map_err(|e| OutputError::io(stage, e))?;
        // Claim first, then check emptiness: simultaneous contenders cannot both succeed.
        for entry in fs::read_dir(&claim.root).map_err(|e| OutputError::io(stage, e))? {
            let entry = entry.map_err(|e| OutputError::io(stage, e))?;
            if entry.file_name() != CLAIM_FILE {
                return Err(OutputError {
                    stage,
                    code: OutputCode::BusyOrNonempty,
                    source: io::Error::new(io::ErrorKind::AlreadyExists, "output is not empty"),
                });
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = claim
                ._root_guard
                .metadata()
                .map_err(|e| OutputError::io(stage, e))?
                .permissions()
                .mode();
            // Restrict an accepted empty destination without adding any access bits.
            claim
                ._root_guard
                .set_permissions(fs::Permissions::from_mode(mode & 0o700))
                .map_err(|e| OutputError::io(stage, e))?;
        }
        private_directory(&claim.root.join("results")).map_err(|e| OutputError::io(stage, e))?;
        claim.results = Some(
            directory_snapshot(&claim.root.join("results"))
                .map_err(|e| OutputError::io(stage, e))?,
        );
        Ok(Self(Arc::new(claim)))
    }
    pub fn root(&self) -> &Path {
        &self.0.root
    }
    pub fn begin_report(&self, relative: &RelativePath) -> Result<PendingReport, OutputError> {
        let report_id = relative.report_id();
        self.begin_id(report_id)
    }
    fn begin_id(&self, report_id: String) -> Result<PendingReport, OutputError> {
        let stage = OutputStage::Prepare;
        // Only internally generated IDs reach this function (tests can inject collisions).
        self.0.verify().map_err(|source| OutputError {
            stage,
            code: OutputCode::UnsafePath,
            source,
        })?;
        let shard = &report_id[..2];
        let directory = self.0.root.join("results").join(shard);
        let mut shards =
            self.0.shards.lock().map_err(|_| {
                OutputError::io(stage, io::Error::other("output shard state poisoned"))
            })?;
        if let Some(identity) = shards.get(shard) {
            check_directory(&directory, identity).map_err(|source| OutputError {
                stage,
                code: OutputCode::UnsafePath,
                source,
            })?;
        } else {
            // Serialized within the claim. An existing unowned shard is unexpected.
            private_directory(&directory).map_err(|e| OutputError::io(stage, e))?;
            shards.insert(
                shard.to_owned(),
                directory_snapshot(&directory).map_err(|e| OutputError::io(stage, e))?,
            );
        }
        #[cfg(test)]
        faults::hit(Point::ReportCreate).map_err(|e| OutputError::io(stage, e))?;
        let temporary = tempfile::Builder::new()
            .prefix(".pending-")
            .suffix(".json")
            .tempfile_in(&directory)
            .map_err(|e| OutputError::io(stage, e))?;
        drop(shards);
        let location = format!("results/{shard}/{report_id}.json");
        Ok(PendingReport {
            temporary: Some(temporary),
            owner: self.clone(),
            report_id,
            location,
            failed: false,
        })
    }
}

/// Only returned after complete bytes have become visible at the final path.
/// The coordinator must still append/flush its terminal journal before counters.
pub struct PublishedReport {
    pub(super) report_id: String,
    pub(super) location: String,
    owner: OutputClaim,
    identity: Snapshot,
}
impl PublishedReport {
    pub fn report_id(&self) -> &str {
        &self.report_id
    }
    pub fn location(&self) -> &str {
        &self.location
    }
    pub(super) fn verify_owner(&self, owner: &OutputClaim) -> io::Result<()> {
        if !Arc::ptr_eq(&self.owner.0, &owner.0) {
            return Err(unsafe_path());
        }
        owner.0.verify()?;
        let shards = owner
            .0
            .shards
            .lock()
            .map_err(|_| io::Error::other("output shard state poisoned"))?;
        check_directory(
            &owner.root().join("results").join(&self.report_id[..2]),
            &shards[&self.report_id[..2]],
        )?;
        let file = open_checked(&owner.root().join(&self.location), false)?;
        if !Snapshot::opened(&file)?.same_data(&self.identity) {
            return Err(unsafe_path());
        }
        drop(file);
        Ok(())
    }
}
impl fmt::Debug for PublishedReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedReport")
            .field("report_id", &self.report_id)
            .field("location", &self.location)
            .finish()
    }
}

pub struct PendingReport {
    // Drop temporary before the final owner clone, so empty shards can be removed.
    temporary: Option<NamedTempFile>,
    owner: OutputClaim,
    report_id: String,
    location: String,
    failed: bool,
}
impl Drop for PendingReport {
    fn drop(&mut self) {
        let owned = self.verify_temporary().is_ok();
        if let Some(mut temporary) = self.temporary.take() {
            // Never unlink a replacement at a formerly owned temporary pathname.
            temporary.disable_cleanup(!owned);
            drop(temporary);
        }
    }
}
impl Write for PendingReport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if let Err(error) = faults::hit(Point::ReportWrite) {
            self.failed = true;
            return Err(error);
        }
        #[cfg(test)]
        if let Err(error) = faults::hit(Point::ReportPartial) {
            self.failed = true;
            self.temporary
                .as_mut()
                .unwrap()
                .write_all(&bytes[..bytes.len().min(1)])?;
            return Err(error);
        }
        let result = self.temporary.as_mut().unwrap().write(bytes);
        self.failed |= result.is_err() || matches!(result, Ok(0) if !bytes.is_empty());
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if let Err(error) = faults::hit(Point::ReportFlush) {
            self.failed = true;
            return Err(error);
        }
        let result = self.temporary.as_mut().unwrap().flush();
        self.failed |= result.is_err();
        result
    }
}
impl PendingReport {
    fn verify_temporary(&self) -> io::Result<()> {
        let Some(temporary) = &self.temporary else {
            return Ok(());
        };
        self.owner.0.verify()?;
        let shards = self
            .owner
            .0
            .shards
            .lock()
            .map_err(|_| io::Error::other("output shard state poisoned"))?;
        let shard = &self.report_id[..2];
        check_directory(
            &self.owner.root().join("results").join(shard),
            &shards[shard],
        )?;
        let metadata = fs::symlink_metadata(temporary.path())?;
        if is_link(&metadata)
            || !metadata.is_file()
            || !Snapshot::observed(temporary.path(), &metadata)?
                .same_identity(&Snapshot::opened(temporary.as_file())?)
        {
            return Err(unsafe_path());
        }
        Ok(())
    }
    /// Flush, validate the input/cancellation state, then atomically publish without
    /// replacement. Failed validation, collision or I/O drops the owned temporary.
    /// This guarantees atomic visibility, not fsync-backed power-loss durability.
    pub fn publish(
        mut self,
        validate_input: impl FnOnce() -> io::Result<()>,
    ) -> Result<PublishedReport, OutputError> {
        if self.failed {
            return Err(OutputError::io(
                OutputStage::Write,
                io::Error::other("report stream previously failed"),
            ));
        }
        self.flush()
            .map_err(|e| OutputError::io(OutputStage::Flush, e))?;
        validate_input().map_err(|e| OutputError::io(OutputStage::ValidateInput, e))?;
        self.verify_temporary().map_err(|source| OutputError {
            stage: OutputStage::Publish,
            code: OutputCode::UnsafePath,
            source,
        })?;
        let identity = Snapshot::opened(self.temporary.as_ref().unwrap().as_file())
            .map_err(|e| OutputError::io(OutputStage::Publish, e))?;
        let destination = self.owner.root().join(&self.location);
        #[cfg(test)]
        faults::hit(Point::ReportPublish).map_err(|e| OutputError::io(OutputStage::Publish, e))?;
        match self
            .temporary
            .take()
            .unwrap()
            .persist_noclobber(destination)
        {
            Ok(file) => {
                drop(file);
                #[cfg(test)]
                faults::hit(Point::ReportPublished)
                    .map_err(|e| OutputError::io(OutputStage::Publish, e))?;
                Ok(PublishedReport {
                    report_id: std::mem::take(&mut self.report_id),
                    location: std::mem::take(&mut self.location),
                    owner: self.owner.clone(),
                    identity,
                })
            }
            Err(error) => {
                self.temporary = Some(error.file);
                Err(OutputError {
                    stage: OutputStage::Publish,
                    code: if error.error.kind() == io::ErrorKind::AlreadyExists {
                        OutputCode::Collision
                    } else {
                        OutputCode::Io
                    },
                    source: error.error,
                })
            }
        }
    }
}

// Coordinator-only artifact primitives. Journal ownership is provisional until
// initialization has successfully published the first incomplete manifest.
pub(super) struct OwnedJournal {
    file: File,
    path: PathBuf,
    identity: Snapshot,
    owner: OutputClaim,
    retained: bool,
}
impl OwnedJournal {
    pub(super) fn retain(&mut self) {
        self.retained = true;
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        self.owner.0.verify()?;
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.is_file()
            || is_link(&metadata)
            || Snapshot::observed(&self.path, &metadata)? != self.identity
            || Snapshot::opened(&self.file)? != self.identity
        {
            return Err(unsafe_path());
        }
        Ok(())
    }
    pub(super) fn append(&mut self, value: &impl serde::Serialize) -> io::Result<()> {
        self.verify()?;
        #[cfg(test)]
        let kind = if self.path.file_name().is_some_and(|p| p == "errors.jsonl") {
            Journal::Diagnostic
        } else if serde_json::to_value(value)?["record_type"] == "admission" {
            Journal::Admission
        } else {
            Journal::Terminal
        };
        #[cfg(test)]
        {
            faults::hit(Point::Journal(kind, Step::Write))?;
            if let Err(error) = faults::hit(Point::Journal(kind, Step::Partial)) {
                // A real torn JSON record reaches disk before the write reports failure.
                self.file.write_all(b"{\"schema_version\":")?;
                self.file.flush()?;
                return Err(error);
            }
        }
        write_json_line(&mut self.file, value)?;
        #[cfg(test)]
        faults::hit(Point::Journal(kind, Step::Flush))?;
        self.file.flush()?;
        #[cfg(test)]
        faults::hit(Point::Journal(kind, Step::Flushed))?;
        self.identity = Snapshot::opened(&self.file)?;
        self.verify()
    }
}
impl Drop for OwnedJournal {
    fn drop(&mut self) {
        if !self.retained && self.verify().is_ok() {
            let _ = fs::remove_file(&self.path);
        }
    }
}
impl OutputClaim {
    pub(super) fn create_journal(&self, errors: bool) -> io::Result<OwnedJournal> {
        self.0.verify()?;
        let path = self.root().join(if errors {
            "errors.jsonl"
        } else {
            "files.jsonl"
        });
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        let identity = Snapshot::opened(&file)?;
        Ok(OwnedJournal {
            file,
            path,
            identity,
            owner: self.clone(),
            retained: false,
        })
    }
    pub(super) fn write_manifest(
        &self,
        manifest: &super::Manifest,
        previous: Option<&Snapshot>,
    ) -> io::Result<Snapshot> {
        manifest.validate().map_err(io::Error::other)?;
        self.0.verify()?;
        let destination = self.root().join("manifest.json");
        #[cfg(test)]
        faults::hit(Point::ManifestCreate)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".manifest-")
            .tempfile_in(self.root())?;
        #[cfg(test)]
        faults::hit(Point::ManifestWrite)?;
        write_json_line(&mut temporary, manifest)?;
        #[cfg(test)]
        faults::hit(Point::ManifestFlush)?;
        temporary.flush()?;
        let identity = Snapshot::opened(temporary.as_file())?;
        self.0.verify()?;
        if let Some(previous) = previous {
            let metadata = fs::symlink_metadata(&destination)?;
            if !metadata.is_file()
                || is_link(&metadata)
                || !Snapshot::observed(&destination, &metadata)?.same_data(previous)
            {
                return Err(unsafe_path());
            }
        }
        // The first manifest never replaces data; later snapshots replace only
        // the previously owned manifest. Hostile concurrent mutation is excluded.
        #[cfg(test)]
        {
            faults::hit(Point::ManifestReplace)?;
            if manifest.status == super::BatchStatus::Complete {
                faults::hit(Point::FinalManifestReplace)?;
            }
        }
        let result = if previous.is_some() {
            temporary.persist(destination)
        } else {
            temporary.persist_noclobber(destination)
        };
        result.map_err(|e| e.error)?;
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_partial_write_error_is_not_retried_on_drop() {
        struct FailingWriter(usize);
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                if self.0 == 1 {
                    Ok(1)
                } else {
                    Err(io::Error::other("full"))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("must not flush after a failed write")
            }
        }
        let mut output = FailingWriter(0);
        assert!(write_json_line(&mut output, &serde_json::json!({"record": 1})).is_err());
        assert_eq!(output.0, 2, "Drop must not retry the failed write");
    }

    #[test]
    fn json_lines_are_complete_and_flushed_before_returning() {
        #[derive(Default)]
        struct Observer {
            bytes: Vec<u8>,
            flushed: bool,
        }
        impl Write for Observer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.flushed = false;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushed = true;
                Ok(())
            }
        }
        for size in [4, 32_768] {
            let value = serde_json::json!({"path": "x".repeat(size)});
            let mut output = Observer::default();
            write_json_line(&mut output, &value).unwrap();
            assert!(output.flushed);
            let mut expected = serde_json::to_vec(&value).unwrap();
            expected.push(b'\n');
            assert_eq!(output.bytes, expected);
        }
    }

    fn fixture() -> (tempfile::TempDir, ResolvedRoots) {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir(base.join("input")).unwrap();
        let roots = resolve_roots(&base.join("input"), &base.join("output")).unwrap();
        (temp, roots)
    }
    fn path(name: &str) -> RelativePath {
        RelativePath::from_relative(Path::new(name)).unwrap()
    }

    #[test]
    fn failed_write_cannot_be_published_even_if_caller_ignores_it() {
        let (_temp, roots) = fixture();
        let claim = OutputClaim::acquire(&roots).unwrap();
        let mut report = claim.begin_report(&path("sample")).unwrap();
        let temporary = report.temporary.take().unwrap();
        let (file, temp_path) = temporary.into_parts();
        drop(file);
        let read_only = File::open(&temp_path).unwrap();
        report.temporary = Some(NamedTempFile::from_parts(read_only, temp_path));
        assert!(report.write_all(b"report").is_err());
        assert_eq!(
            report.publish(|| Ok(())).unwrap_err().stage,
            OutputStage::Write
        );
        drop(claim);
        assert_eq!(fs::read_dir(roots.output()).unwrap().count(), 0);
    }

    #[test]
    fn injected_digest_collision_never_replaces_the_first_report() {
        let (_temp, roots) = fixture();
        let claim = OutputClaim::acquire(&roots).unwrap();
        let id = path("first-source").report_id();
        assert_ne!(id, path("second-source").report_id());
        let mut first = claim.begin_id(id.clone()).unwrap();
        first.write_all(b"first source").unwrap();
        let published = first.publish(|| Ok(())).unwrap();
        // Force the second source's digest to collide at the internal ID boundary.
        let mut second = claim.begin_id(id).unwrap();
        second.write_all(b"second source").unwrap();
        assert_eq!(
            second.publish(|| Ok(())).unwrap_err().code,
            OutputCode::Collision
        );
        assert_eq!(
            fs::read(roots.output().join(published.location)).unwrap(),
            b"first source"
        );
    }

    #[test]
    fn replaced_temporary_is_not_published_or_deleted() {
        let (_temp, roots) = fixture();
        let claim = OutputClaim::acquire(&roots).unwrap();
        let mut report = claim.begin_report(&path("sample")).unwrap();
        report.write_all(b"own partial data").unwrap();
        let temp_path = report.temporary.as_ref().unwrap().path().to_owned();
        let old_path = temp_path.with_extension("moved");
        fs::rename(&temp_path, &old_path).unwrap();
        fs::write(&temp_path, b"foreign replacement").unwrap();
        assert_eq!(
            report.publish(|| Ok(())).unwrap_err().code,
            OutputCode::UnsafePath
        );
        assert_eq!(fs::read(&temp_path).unwrap(), b"foreign replacement");
        assert_eq!(fs::read(&old_path).unwrap(), b"own partial data");
    }

    #[test]
    fn replaced_claim_is_preserved_on_drop() {
        let (_temp, roots) = fixture();
        let claim = OutputClaim::acquire(&roots).unwrap();
        let lock = roots.output().join(CLAIM_FILE);
        fs::rename(&lock, roots.output().join("old-lock")).unwrap();
        fs::write(&lock, b"another owner").unwrap();
        drop(claim);
        assert_eq!(fs::read(lock).unwrap(), b"another owner");
        assert!(roots.output().join("old-lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_destination_link_and_post_preflight_link_are_never_followed() {
        use std::os::unix::fs::symlink;
        let (_temp, roots) = fixture();
        let foreign = roots.input().join("foreign");
        fs::create_dir(&foreign).unwrap();
        symlink(&foreign, roots.output()).unwrap();
        assert_eq!(
            OutputClaim::acquire(&roots).err().unwrap().code,
            OutputCode::UnsafePath
        );
        assert_eq!(fs::read_dir(&foreign).unwrap().count(), 0);
        fs::remove_file(roots.output()).unwrap();
        let claim = OutputClaim::acquire(&roots).unwrap();
        let source = path("sample");
        let mut report = claim.begin_report(&source).unwrap();
        report.write_all(b"new report").unwrap();
        let target = foreign.join("preserved");
        fs::write(&target, b"keep").unwrap();
        symlink(&target, roots.output().join(source.report_location())).unwrap();
        assert_eq!(
            report.publish(|| Ok(())).unwrap_err().code,
            OutputCode::Collision
        );
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }
}
