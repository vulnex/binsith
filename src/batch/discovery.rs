//
// VULNEX -BinSith-
//
// File: batch/discovery.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::{
    input::{changed, open_checked, Candidate, Snapshot},
    roots::{is_link, ResolvedRoots},
};
use crate::scanner::CancellationToken;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Subdirectory,
    Link,
    SpecialFile,
    OutputTree,
}

#[derive(Debug)]
pub enum DiscoveryEvent {
    File(Candidate),
    Skipped {
        relative: PathBuf,
        reason: SkipReason,
    },
    /// Root errors use an empty relative path. The coordinator must escape paths
    /// and messages before terminal display. A fatal scratch error stops traversal.
    Error {
        relative: PathBuf,
        error: io::Error,
        fatal: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct PendingDirectory {
    path: Vec<u8>,
    observed: Snapshot,
}

fn native_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}
fn native_path(bytes: Vec<u8>) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(bytes).into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if bytes.len() % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid queued path",
            ));
        }
        let units: Vec<_> = bytes
            .chunks_exact(2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect();
        Ok(OsString::from_wide(&units).into())
    }
}

/// Append-only private scratch: O(total discovered directory-path bytes) disk,
/// O(longest queued path) userspace memory and exactly one scratch handle.
struct DirectoryQueue {
    file: File,
    read: u64,
    end: u64,
    max_record: u64,
}
impl DirectoryQueue {
    fn new() -> io::Result<Self> {
        Ok(Self {
            file: tempfile::tempfile()?,
            read: 0,
            end: 0,
            max_record: 0,
        })
    }
    fn push(&mut self, directory: &PendingDirectory) -> io::Result<()> {
        let bytes = serde_json::to_vec(directory)?;
        self.file.seek(SeekFrom::Start(self.end))?;
        self.file.write_all(&(bytes.len() as u64).to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.end = self.file.stream_position()?;
        self.max_record = self.max_record.max(bytes.len() as u64);
        Ok(())
    }
    fn pop(&mut self) -> io::Result<Option<PendingDirectory>> {
        if self.read == self.end {
            return Ok(None);
        }
        self.file.seek(SeekFrom::Start(self.read))?;
        let mut size = [0; 8];
        self.file.read_exact(&mut size)?;
        let size = u64::from_le_bytes(size);
        if size > self.max_record || size > self.end.saturating_sub(self.read).saturating_sub(8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid directory queue record",
            ));
        }
        let mut bytes = vec![
            0;
            usize::try_from(size)
                .map_err(|_| io::Error::other("directory record too large"))?
        ];
        self.file.read_exact(&mut bytes)?;
        self.read = self.file.stream_position()?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
}

struct Directory {
    relative: PathBuf,
    observed: Snapshot,
    #[cfg(unix)]
    entries: rustix::fs::Dir,
    #[cfg(windows)]
    entries: fs::ReadDir,
    #[cfg(windows)]
    _guard: File,
}
impl Directory {
    fn open(root: &Path, relative: PathBuf, observed: Snapshot) -> io::Result<Self> {
        let path = root.join(&relative);
        let file = open_checked(&path, true)?;
        if !Snapshot::opened(&file)?.same_identity(&observed) {
            return Err(changed());
        }
        #[cfg(unix)]
        let entries = rustix::fs::Dir::new(file)?;
        #[cfg(windows)]
        let entries = fs::read_dir(&path)?;
        Ok(Self {
            relative,
            observed,
            entries,
            #[cfg(windows)]
            _guard: file,
        })
    }
    fn next_name(&mut self) -> Option<io::Result<OsString>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            loop {
                let entry = match self.entries.read()? {
                    Ok(e) => e,
                    Err(e) => return Some(Err(e.into())),
                };
                let name = entry.file_name().to_bytes();
                if name != b"." && name != b".." {
                    return Some(Ok(OsString::from_vec(name.to_vec())));
                }
            }
        }
        #[cfg(windows)]
        {
            self.entries.next().map(|e| e.map(|e| e.file_name()))
        }
    }
}

/// Incremental breadth-first traversal. No sorting, complete-tree collection,
/// queued input handles or recursion stack. Creation performs no enumeration;
/// next() drives all work. Drop/stop releases the active directory and scratch.
pub struct Discovery {
    root: PathBuf,
    output: PathBuf,
    recursive: bool,
    cancellation: CancellationToken,
    pending: Option<DirectoryQueue>,
    initial: Option<PendingDirectory>,
    active: Option<Directory>,
    finished: bool,
    complete: bool,
}
impl Discovery {
    pub fn new(
        roots: &ResolvedRoots,
        recursive: bool,
        cancellation: CancellationToken,
    ) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(roots.input())?;
        if is_link(&metadata) || !metadata.is_dir() {
            return Err(changed());
        }
        let observed = Snapshot::observed(roots.input(), &metadata)?;
        Ok(Self {
            root: roots.input().to_owned(),
            output: roots.output().to_owned(),
            recursive,
            cancellation,
            pending: None,
            initial: Some(PendingDirectory {
                path: Vec::new(),
                observed,
            }),
            active: None,
            finished: false,
            complete: false,
        })
    }
    /// True only after natural exhaustion. Discovery errors are separate events;
    /// a fully traversed tree with errors still cannot yield a successful batch.
    pub fn discovery_complete(&self) -> bool {
        self.complete
    }
    pub fn stop(&mut self) {
        self.finished = true;
        self.active = None;
        self.initial = None;
        self.pending = None;
    }
    fn error(relative: PathBuf, error: io::Error, fatal: bool) -> DiscoveryEvent {
        DiscoveryEvent::Error {
            relative,
            error,
            fatal,
        }
    }
    fn queue(&mut self, relative: &Path, observed: Snapshot) -> io::Result<()> {
        if self.pending.is_none() {
            self.pending = Some(DirectoryQueue::new()?);
        }
        self.pending.as_mut().unwrap().push(&PendingDirectory {
            path: native_bytes(relative),
            observed,
        })
    }
    fn visit(&mut self) -> io::Result<Option<PendingDirectory>> {
        if let Some(initial) = self.initial.take() {
            return Ok(Some(initial));
        }
        match &mut self.pending {
            Some(queue) => queue.pop(),
            None => Ok(None),
        }
    }
}
impl Iterator for Discovery {
    type Item = DiscoveryEvent;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            if self.cancellation.is_cancelled() {
                self.stop();
                return None;
            }
            if self.active.is_none() {
                let next = match self.visit() {
                    Ok(Some(next)) => next,
                    Ok(None) => {
                        self.complete = true;
                        self.stop();
                        return None;
                    }
                    Err(error) => {
                        self.stop();
                        return Some(Self::error(PathBuf::new(), error, true));
                    }
                };
                let relative = match native_path(next.path) {
                    Ok(path) => path,
                    Err(error) => {
                        self.stop();
                        return Some(Self::error(PathBuf::new(), error, true));
                    }
                };
                match Directory::open(&self.root, relative.clone(), next.observed) {
                    Ok(directory) => self.active = Some(directory),
                    Err(error) => return Some(Self::error(relative, error, false)),
                }
            }
            let directory = self.active.as_mut().unwrap();
            // Detect accidental rename/substitution before resolving child paths.
            let stable = fs::symlink_metadata(self.root.join(&directory.relative)).and_then(|m| {
                if is_link(&m) || !m.is_dir() {
                    return Err(changed());
                }
                let observed = Snapshot::observed(&self.root.join(&directory.relative), &m)?;
                if !observed.same_identity(&directory.observed) {
                    return Err(changed());
                }
                Ok(())
            });
            if let Err(error) = stable {
                let relative = directory.relative.clone();
                self.active = None;
                return Some(Self::error(relative, error, false));
            }
            let name = match directory.next_name() {
                None => {
                    self.active = None;
                    continue;
                }
                Some(Err(error)) => {
                    let relative = directory.relative.clone();
                    self.active = None;
                    return Some(Self::error(relative, error, false));
                }
                Some(Ok(name)) => name,
            };
            let relative = directory.relative.join(name);
            let absolute = self.root.join(&relative);
            let metadata = match fs::symlink_metadata(&absolute) {
                Ok(metadata) => metadata,
                Err(error) => return Some(Self::error(relative, error, false)),
            };
            let skip = if is_link(&metadata) {
                Some(SkipReason::Link)
            } else if absolute == self.output {
                Some(SkipReason::OutputTree)
            } else if metadata.is_dir() && !self.recursive {
                Some(SkipReason::Subdirectory)
            } else if !metadata.is_file() && !metadata.is_dir() {
                Some(SkipReason::SpecialFile)
            } else {
                None
            };
            if let Some(reason) = skip {
                return Some(DiscoveryEvent::Skipped { relative, reason });
            }
            let observed = match Snapshot::observed(&absolute, &metadata) {
                Ok(snapshot) => snapshot,
                Err(error) => return Some(Self::error(relative, error, false)),
            };
            if metadata.is_dir() {
                // Canonical spelling also catches output aliases on case-insensitive volumes.
                match fs::canonicalize(&absolute) {
                    Ok(path) if path == self.output => {
                        return Some(DiscoveryEvent::Skipped {
                            relative,
                            reason: SkipReason::OutputTree,
                        })
                    }
                    Err(error) => return Some(Self::error(relative, error, false)),
                    _ => {}
                }
                if let Err(error) = self.queue(&relative, observed) {
                    self.stop();
                    return Some(Self::error(relative, error, true));
                }
            } else {
                return Some(DiscoveryEvent::File(Candidate {
                    absolute,
                    relative,
                    observed,
                }));
            }
        }
    }
}
impl std::iter::FusedIterator for Discovery {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::roots::resolve_roots;

    fn fixture() -> (tempfile::TempDir, ResolvedRoots) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let roots = resolve_roots(&root, &root.join("reports")).unwrap();
        (temp, roots)
    }
    fn observed(path: &Path) -> Snapshot {
        Snapshot::observed(path, &fs::symlink_metadata(path).unwrap()).unwrap()
    }

    #[test]
    fn queued_directory_deletion_is_one_error_and_other_directories_continue() {
        let (_temp, roots) = fixture();
        fs::create_dir(roots.input().join("gone")).unwrap();
        fs::create_dir(roots.input().join("good")).unwrap();
        fs::write(roots.input().join("good/file"), b"x").unwrap();
        let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
        discovery.initial = None;
        discovery
            .queue(Path::new("gone"), observed(&roots.input().join("gone")))
            .unwrap();
        discovery
            .queue(Path::new("good"), observed(&roots.input().join("good")))
            .unwrap();
        fs::remove_dir(roots.input().join("gone")).unwrap();
        assert!(
            matches!(discovery.next(), Some(DiscoveryEvent::Error { relative, fatal: false, .. }) if relative == Path::new("gone"))
        );
        assert!(
            matches!(discovery.next(), Some(DiscoveryEvent::File(file)) if file.relative_path() == Path::new("good/file"))
        );
        assert!(discovery.next().is_none());
        assert!(discovery.discovery_complete());
        assert!(discovery.pending.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn queued_directory_replaced_with_link_or_new_directory_is_not_traversed() {
        use std::os::unix::fs::symlink;
        for link in [false, true] {
            let (_temp, roots) = fixture();
            let path = roots.input().join("child");
            fs::create_dir(&path).unwrap();
            let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
            discovery.initial = None;
            discovery
                .queue(Path::new("child"), observed(&path))
                .unwrap();
            fs::rename(&path, roots.input().join("original")).unwrap();
            if link {
                symlink(roots.input().join("original"), &path).unwrap();
            } else {
                fs::create_dir(&path).unwrap();
            }
            assert!(matches!(
                discovery.next(),
                Some(DiscoveryEvent::Error { fatal: false, .. })
            ));
            assert!(discovery.next().is_none());
        }
    }

    #[test]
    fn scratch_write_and_truncation_failures_are_fatal_and_release_state() {
        let (_temp, roots) = fixture();
        fs::create_dir(roots.input().join("child")).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let read_only = File::open(file.path()).unwrap();
        let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
        discovery.pending = Some(DirectoryQueue {
            file: read_only,
            read: 0,
            end: 0,
            max_record: 0,
        });
        assert!(matches!(
            discovery.next(),
            Some(DiscoveryEvent::Error { fatal: true, .. })
        ));
        assert!(!discovery.discovery_complete());
        assert!(discovery.active.is_none() && discovery.pending.is_none());
        assert!(discovery.next().is_none());

        let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
        discovery.initial = None;
        discovery
            .queue(Path::new("child"), observed(&roots.input().join("child")))
            .unwrap();
        discovery.pending.as_ref().unwrap().file.set_len(3).unwrap();
        assert!(matches!(
            discovery.next(),
            Some(DiscoveryEvent::Error { fatal: true, .. })
        ));
        assert!(!discovery.discovery_complete());
        assert!(discovery.pending.is_none());
    }

    #[test]
    fn breadth_is_spooled_without_holding_directory_handles_or_paths_in_memory() {
        let (_temp, roots) = fixture();
        for i in 0..128 {
            let path = roots.input().join(format!("child-{i}"));
            fs::create_dir(&path).unwrap();
            fs::write(path.join("file"), b"x").unwrap();
        }
        let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
        assert!(matches!(discovery.next(), Some(DiscoveryEvent::File(_))));
        let queue = discovery.pending.as_ref().unwrap();
        assert!(queue.end > queue.max_record * 100);
        assert!(queue.max_record < 1024);
        // At this point all root children are queued on disk, while the only
        // active directory is the one containing this first yielded candidate.
        assert!(discovery.active.is_some());
        let scratch_bytes = queue.end;
        discovery.stop();
        assert!(discovery.active.is_none() && discovery.pending.is_none());
        assert!(scratch_bytes > 0);
    }
}
