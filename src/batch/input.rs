//
// VULNEX -BinSith-
//
// File: batch/input.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::{roots::is_link, RelativePath};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Snapshot {
    identity: (u64, u64),
    size: u64,
    modified: SystemTime,
    // Unix change time detects some same-size writes with restored modification time.
    changed: Option<(i64, i64)>,
}
impl Snapshot {
    pub(super) fn same_contents(&self, other: &Self) -> bool {
        self.size == other.size && self.modified == other.modified
    }
    pub(super) fn same_contents_and_change(&self, other: &Self) -> bool {
        self.same_contents(other) && self.changed == other.changed
    }
    pub(super) fn same_data(&self, other: &Self) -> bool {
        self.identity == other.identity && self.same_contents(other)
    }
    pub(super) fn same_identity(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
    pub(super) fn observed(path: &Path, metadata: &Metadata) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let _ = path;
            Self::metadata(metadata)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::*;
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)?;
            let actual = file.metadata()?;
            if is_link(&actual)
                || actual.is_dir() != metadata.is_dir()
                || actual.is_file() != metadata.is_file()
            {
                return Err(changed());
            }
            Self::opened(&file)
        }
    }
    #[cfg(unix)]
    fn metadata(metadata: &Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            identity: (metadata.dev(), metadata.ino()),
            size: metadata.len(),
            modified: metadata.modified()?,
            changed: Some((metadata.ctime(), metadata.ctime_nsec())),
        })
    }
    pub(super) fn opened(file: &File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Self::metadata(&file.metadata()?)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            };
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: live File handle and correctly sized writable output. Read only on success.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            let metadata = file.metadata()?;
            Ok(Self {
                identity: (
                    u64::from(info.dwVolumeSerialNumber),
                    (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
                ),
                size: metadata.len(),
                modified: metadata.modified()?,
                changed: None,
            })
        }
    }
}

pub(super) fn changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "file_changed")
}

/// Open without following the final component, then classify the opened handle.
/// Nonblocking Unix opens prevent a substituted FIFO from waiting for a writer.
/// This is not containment against hostile mutation of ancestor directories.
pub(super) fn open_checked(path: &Path, directory: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if directory {
            flags |= OFlags::DIRECTORY;
        }
        options.custom_flags(flags.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        // Keep directories from being renamed while path-based ReadDir enumerates.
        options
            .share_mode(if directory {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            })
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if is_link(&metadata)
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not the expected regular file/directory",
        ));
    }
    Ok(file)
}

/// A queued candidate owns metadata and native paths, never an open input handle.
#[derive(Debug)]
pub struct Candidate {
    pub(super) absolute: PathBuf,
    pub(super) relative: PathBuf,
    pub(super) observed: Snapshot,
}
impl Candidate {
    pub fn relative_path(&self) -> &Path {
        &self.relative
    }
    pub fn record_path(&self) -> Result<RelativePath, &'static str> {
        RelativePath::from_relative(&self.relative)
    }
    pub fn open(&self) -> io::Result<OpenedInput> {
        let file = open_checked(&self.absolute, false)?;
        let before = Snapshot::opened(&file)?;
        if before != self.observed {
            return Err(changed());
        }
        Ok(OpenedInput {
            file,
            path: self.absolute.clone(),
            before,
        })
    }
}

pub struct OpenedInput {
    file: File,
    path: PathBuf,
    before: Snapshot,
}
impl OpenedInput {
    /// Select independently for this file. Pass the returned Take reader to the
    /// scanner, then call verify_unchanged before publishing its temporary report.
    pub fn selected(
        &mut self,
        offset: u64,
        length: Option<u64>,
    ) -> io::Result<io::Take<&mut File>> {
        if offset > self.before.size || length.is_some_and(|n| offset.checked_add(n).is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid per-file scan range",
            ));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        Ok(std::io::Read::take(
            &mut self.file,
            length
                .unwrap_or(self.before.size - offset)
                .min(self.before.size - offset),
        ))
    }
    /// Both the open handle and current pathname must still match. Metadata is
    /// evidence, not a complete mutation detector or a filesystem snapshot.
    pub fn verify_unchanged(&self) -> io::Result<()> {
        let current = Snapshot::opened(&self.file)?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| changed())?;
        if !metadata.is_file()
            || is_link(&metadata)
            || current != self.before
            || Snapshot::observed(&self.path, &metadata).map_err(|_| changed())? != self.before
        {
            return Err(changed());
        }
        Ok(())
    }
}
