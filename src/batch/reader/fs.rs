//! Reader-only containment. Unix uses descriptor-relative no-follow opens;
//! Windows retains non-share-write/non-share-delete ancestor guards while opening.
use super::{invalid, Result};
use crate::batch::input::Snapshot;
use std::{
    fs::File,
    path::{Component, Path, PathBuf},
};

pub(super) struct Root {
    pub file: File,
    path: PathBuf,
    identity: Snapshot,
    _parents: Vec<File>,
}
pub(super) struct CheckedFile {
    pub file: File,
    pub before: Snapshot,
    _parents: Vec<File>,
}

#[cfg(unix)]
fn child(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let file =
        File::from(openat(parent, name, flags, Mode::empty()).map_err(std::io::Error::from)?);
    classify(&file, directory)?;
    Ok(file)
}
#[cfg(windows)]
fn windows_open(path: &Path, directory: bool) -> Result<File> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::*;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    classify(&file, directory)?;
    Ok(file)
}
fn classify(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    if crate::batch::roots::is_link(&m) || if directory { !m.is_dir() } else { !m.is_file() } {
        return Err(invalid("artifact is not a regular file/directory"));
    }
    Ok(())
}
impl Root {
    pub fn open(path: &Path) -> Result<Self> {
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut parents = Vec::new();
        #[cfg(unix)]
        let mut current = File::open("/")?;
        #[cfg(windows)]
        let mut prefix = PathBuf::new();
        #[cfg(windows)]
        let mut current = None;
        for component in path.components() {
            match component {
                Component::ParentDir => return Err(invalid("parent traversal in batch root")),
                Component::CurDir => (),
                Component::Normal(name) => {
                    #[cfg(unix)]
                    {
                        let next = child(&current, name, true)?;
                        parents.push(current);
                        current = next;
                    }
                    #[cfg(windows)]
                    {
                        prefix.push(name);
                        let next = windows_open(&prefix, true)?;
                        if let Some(previous) = current.replace(next) {
                            parents.push(previous);
                        }
                    }
                }
                Component::RootDir => {
                    #[cfg(windows)]
                    {
                        prefix.push(component.as_os_str());
                        current = Some(windows_open(&prefix, true)?);
                    }
                }
                Component::Prefix(_) => {
                    #[cfg(windows)]
                    prefix.push(component.as_os_str());
                }
            }
        }
        #[cfg(windows)]
        let current = current.ok_or_else(|| invalid("invalid batch root"))?;
        let identity = Snapshot::opened(&current)?;
        Ok(Self {
            file: current,
            path,
            identity,
            _parents: parents,
        })
    }
    pub fn check(&self) -> Result<()> {
        classify(&self.file, true)?;
        let fresh = Self::open(&self.path)?;
        if !fresh.identity.same_identity(&self.identity) {
            return Err(invalid("batch root changed"));
        }
        Ok(())
    }
    pub fn open_file(&self, relative: &str) -> Result<CheckedFile> {
        self.open_relative(relative, false)
            .map_err(|error| match error {
                super::Error::Io(e)
                    if relative != ".binsith.lock" && e.kind() == std::io::ErrorKind::NotFound =>
                {
                    invalid("referenced artifact is missing")
                }
                other => other,
            })
    }
    fn open_relative(&self, relative: &str, last_is_directory: bool) -> Result<CheckedFile> {
        self.check()?;
        let components: Vec<_> = relative.split('/').collect();
        if components.is_empty()
            || components.iter().any(|p| {
                p.is_empty()
                    || *p == "."
                    || *p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
            })
        {
            return Err(invalid("unsafe artifact location"));
        }
        let mut guards = Vec::new();
        #[cfg(unix)]
        let mut parent = &self.file;
        #[cfg(windows)]
        let mut path = self.path.clone();
        for (index, name) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            let directory = !last || last_is_directory;
            #[cfg(unix)]
            let file = child(parent, std::ffi::OsStr::new(name), directory)?;
            #[cfg(windows)]
            let file = {
                path.push(name);
                windows_open(&path, directory)?
            };
            if last {
                let before = Snapshot::opened(&file)?;
                return Ok(CheckedFile {
                    file,
                    before,
                    _parents: guards,
                });
            }
            guards.push(file);
            #[cfg(unix)]
            {
                parent = guards.last().unwrap();
            }
        }
        Err(invalid("missing artifact filename"))
    }
    pub fn directory_exists(&self, relative: &str) -> Result<bool> {
        match self.open_relative(relative, true) {
            Ok(_) => Ok(true),
            Err(super::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn names(
        &self,
        relative: &str,
        mut visit: impl FnMut(std::ffi::OsString) -> Result<()>,
    ) -> Result<()> {
        let guard = self.open_relative(relative, true)?;
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut entries =
                rustix::fs::Dir::new(guard.file.try_clone()?).map_err(std::io::Error::from)?;
            while let Some(entry) = entries.read() {
                let entry = entry.map_err(std::io::Error::from)?;
                let bytes = entry.file_name().to_bytes();
                if bytes != b"." && bytes != b".." {
                    visit(std::ffi::OsString::from_vec(bytes.to_vec()))?;
                }
            }
        }
        #[cfg(windows)]
        {
            for entry in std::fs::read_dir(self.path.join(relative))? {
                visit(entry?.file_name())?;
            }
        }
        guard.verify()?;
        let after = self.open_relative(relative, true)?;
        if after.before != guard.before {
            return Err(invalid("artifact directory changed during enumeration"));
        }
        Ok(())
    }
    pub fn unclaimed(&self) -> Result<()> {
        match self.open_file(".binsith.lock") {
            Ok(_) => Err(invalid(
                "batch has an output claim; use a quiescent completed copy",
            )),
            Err(super::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
    pub fn verify(&self, relative: &str, expected: &Snapshot) -> Result<()> {
        let current = self.open_file(relative)?;
        if current.before != *expected {
            return Err(invalid("artifact changed during import"));
        }
        Ok(())
    }
}
impl CheckedFile {
    pub fn verify(&self) -> Result<()> {
        if Snapshot::opened(&self.file)? != self.before {
            return Err(invalid("opened artifact changed during import"));
        }
        Ok(())
    }
}

impl Root {
    /// Exclusive destination with a guarded existing parent. Never create through
    /// symlinks or reuse a directory; compare ancestor identities as well as names.
    pub(super) fn create_output(&self, destination: &Path) -> Result<Self> {
        let name = destination
            .file_name()
            .ok_or_else(|| invalid("invalid export destination"))?;
        let parent_path = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = Self::open(parent_path)?;
        let source = self.path.canonicalize()?;
        let candidate = parent.path.canonicalize()?.join(name);
        if candidate.starts_with(&source) || source.starts_with(&candidate) {
            return Err(invalid("export destination overlaps source batch"));
        }
        for ancestor in std::iter::once(&parent.file).chain(parent._parents.iter()) {
            if Snapshot::opened(ancestor)?.same_identity(&self.identity) {
                return Err(invalid("export destination is inside source batch"));
            }
        }
        #[cfg(unix)]
        rustix::fs::mkdirat(&parent.file, name, rustix::fs::Mode::from_raw_mode(0o700)).map_err(
            |e| {
                let e = std::io::Error::from(e);
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    invalid("export destination already exists")
                } else {
                    e.into()
                }
            },
        )?;
        #[cfg(windows)]
        std::fs::create_dir(&candidate).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                invalid("export destination already exists")
            } else {
                e.into()
            }
        })?;
        parent.check()?;
        let result = Self::open(&candidate)?;
        #[cfg(unix)]
        if !Snapshot::opened(&child(&parent.file, name, true)?)?.same_identity(&result.identity) {
            return Err(invalid("export destination changed during creation"));
        }
        Ok(result)
    }
    pub(super) fn create_file(&self, name: &str) -> Result<File> {
        self.check()?;
        // Callers supply fixed bundle basenames, never sample paths.
        if !matches!(
            name,
            "indicators.json" | "indicators.csv" | "summary.json" | ".manifest.pending"
        ) {
            return Err(invalid("invalid bundle filename"));
        }
        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(std::io::Error::from)?,
        );
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(self.path.join(name))?
        };
        Ok(file)
    }
    pub(super) fn publish_manifest(&self, expected: &Snapshot) -> Result<()> {
        self.check()?;
        self.verify(".manifest.pending", expected)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        rustix::fs::renameat_with(
            &self.file,
            ".manifest.pending",
            &self.file,
            "manifest.json",
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        #[cfg(windows)]
        {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::{
                Wdk::Storage::FileSystem::{
                    FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
                },
                Win32::{
                    Foundation::RtlNtStatusToDosError,
                    Storage::FileSystem::{
                        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                    },
                    System::IO::IO_STATUS_BLOCK,
                },
            };
            let pending = std::fs::OpenOptions::new()
                .access_mode(DELETE | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(".manifest.pending"))?;
            classify(&pending, false)?;
            if Snapshot::opened(&pending)? != *expected {
                return Err(invalid("completion manifest changed before publication"));
            }
            // A simple native filename with a NULL RootDirectory renames within
            // the opened file's directory. Path-based Win32 rename reopens that
            // directory for write access, conflicting with our retained guards.
            // Keep those guards and the pending-file handle throughout publication.
            let name: Vec<u16> = "manifest.json".encode_utf16().collect();
            let bytes = std::mem::size_of::<FILE_RENAME_INFORMATION>() + name.len() * 2;
            // usize storage supplies the alignment required by the native struct.
            let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
            let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            let mut status_block = IO_STATUS_BLOCK::default();
            // SAFETY: the zeroed, aligned buffer contains the struct and full name;
            // zero means no replacement and no root handle. All buffers and the
            // synchronous file handle remain live until the system call returns.
            let status = unsafe {
                (*info).FileNameLength = (name.len() * 2) as u32;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                    name.len(),
                );
                NtSetInformationFile(
                    pending.as_raw_handle(),
                    &mut status_block,
                    info.cast(),
                    bytes as u32,
                    FileRenameInformation,
                )
            };
            if status < 0 {
                // SAFETY: accepts any NTSTATUS; does not access caller memory.
                let code = unsafe { RtlNtStatusToDosError(status) };
                return Err(std::io::Error::from_raw_os_error(code as i32).into());
            }
        }
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
        {
            rustix::fs::linkat(
                &self.file,
                ".manifest.pending",
                &self.file,
                "manifest.json",
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
            // Completion is committed; pending-file cleanup cannot change success.
            let _ = rustix::fs::unlinkat(
                &self.file,
                ".manifest.pending",
                rustix::fs::AtFlags::empty(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use std::io::Write;

    fn pending(root: &Root) -> Snapshot {
        let mut file = root.create_file(".manifest.pending").unwrap();
        file.write_all(b"synthetic completion").unwrap();
        Snapshot::opened(&file).unwrap()
    }

    #[test]
    fn publication_rejects_changed_pending_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::open(&temp.path().canonicalize().unwrap()).unwrap();
        let stamp = pending(&root);
        std::fs::write(temp.path().join(".manifest.pending"), b"changed").unwrap();
        assert!(root.publish_manifest(&stamp).is_err());
        assert!(!temp.path().join("manifest.json").exists());
    }

    #[cfg(windows)]
    #[test]
    fn publication_retains_directory_guards_and_never_replaces() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        for collision in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = Root::open(&temp.path().canonicalize().unwrap()).unwrap();
            let stamp = pending(&root);
            let destination = temp.path().join("manifest.json");
            if collision {
                std::fs::write(&destination, b"existing").unwrap();
            }
            let try_write_directory = || {
                std::fs::OpenOptions::new()
                    .access_mode(FILE_WRITE_DATA)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(temp.path())
            };
            assert_eq!(try_write_directory().unwrap_err().raw_os_error(), Some(32));
            let result = root.publish_manifest(&stamp);
            assert_eq!(result.is_err(), collision, "{result:?}");
            assert_eq!(try_write_directory().unwrap_err().raw_os_error(), Some(32));
            assert_eq!(
                std::fs::read(destination).unwrap(),
                if collision {
                    &b"existing"[..]
                } else {
                    &b"synthetic completion"[..]
                }
            );
            assert_eq!(temp.path().join(".manifest.pending").exists(), collision);
            drop(root);
            // Establish that the denied write was caused by the guard, not ACLs.
            assert!(try_write_directory().is_ok());
        }
    }
}
