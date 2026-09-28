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
