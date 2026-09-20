//
// VULNEX -BinSith-
//
// File: batch/roots.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::cli::InputKind;
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

/// Validated absolute roots. This is not an output claim or a containment handle;
/// ownership must revalidate before creation (FS-10), and discovery must use safe
/// opened-handle checks (FS-09). Concurrent hostile ancestor mutation is excluded.
#[derive(Debug)]
pub struct ResolvedRoots {
    input: PathBuf,
    output: PathBuf,
}
impl ResolvedRoots {
    pub fn input(&self) -> &Path {
        &self.input
    }
    pub fn output(&self) -> &Path {
        &self.output
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(super) fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // All reparse points, including junctions, are outside the initial policy.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Classification does not enumerate input or open special files. Standalone
/// category listing and stdin do not inspect the filesystem. Single-file link
/// semantics remain with the existing single-file command.
pub fn classify_input(input: Option<&Path>, list_categories: bool) -> io::Result<InputKind> {
    if list_categories {
        return Ok(InputKind::CategoryListing);
    }
    let input = input.ok_or_else(|| invalid("missing input"))?;
    if input == Path::new("-") {
        return Ok(InputKind::Stdin);
    }
    // Follow only for mode detection. Directory links are rejected in resolution.
    let metadata = fs::metadata(input)?;
    if metadata.is_dir() {
        Ok(InputKind::Directory)
    } else {
        Ok(InputKind::File)
    }
}

/// Walk components before canonicalizing so a link followed by `..` cannot hide
/// an explicitly supplied linked component. The process cwd is the implicit base;
/// its canonical spelling avoids rejecting OS aliases outside the supplied path.
pub(super) fn directory_path(path: &Path, allow_missing: bool) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(invalid("empty root path"));
    }
    let mut resolved = if path.is_absolute() {
        PathBuf::new()
    } else {
        fs::canonicalize(std::env::current_dir()?)?
    };
    let mut missing = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                // Drive-relative paths depend on hidden per-drive cwd state.
                if !path.is_absolute() {
                    return Err(invalid("drive-relative root is unsupported"));
                }
                resolved.push(prefix.as_os_str());
            }
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if missing {
                    return Err(invalid("parent traversal through a missing directory"));
                }
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if missing {
                    continue;
                }
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) => {
                        if is_link(&metadata) {
                            return Err(invalid("root path contains a symlink or reparse point"));
                        }
                        if !metadata.is_dir() {
                            return Err(invalid("root path component is not a directory"));
                        }
                        resolved = fs::canonicalize(&resolved)?;
                    }
                    Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {
                        missing = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    // Covers roots without normal components (e.g. / or .).
    if !missing && !fs::metadata(&resolved)?.is_dir() {
        return Err(invalid("root is not a directory"));
    }
    Ok(resolved)
}

/// Resolve existing input and existing/new output without creating files or
/// enumerating input. Existing output aliases use the filesystem's canonical
/// spelling, including case normalization where supplied by the platform.
pub fn resolve_roots(input: &Path, output: &Path) -> io::Result<ResolvedRoots> {
    let input = directory_path(input, false)?;
    let output = directory_path(output, true)?;
    if input.starts_with(&output) {
        return Err(invalid(
            "output must not equal input or contain the input root",
        ));
    }
    Ok(ResolvedRoots { input, output })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let input = base.join("samples");
        fs::create_dir(&input).unwrap();
        (temp, base, input)
    }

    #[test]
    fn resolves_new_existing_and_nested_destinations_without_creating_them() {
        let (_temp, base, input) = fixture();
        fs::write(input.join("evidence"), b"unchanged").unwrap();
        let existing = base.join("existing");
        fs::create_dir(&existing).unwrap();
        for output in [base.join("new/deep"), input.join("reports/deep"), existing] {
            let existed = output.exists();
            let roots = resolve_roots(&input, &output).unwrap();
            assert_eq!(roots.input(), input);
            assert_eq!(roots.output(), output);
            assert_eq!(output.exists(), existed);
        }
        assert_eq!(fs::read(input.join("evidence")).unwrap(), b"unchanged");
        assert_eq!(fs::read_dir(input).unwrap().count(), 1);
    }

    #[test]
    fn rejects_aliases_ancestors_missing_inputs_and_file_components() {
        let (_temp, base, input) = fixture();
        fs::create_dir(input.join("child")).unwrap();
        fs::write(base.join("file"), b"keep").unwrap();
        for output in [
            input.clone(),
            base.clone(),
            input.join("child/.."),
            base.join("file"),
            base.join("file/child"),
            base.join("missing/../out"),
        ] {
            assert!(resolve_roots(&input, &output).is_err(), "{output:?}");
        }
        for bad_input in [base.join("absent"), base.join("file"), PathBuf::new()] {
            assert!(resolve_roots(&bad_input, &base.join("out")).is_err());
        }
        assert!(resolve_roots(&input, Path::new("")).is_err());
        assert!(!base.join("out").exists());
        assert_eq!(fs::read(base.join("file")).unwrap(), b"keep");
    }

    #[test]
    fn classification_bypasses_io_for_stdin_and_category_listing() {
        let (_temp, base, input) = fixture();
        fs::write(base.join("sample"), b"x").unwrap();
        assert_eq!(
            classify_input(Some(&input), false).unwrap(),
            InputKind::Directory
        );
        assert_eq!(
            classify_input(Some(&base.join("sample")), false).unwrap(),
            InputKind::File
        );
        assert_eq!(
            classify_input(Some(Path::new("-")), false).unwrap(),
            InputKind::Stdin
        );
        assert_eq!(
            classify_input(None, true).unwrap(),
            InputKind::CategoryListing
        );
        assert_eq!(
            classify_input(Some(&base.join("absent")), true).unwrap(),
            InputKind::CategoryListing
        );
        assert!(classify_input(None, false).is_err());
        assert!(classify_input(Some(&base.join("absent")), false).is_err());
    }

    #[test]
    fn resolves_relative_roots_and_component_boundaries() {
        // Create below cwd without changing process-wide cwd during parallel tests.
        let temp = tempfile::tempdir_in(".").unwrap();
        let absolute = fs::canonicalize(temp.path()).unwrap();
        let relative = absolute
            .strip_prefix(fs::canonicalize(std::env::current_dir().unwrap()).unwrap())
            .unwrap();
        fs::create_dir(absolute.join("samples")).unwrap();
        fs::create_dir(absolute.join("samples/child")).unwrap();
        let roots = resolve_roots(
            &relative.join("samples/child/.."),
            &relative.join("samples-other"),
        )
        .unwrap();
        assert_eq!(roots.input(), absolute.join("samples"));
        assert_eq!(roots.output(), absolute.join("samples-other"));
        assert!(!roots.output().exists());
    }

    #[test]
    fn rejects_existing_case_alias_on_case_insensitive_volumes() {
        let (_temp, base, input) = fixture();
        let alias = base.join("SAMPLES");
        if !alias.exists() {
            // Case-sensitive volumes: this is a distinct valid output.
            assert!(resolve_roots(&input, &alias).is_ok());
        } else {
            assert!(resolve_roots(&input, &alias).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_components_even_before_parent_traversal() {
        use std::os::unix::fs::symlink;
        let (_temp, base, input) = fixture();
        symlink(&input, base.join("alias")).unwrap();
        symlink(base.join("absent"), base.join("dangling")).unwrap();
        for root in [base.join("alias"), base.join("alias/../samples")] {
            assert_eq!(
                classify_input(Some(&root), false).unwrap(),
                InputKind::Directory
            );
            assert!(resolve_roots(&root, &base.join("out")).is_err());
        }
        for output in [
            base.join("alias/out"),
            base.join("alias/../out"),
            base.join("dangling/out"),
        ] {
            assert!(resolve_roots(&input, &output).is_err());
        }
        assert!(!base.join("out").exists());
        assert!(!input.join("out").exists());
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS volume rejects non-UTF-8 directory names; execute on Linux"
    )]
    fn preserves_native_non_utf8_roots() {
        use std::os::unix::ffi::OsStringExt;
        let (_temp, base, _) = fixture();
        let input = base.join(std::ffi::OsString::from_vec(b"samples\xff".to_vec()));
        let output = base.join(std::ffi::OsString::from_vec(b"reports\xfe".to_vec()));
        fs::create_dir(&input).unwrap();
        let roots = resolve_roots(&input, &output).unwrap();
        assert_eq!(roots.input(), input);
        assert_eq!(roots.output(), output);
    }
}
