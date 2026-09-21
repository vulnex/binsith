//! Native Windows sharing contracts; compiled elsewhere, executed on Windows CI.
#![cfg(windows)]
use binsith::{
    batch::{
        discovery::{Discovery, DiscoveryEvent},
        roots::resolve_roots,
    },
    scanner::CancellationToken,
};
use std::{fs, os::windows::fs::OpenOptionsExt};

#[test]
fn exclusive_open_after_admission_is_a_file_error_and_can_be_retried_after_release() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let input = root.join("input");
    fs::create_dir(&input).unwrap();
    let path = input.join("sample");
    fs::write(&path, b"original").unwrap();
    let roots = resolve_roots(&input, &root.join("output")).unwrap();
    let candidate = Discovery::new(&roots, false, CancellationToken::default())
        .unwrap()
        .find_map(|event| match event {
            DiscoveryEvent::File(file) => Some(file),
            _ => None,
        })
        .unwrap();
    let exclusive = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    assert!(
        candidate.open().is_err(),
        "sharing violation must not become success"
    );
    drop(exclusive);
    assert!(
        candidate.open().is_ok(),
        "the failed open must not leak an incompatible handle"
    );
}

#[test]
fn unpaired_utf16_files_keep_distinct_journal_identities() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let input = root.join("input");
    fs::create_dir(&input).unwrap();
    let names = [
        OsString::from_wide(&[b'f' as u16, 0xd800]),
        OsString::from_wide(&[b'f' as u16, 0xfffd]),
    ];
    for name in &names {
        fs::write(input.join(name), b"data").unwrap();
    }
    let roots = resolve_roots(&input, &root.join("output")).unwrap();
    let files: Vec<_> = Discovery::new(&roots, true, CancellationToken::default())
        .unwrap()
        .map(|event| match event {
            DiscoveryEvent::File(file) => file,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(files.len(), 2);
    for name in names {
        assert!(files
            .iter()
            .any(|file| file.relative_path() == std::path::Path::new(&name)));
    }
    assert_ne!(
        files[0].record_path().unwrap().report_id(),
        files[1].record_path().unwrap().report_id()
    );
}
