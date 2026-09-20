//
// VULNEX -BinSith-
//
// File: discovery.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use binsith::{
    batch::{
        discovery::{Discovery, DiscoveryEvent, SkipReason},
        input::Candidate,
        roots::{resolve_roots, ResolvedRoots},
    },
    scanner::CancellationToken,
};
use std::{fs, io::Read, path::PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, ResolvedRoots) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    let roots = resolve_roots(&base.join("input"), &base.join("input/reports")).unwrap();
    (temp, base, roots)
}
fn candidate(roots: &ResolvedRoots) -> Candidate {
    Discovery::new(roots, false, CancellationToken::default())
        .unwrap()
        .find_map(|event| match event {
            DiscoveryEvent::File(file) => Some(file),
            DiscoveryEvent::Error { error, .. } => panic!("{error}"),
            _ => None,
        })
        .unwrap()
}

#[test]
fn empty_and_policy_only_discovery_complete_without_admission() {
    let (_temp, _base, roots) = fixture();
    let mut empty = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
    assert!(!empty.discovery_complete());
    assert!(empty.next().is_none());
    assert!(empty.discovery_complete());
    assert!(empty.next().is_none());
    fs::create_dir(roots.input().join("child")).unwrap();
    let mut skipped = Discovery::new(&roots, false, CancellationToken::default()).unwrap();
    assert!(matches!(
        skipped.next(),
        Some(DiscoveryEvent::Skipped {
            reason: SkipReason::Subdirectory,
            ..
        })
    ));
    assert!(skipped.next().is_none());
    assert!(skipped.discovery_complete());
}

#[test]
fn recursion_includes_hidden_hardlinked_files_and_excludes_output_tree() {
    let (_temp, _base, roots) = fixture();
    fs::write(roots.input().join(".hidden"), b"hello").unwrap();
    fs::hard_link(
        roots.input().join(".hidden"),
        roots.input().join("hardlink"),
    )
    .unwrap();
    fs::create_dir(roots.input().join("child")).unwrap();
    fs::write(roots.input().join("child/sample"), b"hello").unwrap();
    fs::create_dir_all(roots.output().join("deep")).unwrap();
    fs::write(roots.output().join("deep/report.json"), b"never scan me").unwrap();
    for recursive in [false, true] {
        let mut discovery =
            Discovery::new(&roots, recursive, CancellationToken::default()).unwrap();
        let mut names = Vec::new();
        let mut excluded = 0;
        for event in &mut discovery {
            match event {
                DiscoveryEvent::File(file) => {
                    let mut opened = file.open().unwrap();
                    let mut bytes = Vec::new();
                    opened
                        .selected(0, None)
                        .unwrap()
                        .read_to_end(&mut bytes)
                        .unwrap();
                    assert_eq!(bytes, b"hello");
                    opened.verify_unchanged().unwrap();
                    names.push(file.relative_path().to_path_buf());
                }
                DiscoveryEvent::Skipped {
                    reason: SkipReason::OutputTree,
                    ..
                } => excluded += 1,
                DiscoveryEvent::Skipped {
                    reason: SkipReason::Subdirectory,
                    ..
                } if !recursive => {}
                event => panic!("unexpected {event:?}"),
            }
        }
        names.sort();
        let mut expected = vec![PathBuf::from(".hidden"), PathBuf::from("hardlink")];
        if recursive {
            expected.push(PathBuf::from("child/sample"));
        }
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(excluded, 1);
        assert!(discovery.discovery_complete());
    }
}

#[test]
fn selection_rejects_past_eof_and_handles_empty_and_clamped_ranges() {
    let (_temp, _base, roots) = fixture();
    fs::write(roots.input().join("sample"), b"abcdef").unwrap();
    let candidate = candidate(&roots);
    let mut opened = candidate.open().unwrap();
    assert!(opened.selected(7, None).is_err());
    assert!(opened.selected(1, Some(u64::MAX)).is_err());
    for (offset, length, expected) in [
        (6, None, &b""[..]),
        (2, Some(0), &b""[..]),
        (2, Some(2), &b"cd"[..]),
        (2, Some(100), &b"cdef"[..]),
    ] {
        let mut bytes = Vec::new();
        opened
            .selected(offset, length)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, expected);
        opened.verify_unchanged().unwrap();
    }
}

#[test]
fn deletion_and_identity_substitution_before_open_are_rejected() {
    let (_temp, base, roots) = fixture();
    let path = roots.input().join("sample");
    fs::write(&path, b"original").unwrap();
    let found = candidate(&roots);
    fs::rename(&path, base.join("original")).unwrap();
    assert!(found.open().is_err());
    fs::write(&path, b"original").unwrap(); // Same bytes/length, different identity.
    assert_eq!(found.open().err().unwrap().to_string(), "file_changed");
}

#[test]
fn mutation_before_open_or_during_scan_never_passes_verification() {
    let (_temp, _base, roots) = fixture();
    let path = roots.input().join("sample");
    fs::write(&path, b"original").unwrap();
    let found = candidate(&roots);
    fs::write(&path, b"modified and longer").unwrap();
    assert_eq!(found.open().err().unwrap().to_string(), "file_changed");
    let mut opened = candidate(&roots).open().unwrap();
    let mut bytes = Vec::new();
    opened
        .selected(0, None)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    fs::write(&path, b"changed after reading").unwrap();
    assert_eq!(
        opened.verify_unchanged().unwrap_err().to_string(),
        "file_changed"
    );
}

#[test]
fn path_replacement_after_open_is_detected_even_if_original_handle_is_unchanged() {
    let (_temp, base, roots) = fixture();
    let path = roots.input().join("sample");
    fs::write(&path, b"original").unwrap();
    let opened = candidate(&roots).open().unwrap();
    fs::rename(&path, base.join("original")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert_eq!(
        opened.verify_unchanged().unwrap_err().to_string(),
        "file_changed"
    );
}

#[test]
fn cancellation_and_explicit_stop_do_not_claim_completed_discovery() {
    let (_temp, _base, roots) = fixture();
    fs::write(roots.input().join("sample"), b"x").unwrap();
    let token = CancellationToken::default();
    let mut discovery = Discovery::new(&roots, true, token.clone()).unwrap();
    token.cancel();
    assert!(discovery.next().is_none());
    assert!(!discovery.discovery_complete());
    let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
    assert!(discovery.next().is_some());
    discovery.stop();
    assert!(discovery.next().is_none());
    assert!(!discovery.discovery_complete());
}

#[test]
fn wide_and_deep_traversal_visits_every_file() {
    let (_temp, _base, roots) = fixture();
    for n in 0..200 {
        let dir = roots.input().join(format!("wide-{n}"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("sample"), b"x").unwrap();
    }
    let mut deep = roots.input().to_path_buf();
    for _ in 0..48 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    fs::write(deep.join("bottom"), b"x").unwrap();
    let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
    let count = discovery
        .by_ref()
        .map(|event| match event {
            DiscoveryEvent::File(_) => 1,
            event => panic!("unexpected {event:?}"),
        })
        .sum::<usize>();
    assert_eq!(count, 201);
    assert!(discovery.discovery_complete());
}

#[cfg(unix)]
#[test]
fn symlinks_sockets_and_fifos_are_skipped_and_substitutions_never_open_targets() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let (_temp, base, roots) = fixture();
    fs::write(base.join("target"), b"secret").unwrap();
    symlink(base.join("target"), roots.input().join("link")).unwrap();
    symlink(&base, roots.input().join("dir-link")).unwrap();
    symlink(base.join("missing"), roots.input().join("dangling")).unwrap();
    let _socket = UnixListener::bind(roots.input().join("socket")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(roots.input().join("fifo"))
        .status()
        .unwrap()
        .success());
    let events: Vec<_> = Discovery::new(&roots, true, CancellationToken::default())
        .unwrap()
        .collect();
    assert_eq!(events.len(), 5);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                DiscoveryEvent::Skipped {
                    reason: SkipReason::Link,
                    ..
                }
            ))
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                DiscoveryEvent::Skipped {
                    reason: SkipReason::SpecialFile,
                    ..
                }
            ))
            .count(),
        2
    );
    let sample = roots.input().join("sample");
    fs::write(&sample, b"original").unwrap();
    let found = candidate(&roots);
    fs::remove_file(&sample).unwrap();
    symlink(base.join("target"), &sample).unwrap();
    assert!(found.open().is_err());
    fs::remove_file(&sample).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&sample)
        .status()
        .unwrap()
        .success());
    // A regression that removes O_NONBLOCK must fail by timeout, not hang the suite.
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(found.open().is_err()).unwrap();
    });
    assert!(receive
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("FIFO open blocked"));
    worker.join().unwrap();
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS volume rejects non-UTF-8 names; execute on Linux"
)]
fn native_names_survive_disk_queue_and_keep_distinct_report_ids() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let (_temp, _base, roots) = fixture();
    let name = OsString::from_vec(b"dir\xff".to_vec());
    fs::create_dir(roots.input().join(&name)).unwrap();
    let paths = [
        PathBuf::from(&name).join(OsString::from_vec(b"file\xfe".to_vec())),
        PathBuf::from(&name).join("file�"),
    ];
    for path in &paths {
        fs::write(roots.input().join(path), b"data").unwrap();
    }
    let files: Vec<_> = Discovery::new(&roots, true, CancellationToken::default())
        .unwrap()
        .map(|event| match event {
            DiscoveryEvent::File(file) => file,
            event => panic!("unexpected {event:?}"),
        })
        .collect();
    assert_eq!(files.len(), 2);
    for path in &paths {
        assert!(files.iter().any(|f| f.relative_path() == path));
    }
    assert_ne!(
        files[0].record_path().unwrap().report_id(),
        files[1].record_path().unwrap().report_id()
    );
}

#[test]
fn creation_after_discovery_construction_is_observed_and_control_names_stay_native() {
    let (_temp, _base, roots) = fixture();
    let mut discovery = Discovery::new(&roots, true, CancellationToken::default()).unwrap();
    // Windows forbids control characters in ordinary filesystem names.
    let name = if cfg!(windows) {
        "created-later"
    } else {
        "created\n\u{1b}[31m"
    };
    fs::write(roots.input().join(name), b"later").unwrap();
    let Some(DiscoveryEvent::File(file)) = discovery.next() else {
        panic!("new entry not observed");
    };
    assert_eq!(file.relative_path(), std::path::Path::new(name));
    assert!(file.record_path().is_ok());
    assert!(discovery.next().is_none());
    assert!(discovery.discovery_complete());
}
