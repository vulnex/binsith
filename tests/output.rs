//
// VULNEX -BinSith-
//
// File: output.rs
// Author: Simon Roses Femerling
// Created: 2026-09-20
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use binsith::batch::{
    output::{OutputClaim, OutputCode, OutputStage},
    roots::{resolve_roots, ResolvedRoots},
    RelativePath,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};

fn fixture() -> (tempfile::TempDir, PathBuf, ResolvedRoots) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(base.join("input")).unwrap();
    let roots = resolve_roots(&base.join("input"), &base.join("output")).unwrap();
    (temp, base, roots)
}
fn relative(path: &str) -> RelativePath {
    RelativePath::from_relative(Path::new(path)).unwrap()
}
fn names(path: &Path) -> Vec<std::ffi::OsString> {
    fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect()
}

#[test]
fn new_and_existing_empty_destinations_are_claimed_and_released() {
    let (_temp, base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    assert!(roots.output().join(".binsith.lock").is_file());
    assert!(roots.output().join("results").is_dir());
    assert_eq!(
        OutputClaim::acquire(&roots).err().unwrap().code,
        OutputCode::BusyOrNonempty
    );
    drop(claim);
    assert!(names(roots.output()).is_empty());
    drop(OutputClaim::acquire(&roots).unwrap());
    let deep = resolve_roots(roots.input(), &base.join("new/parents/output")).unwrap();
    drop(OutputClaim::acquire(&deep).unwrap());
    assert!(names(deep.output()).is_empty());
}

#[test]
fn nonempty_and_stale_outputs_are_preserved() {
    for name in ["evidence", ".hidden", ".binsith.lock", "manifest.json"] {
        let (_temp, _base, roots) = fixture();
        fs::create_dir(roots.output()).unwrap();
        fs::write(roots.output().join(name), b"user-owned or incomplete").unwrap();
        let before = names(roots.output());
        assert_eq!(
            OutputClaim::acquire(&roots).err().unwrap().code,
            OutputCode::BusyOrNonempty
        );
        assert_eq!(names(roots.output()), before);
        assert_eq!(
            fs::read(roots.output().join(name)).unwrap(),
            b"user-owned or incomplete"
        );
    }
}

#[test]
fn simultaneous_claims_have_exactly_one_owner_and_loser_does_not_remove_it() {
    let (_temp, _base, roots) = fixture();
    let roots = Arc::new(roots);
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let roots = roots.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let result = OutputClaim::acquire(&roots);
                barrier.wait(); // Winner holds its claim while loser completes setup.
                let won = result.is_ok();
                if won {
                    assert!(roots.output().join(".binsith.lock").exists());
                } else {
                    assert_eq!(
                        result.as_ref().err().unwrap().code,
                        OutputCode::BusyOrNonempty
                    );
                }
                won
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| usize::from(w.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert!(names(roots.output()).is_empty());
}

#[test]
fn pending_reports_extend_claim_lifetime_and_cleanup_on_abandonment() {
    let (_temp, _base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let mut report = claim.begin_report(&relative("sample")).unwrap();
    report.write_all(b"partial report").unwrap();
    drop(claim);
    assert_eq!(
        OutputClaim::acquire(&roots).err().unwrap().code,
        OutputCode::BusyOrNonempty
    );
    drop(report);
    assert!(names(roots.output()).is_empty());
    drop(OutputClaim::acquire(&roots).unwrap());
}

#[test]
fn native_source_names_publish_to_distinct_stable_sharded_ids() {
    let (_temp, _base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let mut ids = std::collections::HashSet::new();
    for source in [
        "a",
        "a.json/b",
        "first/same",
        "second/same",
        "A",
        "é",
        "e\u{301}",
    ] {
        let path = relative(source);
        let mut report = claim.begin_report(&path).unwrap();
        let destination = roots.output().join(path.report_location());
        let bytes =
            serde_json::to_vec(&serde_json::json!({"source": source, "complete": true})).unwrap();
        report.write_all(&bytes[..bytes.len() / 2]).unwrap();
        assert!(!destination.exists());
        report.write_all(&bytes[bytes.len() / 2..]).unwrap();
        let published = report
            .publish(|| {
                assert!(!destination.exists());
                Ok(())
            })
            .unwrap();
        assert_eq!(published.report_id(), path.report_id());
        assert_eq!(published.location(), path.report_location());
        assert!(ids.insert(published.report_id().to_owned()));
        assert_eq!(fs::read(destination).unwrap(), bytes);
    }
    drop(claim);
    assert!(!roots.output().join(".binsith.lock").exists());
    assert_eq!(
        OutputClaim::acquire(&roots).err().unwrap().code,
        OutputCode::BusyOrNonempty
    );
}

#[test]
fn concurrent_duplicate_publication_has_one_winner_without_overwrite() {
    let (_temp, _base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let path = relative("duplicate");
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [b"first".to_vec(), b"second".to_vec()]
        .into_iter()
        .map(|bytes| {
            let mut report = claim.begin_report(&path).unwrap();
            report.write_all(&bytes).unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (report.publish(|| Ok(())), bytes)
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(r, _)| r.is_ok()).count(), 1);
    let loser = results.iter().find(|(r, _)| r.is_err()).unwrap();
    assert_eq!(loser.0.as_ref().err().unwrap().code, OutputCode::Collision);
    let winner = results.iter().find(|(r, _)| r.is_ok()).unwrap();
    let destination = roots.output().join(path.report_location());
    assert_eq!(fs::read(&destination).unwrap(), winner.1);
    assert_eq!(names(destination.parent().unwrap()).len(), 1);
}

#[test]
fn failed_input_validation_discards_report_and_keeps_destination_unpublished() {
    let (_temp, _base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let path = relative("changed");
    let mut report = claim.begin_report(&path).unwrap();
    report.write_all(b"complete-looking but invalid").unwrap();
    let error = report
        .publish(|| Err(io::Error::new(io::ErrorKind::InvalidData, "file_changed")))
        .unwrap_err();
    assert_eq!(error.stage, OutputStage::ValidateInput);
    let destination = roots.output().join(path.report_location());
    assert!(!destination.exists());
    assert!(names(destination.parent().unwrap()).is_empty());
    drop(claim);
    assert!(names(roots.output()).is_empty());
}

#[cfg(unix)]
#[test]
fn unix_permissions_restrict_outputs_without_broadening_existing_ancestors() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, base, roots) = fixture();
    fs::create_dir(roots.output()).unwrap();
    fs::set_permissions(roots.output(), fs::Permissions::from_mode(0o750)).unwrap();
    let parent_mode = fs::metadata(&base).unwrap().permissions().mode();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let path = relative("sample");
    let mut report = claim.begin_report(&path).unwrap();
    report.write_all(b"private evidence").unwrap();
    let shard = roots.output().join("results").join(&path.report_id()[..2]);
    for entry in fs::read_dir(&shard).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    report.publish(|| Ok(())).unwrap();
    for dir in [
        roots.output().to_path_buf(),
        roots.output().join("results"),
        shard,
    ] {
        assert_eq!(
            fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(roots.output().join(path.report_location()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(base).unwrap().permissions().mode(),
        parent_mode
    );
}

#[cfg(unix)]
#[test]
fn replaced_shard_is_rejected_without_writing_through_its_link() {
    use std::os::unix::fs::symlink;
    let (_temp, base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    let path = relative("sample");
    let mut report = claim.begin_report(&path).unwrap();
    report.write_all(b"evidence").unwrap();
    let shard = roots.output().join("results").join(&path.report_id()[..2]);
    fs::rename(&shard, base.join("old-shard")).unwrap();
    let foreign = base.join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("keep"), b"untouched").unwrap();
    symlink(&foreign, &shard).unwrap();
    assert_eq!(
        report.publish(|| Ok(())).unwrap_err().code,
        OutputCode::UnsafePath
    );
    drop(claim);
    assert_eq!(names(&foreign), [std::ffi::OsString::from("keep")]);
    assert_eq!(fs::read(foreign.join("keep")).unwrap(), b"untouched");
}

#[test]
fn claim_subprocess_helper() {
    let Some(base) = std::env::var_os("BINSITH_TEST_OUTPUT_BASE") else {
        return;
    };
    let base = PathBuf::from(base);
    let roots = resolve_roots(&base.join("input"), &base.join("output")).unwrap();
    let claim = OutputClaim::acquire(&roots);
    if std::env::var("BINSITH_TEST_OUTPUT_EXPECT").unwrap() == "busy" {
        assert_eq!(claim.err().unwrap().code, OutputCode::BusyOrNonempty);
    } else {
        assert!(claim.is_ok());
    }
}

#[test]
fn ownership_is_exclusive_across_processes_and_reusable_after_release() {
    let (_temp, base, roots) = fixture();
    let claim = OutputClaim::acquire(&roots).unwrap();
    for (expect, held) in [("busy", Some(claim)), ("ready", None)] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "claim_subprocess_helper", "--nocapture"])
            .env("BINSITH_TEST_OUTPUT_BASE", &base)
            .env("BINSITH_TEST_OUTPUT_EXPECT", expect)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        drop(held);
    }
}
