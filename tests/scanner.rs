//
// VULNEX -BinSith-
//
// File: scanner.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use binsith::{
    batch::{AnalysisConfiguration, Manifest},
    scanner::{self, CancellationToken, ScanErrorKind, ScanRequest},
    string_analysis,
};
use std::{
    io::{self, Read, Write},
    process::Command,
};

fn configuration() -> AnalysisConfiguration {
    let manifest: Manifest =
        serde_json::from_str(include_str!("fixtures/batch/manifest-interrupted.json")).unwrap();
    manifest.configuration.analysis
}

#[test]
fn library_report_matches_cli_for_supported_modes_and_counts_source_bytes_once() {
    let temporary = tempfile::tempdir().unwrap();
    let sample = temporary.path().join("sample.bin");
    let bytes = b"prefix\0https://example.com/a\0aHR0cHM6Ly9leGFtcGxlLmNvbQ==\0h\0t\0t\0p\0:\0/\0/\0x\0.\0c\0o\0m\0\0";
    std::fs::write(&sample, bytes).unwrap();
    for mode in ["summary", "strings", "utf16", "entropy", "limited", "range"] {
        let mut config = configuration();
        let mut flags = vec![];
        match mode {
            "summary" => config.strings = false,
            "strings" => flags.extend(["-s"]),
            "utf16" => {
                config.scan_utf16 = true;
                flags.extend(["-s", "--scan-utf16"]);
            }
            "entropy" => {
                config.entropy = true;
                config.entropy_window = 8;
                flags.extend(["-s", "--entropy", "--entropy-window", "8"]);
            }
            "limited" => {
                config.max_string_bytes = 8;
                flags.extend(["-s", "--max-string-bytes", "8"]);
            }
            "range" => {
                config.offset = 7;
                config.length = Some(22);
                flags.extend(["-s", "--offset", "7", "--length", "22"]);
            }
            _ => unreachable!(),
        }
        // The non-quiet CLI retains its established orchestration; comparing it to
        // the library catches differences independently of the new quiet route.
        let cli_path = temporary.path().join(format!("{mode}.json"));
        let result = Command::new(env!("CARGO_BIN_EXE_binsith"))
            .arg(&sample)
            .args(flags)
            .arg("-j")
            .arg(&cli_path)
            .output()
            .unwrap();
        assert!(result.status.success(), "{mode}: {:?}", result.stderr);
        let mut reference: serde_json::Value =
            serde_json::from_slice(&std::fs::read(cli_path).unwrap()).unwrap();
        let patterns = if config.strings {
            string_analysis::load_patterns(None).unwrap()
        } else {
            vec![]
        };
        let metadata = reference["metadata"].clone();
        let request = ScanRequest {
            display_path: sample.to_str().unwrap(),
            configuration: &config,
            patterns: &patterns,
            metadata: &metadata,
        };
        let start = config.offset as usize;
        let end = bytes
            .len()
            .min(start + config.length.unwrap_or((bytes.len() - start) as u64) as usize);
        let mut output = Vec::new();
        let mut progress = Vec::new();
        let outcome = scanner::scan_selected(
            &bytes[start..end],
            &mut output,
            &request,
            &CancellationToken::default(),
            |n| progress.push(n),
        )
        .unwrap();
        let mut actual: serde_json::Value = serde_json::from_slice(&output).unwrap();
        // Arithmetic optimization across library/bin compilation can affect float
        // rounding at the last bit; canonical JSON parsing handles all other fields.
        assert!(
            (actual["file_summary"]["entropy"].as_f64().unwrap()
                - reference["file_summary"]["entropy"].as_f64().unwrap())
            .abs()
                < 1e-12
        );
        actual["file_summary"]["entropy"] = serde_json::Value::Null;
        reference["file_summary"]["entropy"] = serde_json::Value::Null;
        assert_eq!(actual, reference, "{mode}");
        assert_eq!(outcome.summary.size_bytes, (end - start) as u64);
        assert_eq!(progress.last(), Some(&((end - start) as u64)));
        assert!(progress.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(outcome.coverage.limited(), mode == "limited");
        assert_eq!(outcome.has_actionable_indicators.is_some(), config.strings);
    }
}

#[test]
fn cancellation_before_and_during_read_never_finishes_a_report() {
    let config = configuration();
    let request = ScanRequest {
        display_path: "memory",
        configuration: &config,
        patterns: &[],
        metadata: &serde_json::Value::Null,
    };
    for pre_cancelled in [false, true] {
        let token = CancellationToken::default();
        if pre_cancelled {
            token.cancel();
        }
        let mut output = Vec::new();
        let error =
            scanner::scan_selected(&b"hello world"[..], &mut output, &request, &token, |_| {
                token.cancel()
            })
            .err()
            .unwrap();
        assert_eq!(error.kind, ScanErrorKind::Cancelled);
        assert!(output.is_empty());
    }
}

struct BrokenInput;
impl Read for BrokenInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("input failure"))
    }
}
struct BrokenOutput {
    remaining: usize,
    flush_failure: bool,
}
impl Write for BrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "report failure"));
        }
        let count = bytes.len().min(self.remaining);
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_failure {
            Err(io::Error::other("flush failure"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn failures_preserve_stage_and_underlying_io_kind() {
    let config = configuration();
    let request = ScanRequest {
        display_path: "memory",
        configuration: &config,
        patterns: &[],
        metadata: &serde_json::Value::Null,
    };
    let token = CancellationToken::default();
    let error = scanner::scan_selected(BrokenInput, io::sink(), &request, &token, |_| {})
        .err()
        .unwrap();
    assert_eq!(error.kind, ScanErrorKind::Read);
    // Include failures during report initialization, findings, and final flush.
    for remaining in [0, 400, usize::MAX] {
        let output = BrokenOutput {
            remaining,
            flush_failure: remaining == usize::MAX,
        };
        let error = scanner::scan_selected(&b"hello world\0"[..], output, &request, &token, |_| {})
            .err()
            .unwrap();
        assert_eq!(error.kind, ScanErrorKind::Report);
        let expected = if remaining == usize::MAX {
            io::ErrorKind::Other
        } else {
            io::ErrorKind::BrokenPipe
        };
        assert_eq!(error.into_io_error().kind(), expected);
    }
}

#[test]
fn invalid_configuration_and_empty_input_have_explicit_outcomes() {
    let mut config = configuration();
    config.entropy_threshold = f64::NAN;
    let mut output = Vec::new();
    let token = CancellationToken::default();
    let request = ScanRequest {
        display_path: "memory",
        configuration: &config,
        patterns: &[],
        metadata: &serde_json::Value::Null,
    };
    let error = scanner::scan_selected(io::empty(), &mut output, &request, &token, |_| {})
        .err()
        .unwrap();
    assert_eq!(error.kind, ScanErrorKind::InvalidConfiguration);
    assert!(output.is_empty());
    config.entropy_threshold = 7.0;
    config.strings = false;
    let request = ScanRequest {
        display_path: "memory",
        configuration: &config,
        patterns: &[],
        metadata: &serde_json::Value::Null,
    };
    let outcome = scanner::scan_selected(io::empty(), &mut output, &request, &token, |_| {
        panic!("empty input has no consumed bytes")
    })
    .unwrap();
    assert_eq!(outcome.summary.size_bytes, 0);
    assert_eq!(outcome.has_actionable_indicators, None);
    assert!(!outcome.coverage.limited());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output).unwrap()["complete"],
        true
    );
}
