//
// VULNEX -BinSith-
//
// File: batch_cli_tests.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::Args;
use binsith::batch::cli::{FolderConfiguration, FolderOptions, InputKind, ProgressMode};
use clap::{CommandFactory, FromArgMatches};

fn resolve(
    arguments: &[&str],
    kind: InputKind,
    cpu: usize,
    tty: bool,
) -> Result<Option<FolderConfiguration>, String> {
    // Exercise the public grammar and its explicit-versus-default option values.
    let command = Args::command();
    let matches = command
        .try_get_matches_from(arguments)
        .map_err(|e| e.to_string())?;
    let args = Args::from_arg_matches(&matches).map_err(|e| e.to_string())?;
    let folder = FolderOptions::from_arg_matches(&matches).map_err(|e| e.to_string())?;
    folder.resolve(&matches, kind, cpu, tty, args.quiet)
}

#[test]
fn folder_contract_accepts_analysis_matrix_and_requires_destination() {
    for flags in [
        vec![],
        vec!["-s"],
        vec!["-S", "-D"],
        vec!["-i", "-s", "--scan-utf16"],
        vec![
            "--encoding",
            "utf16be",
            "--category",
            "URL,IPv4",
            "--patterns",
            "patterns.toml",
        ],
        vec!["--offset", "0x10", "--length", "0", "--min-length", "8"],
        vec![
            "--entropy",
            "--entropy-window",
            "8192",
            "--entropy-threshold",
            "7.5",
        ],
        vec![
            "--max-string-bytes",
            "4",
            "--max-decode-bytes",
            "0",
            "--decode-depth",
            "0",
        ],
        vec!["--recursive", "--fail-fast", "--jobs", "2"],
    ] {
        let mut argv = vec!["binsith", "samples", "--output-dir", "reports"];
        argv.extend(flags);
        assert!(
            resolve(&argv, InputKind::Directory, 8, false)
                .unwrap()
                .is_some(),
            "{argv:?}"
        );
    }
    assert!(resolve(&["binsith", "samples"], InputKind::Directory, 4, false).is_err());
    assert!(resolve(
        &["binsith", "samples", "--output-dir", ""],
        InputKind::Directory,
        4,
        false
    )
    .is_err());
}

#[test]
fn explicit_unsupported_options_are_rejected_even_when_equal_to_defaults() {
    for flags in [
        vec!["-j", "report.json"],
        vec!["--jsonl"],
        vec!["--live-jsonl"],
        vec!["--export-indicators", "ioc.json"],
        vec!["--export-format", "json"],
        vec!["--export-validation", "all"],
        vec!["--compare", "other.bin"],
        vec!["-x"],
        vec!["--match-exit-code", "0"],
        vec!["--no-match-exit-code", "0"],
        vec!["--inconclusive-exit-code", "0"],
    ] {
        let mut argv = vec!["binsith", "samples", "--output-dir", "reports"];
        argv.extend(flags);
        assert!(
            resolve(&argv, InputKind::Directory, 8, false).is_err(),
            "{argv:?}"
        );
    }
    // Implicit clap defaults must not be mistaken for explicit user selections.
    assert!(resolve(
        &["binsith", "samples", "--output-dir", "reports"],
        InputKind::Directory,
        8,
        false
    )
    .is_ok());
}

#[test]
fn folder_flags_are_rejected_for_files_stdin_and_category_listing() {
    for (input, kind) in [
        ("file.bin", InputKind::File),
        ("-", InputKind::Stdin),
        ("--list-categories", InputKind::CategoryListing),
    ] {
        assert!(resolve(&["binsith", input], kind, 4, false)
            .unwrap()
            .is_none());
        for flags in [
            vec!["--recursive"],
            vec!["--jobs", "1"],
            vec!["--output-dir", "reports"],
            vec!["--progress"],
            vec!["--fail-fast"],
            vec!["--include", "*"],
            vec!["--exclude", "cache/"],
            vec!["--max-depth", "0"],
            vec!["--max-file-bytes", "0"],
        ] {
            let mut argv = vec!["binsith", input];
            argv.extend(flags);
            assert!(resolve(&argv, kind, 4, false).is_err(), "{argv:?}");
        }
    }
}

#[test]
fn workers_are_positive_cpu_capped_and_queue_arithmetic_is_checked() {
    let argv = ["binsith", "samples", "--output-dir", "reports"];
    for (cpu, expected) in [(0, 1), (1, 1), (2, 2), (100, 4)] {
        let config = resolve(&argv, InputKind::Directory, cpu, false)
            .unwrap()
            .unwrap();
        assert_eq!(config.jobs, expected);
        assert_eq!(config.work_queue_capacity, expected * 2);
    }
    let huge = usize::MAX.to_string();
    for value in ["0", "-1", "no", huge.as_str()] {
        let mut args = argv.to_vec();
        args.extend(["--jobs", value]);
        assert!(resolve(&args, InputKind::Directory, 4, false).is_err());
    }
    let config = resolve(
        &[
            "binsith",
            "samples",
            "--output-dir",
            "reports",
            "--jobs",
            "8",
        ],
        InputKind::Directory,
        2,
        false,
    )
    .unwrap()
    .unwrap();
    assert_eq!(config.jobs, 8); // Explicit choices are not capped at the default.
}

#[test]
fn quiet_progress_and_redirected_stderr_have_explicit_precedence() {
    for tty in [false, true] {
        for quiet in [false, true] {
            for progress in [false, true] {
                let mut argv = vec!["binsith", "samples", "--output-dir", "reports"];
                if quiet {
                    argv.push("-q");
                }
                if progress {
                    argv.push("--progress");
                }
                let config = resolve(&argv, InputKind::Directory, 4, tty)
                    .unwrap()
                    .unwrap();
                let expected = match (tty, quiet, progress) {
                    (true, false, _) | (true, _, true) => ProgressMode::Interactive,
                    (false, _, true) => ProgressMode::Plain,
                    _ => ProgressMode::Disabled,
                };
                assert_eq!(config.progress, expected);
                assert_eq!(config.human_summary, !quiet);
            }
        }
    }
}

use binsith::batch::preflight::{
    self, PreparedBatch, SetupBackend, SetupContext, SetupError, SetupResult, SetupStage,
};
use binsith::batch::{pattern_fingerprint, BatchConfiguration};
use std::{cell::Cell, path::Path, rc::Rc};

struct Claim(Rc<Cell<usize>>);
impl Drop for Claim {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
#[derive(Default)]
struct Backend {
    calls: Vec<SetupStage>,
    fail: Option<SetupStage>,
    live_claims: Rc<Cell<usize>>,
}
impl Backend {
    fn stage(&mut self, stage: SetupStage) -> SetupResult<()> {
        self.calls.push(stage);
        if self.fail == Some(stage) {
            Err("injected setup failure".into())
        } else {
            Ok(())
        }
    }
}
impl SetupBackend for Backend {
    type Roots = (std::path::PathBuf, std::path::PathBuf);
    type Output = Claim;
    type Ready = Claim;
    fn load_patterns(&mut self, path: Option<&str>) -> SetupResult<Vec<(String, regex::Regex)>> {
        self.stage(SetupStage::Patterns)?;
        super::string_analysis::load_patterns(path)
    }
    fn resolve_roots(&mut self, input: &Path, output: &Path) -> SetupResult<Self::Roots> {
        self.stage(SetupStage::Roots)?;
        Ok((input.to_owned(), output.to_owned()))
    }
    fn claim_output(&mut self, _: Self::Roots) -> SetupResult<Self::Output> {
        self.stage(SetupStage::Output)?;
        self.live_claims.set(self.live_claims.get() + 1);
        Ok(Claim(self.live_claims.clone()))
    }
    fn initialize(
        &mut self,
        output: Self::Output,
        config: &BatchConfiguration,
    ) -> SetupResult<Self::Ready> {
        self.stage(SetupStage::Initialize)?;
        config.analysis.validate()?;
        Ok(output)
    }
}

fn prepare_test(
    arguments: &[&str],
    kind: InputKind,
    backend: &mut Backend,
) -> Result<Option<PreparedBatch<Claim>>, SetupError> {
    let matches = Args::command().try_get_matches_from(arguments).unwrap();
    let options = FolderOptions::from_arg_matches(&matches).unwrap();
    preflight::prepare(
        &options,
        &matches,
        SetupContext {
            input: Path::new("samples"),
            input_kind: kind,
            available_parallelism: 4,
            stderr_is_terminal: false,
        },
        backend,
    )
}

#[test]
fn preflight_orders_setup_and_transfers_output_ownership_only_on_success() {
    let mut backend = Backend::default();
    let prepared = prepare_test(
        &[
            "binsith",
            "samples",
            "--output-dir",
            "reports",
            "--category",
            "URL,URL",
        ],
        InputKind::Directory,
        &mut backend,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        backend.calls,
        [
            SetupStage::Patterns,
            SetupStage::Roots,
            SetupStage::Output,
            SetupStage::Initialize
        ]
    );
    assert_eq!(backend.live_claims.get(), 1);
    assert!(prepared.configuration.analysis.strings);
    assert!(prepared.configuration.analysis.matches_only);
    assert_eq!(prepared.configuration.analysis.categories, ["URL"]);
    assert_eq!(prepared.patterns.len(), 1);
    assert_eq!(
        prepared.configuration.patterns_sha256,
        pattern_fingerprint(
            prepared
                .patterns
                .iter()
                .map(|(n, r)| (n.as_str(), r.as_str()))
        )
    );
    drop(prepared);
    assert_eq!(backend.live_claims.get(), 0);
}

#[test]
fn preflight_stops_at_each_failure_and_drops_partial_output_claims() {
    let stages = [
        SetupStage::Patterns,
        SetupStage::Roots,
        SetupStage::Output,
        SetupStage::Initialize,
    ];
    for (index, stage) in stages.iter().enumerate() {
        let mut backend = Backend {
            fail: Some(*stage),
            ..Default::default()
        };
        let result = prepare_test(
            &["binsith", "samples", "--output-dir", "reports"],
            InputKind::Directory,
            &mut backend,
        );
        let error = result.err().expect("one global setup error");
        assert_eq!(error.stage, *stage);
        assert_eq!(error.exit_status().code(), 2);
        assert_eq!(backend.calls, stages[..=index]);
        assert_eq!(backend.live_claims.get(), 0);
    }
}

#[test]
fn invalid_global_options_fail_before_pattern_io_or_output_claims() {
    for flags in [
        vec!["--entropy-threshold", "NaN"],
        vec!["--entropy-threshold", "9"],
        vec!["--offset", "18446744073709551615", "--length", "1"],
        vec!["--jobs", "0"],
        vec!["--match-exit-code", "0"],
    ] {
        let mut argv = vec!["binsith", "samples", "--output-dir", "reports"];
        argv.extend(flags);
        let mut backend = Backend::default();
        let error = prepare_test(&argv, InputKind::Directory, &mut backend)
            .err()
            .unwrap();
        assert_eq!(error.stage, SetupStage::Options, "{argv:?}");
        assert_eq!(error.exit_status().code(), 2);
        assert!(backend.calls.is_empty());
    }
    let mut backend = Backend::default();
    assert!(prepare_test(&["binsith", "samples"], InputKind::Directory, &mut backend).is_err());
    assert!(backend.calls.is_empty());
}

#[test]
fn invalid_patterns_and_unknown_categories_fail_once_before_root_or_output_work() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("patterns.toml");
    for contents in ["broken toml", "bad = '['"] {
        std::fs::write(&path, contents).unwrap();
        let mut backend = Backend::default();
        let error = prepare_test(
            &[
                "binsith",
                "samples",
                "--output-dir",
                "reports",
                "--patterns",
                path.to_str().unwrap(),
            ],
            InputKind::Directory,
            &mut backend,
        )
        .err()
        .unwrap();
        assert_eq!(error.stage, SetupStage::Patterns);
        assert_eq!(backend.calls, [SetupStage::Patterns]);
        assert_eq!(error.exit_status().code(), 2);
    }
    let mut backend = Backend::default();
    let error = prepare_test(
        &[
            "binsith",
            "samples",
            "--output-dir",
            "reports",
            "--category",
            "not-a-category",
        ],
        InputKind::Directory,
        &mut backend,
    )
    .err()
    .unwrap();
    assert_eq!(error.stage, SetupStage::Patterns);
    assert!(error.to_string().contains("unknown category"));
    assert_eq!(backend.calls, [SetupStage::Patterns]);
}

#[test]
fn normalized_configuration_preserves_existing_analysis_selection_rules() {
    for flags in [
        vec![],
        vec!["-s"],
        vec!["-S"],
        vec!["--encoding", "auto"],
        vec!["--encoding", "utf16le"],
        vec!["--scan-utf16"],
        vec!["--category", "URL"],
        vec!["--entropy"],
        vec!["-D", "--decode-depth", "0"],
    ] {
        let mut argv = vec!["binsith", "samples", "--output-dir", "reports"];
        argv.extend(flags);
        let matches = Args::command().try_get_matches_from(&argv).unwrap();
        let args = Args::from_arg_matches(&matches).unwrap();
        let config = preflight::analysis_configuration(&matches).unwrap();
        assert_eq!(
            config.strings,
            args.strings
                || args.matches_only
                || args.encoding.is_some()
                || args.scan_utf16
                || !args.categories.is_empty()
        );
        assert_eq!(
            config.matches_only,
            args.matches_only || !args.categories.is_empty()
        );
        assert_eq!(config.no_decode, args.no_decode);
        assert_eq!(config.decode_depth, args.decode_depth);
    }
    let mut backend = Backend::default();
    assert!(
        prepare_test(&["binsith", "sample.bin"], InputKind::File, &mut backend)
            .unwrap()
            .is_none()
    );
    assert!(backend.calls.is_empty());
}

fn inspect_test(
    arguments: &[&str],
    input: Option<&Path>,
) -> Result<Option<preflight::FrozenBatch>, SetupError> {
    let matches = Args::command().try_get_matches_from(arguments).unwrap();
    let options = FolderOptions::from_arg_matches(&matches).unwrap();
    preflight::inspect(&options, &matches, input, 8, false)
}

#[test]
fn concrete_preflight_freezes_patterns_and_options_before_filesystem_setup() {
    let temp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(temp.path()).unwrap();
    let input = base.join("samples");
    let output = input.join("reports");
    let patterns = base.join("patterns.toml");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(&patterns, "URL = 'https?://[^ ]+'\nUnused = 'unused'").unwrap();
    let frozen = inspect_test(
        &[
            "binsith",
            "samples",
            "--output-dir",
            output.to_str().unwrap(),
            "--patterns",
            patterns.to_str().unwrap(),
            "--category",
            "URL,URL",
            "--jobs",
            "3",
            "--offset",
            "0x10",
            "--length",
            "0",
            "--recursive",
        ],
        Some(&input),
    )
    .unwrap()
    .unwrap();
    // Removing the source cannot affect this batch or trigger later recompilation.
    std::fs::remove_file(patterns).unwrap();
    assert_eq!(frozen.patterns().len(), 1);
    assert!(frozen.patterns()[0].1.is_match("https://example.org"));
    let config = frozen.configuration();
    assert_eq!(config.jobs, 3);
    assert_eq!(config.work_queue_capacity, 6);
    assert!(config.recursive);
    assert_eq!(config.analysis.offset, 16);
    assert_eq!(config.analysis.length, Some(0));
    assert_eq!(config.analysis.categories, ["URL"]);
    assert_eq!(
        config.patterns_sha256,
        pattern_fingerprint(
            frozen
                .patterns()
                .iter()
                .map(|(n, r)| (n.as_str(), r.as_str()))
        )
    );
    assert_eq!(frozen.roots().input(), input);
    assert_eq!(frozen.roots().output(), output);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(input).unwrap().count(), 0);
    fn shareable<T: Send + Sync>() {}
    shareable::<preflight::FrozenBatch>();
}

#[test]
fn concrete_preflight_returns_stage_specific_errors_without_output_side_effects() {
    let temp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(temp.path()).unwrap();
    let input = base.join("samples");
    let output = base.join("out");
    let missing_patterns = base.join("missing.toml");
    std::fs::create_dir(&input).unwrap();
    for (flags, stage) in [
        (
            vec![
                "--jobs",
                "0",
                "--patterns",
                missing_patterns.to_str().unwrap(),
            ],
            SetupStage::Options,
        ),
        (
            vec!["--patterns", missing_patterns.to_str().unwrap()],
            SetupStage::Patterns,
        ),
        (vec!["--category", "unknown"], SetupStage::Patterns),
    ] {
        let mut args = vec![
            "binsith",
            "samples",
            "--output-dir",
            output.to_str().unwrap(),
        ];
        args.extend(flags);
        let error = inspect_test(&args, Some(&input)).err().unwrap();
        assert_eq!(error.stage, stage);
        assert_eq!(error.exit_status().code(), 2);
        assert!(!output.exists());
    }
    let error = inspect_test(
        &["binsith", "samples", "--output-dir", base.to_str().unwrap()],
        Some(&input),
    )
    .err()
    .unwrap();
    assert_eq!(error.stage, SetupStage::Roots);
    assert_eq!(error.exit_status().code(), 2);
    assert_eq!(std::fs::read_dir(input).unwrap().count(), 0);
}

#[test]
fn concrete_preflight_leaves_single_file_stdin_and_listing_to_existing_command() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("sample");
    std::fs::write(&input, b"data").unwrap();
    for (args, path) in [
        (
            vec!["binsith", "sample", "--patterns", "missing.toml"],
            Some(input.as_path()),
        ),
        (vec!["binsith", "-"], Some(Path::new("-"))),
        (vec!["binsith", "--list-categories"], None),
    ] {
        assert!(inspect_test(&args, path).unwrap().is_none());
        let mut invalid = args;
        invalid.push("--recursive");
        assert_eq!(
            inspect_test(&invalid, path).err().unwrap().stage,
            SetupStage::Options
        );
    }
}
