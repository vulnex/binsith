//
// VULNEX -BinSith-
//
// File: batch/preflight.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::cli::{FolderConfiguration, FolderOptions, InputKind};
use super::{pattern_fingerprint, AnalysisConfiguration, BatchConfiguration, ExitStatus};
use crate::string_analysis::LoadedPatterns;
use clap::ArgMatches;
use regex::Regex;
use std::{error::Error, fmt, path::Path};

pub type SetupResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    Options,
    Patterns,
    Roots,
    Output,
    Initialize,
}

#[derive(Debug)]
pub struct SetupError {
    pub stage: SetupStage,
    source: Box<dyn Error>,
}
impl SetupError {
    fn at(stage: SetupStage, source: impl Into<Box<dyn Error>>) -> Self {
        Self {
            stage,
            source: source.into(),
        }
    }
    pub fn exit_status(&self) -> ExitStatus {
        ExitStatus::SetupFailure
    }
}
impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.stage, self.source)
    }
}
impl Error for SetupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Root classification may inspect metadata but must not enumerate the directory.
pub struct SetupContext<'a> {
    pub input: &'a Path,
    pub input_kind: InputKind,
    pub available_parallelism: usize,
    pub stderr_is_terminal: bool,
}

/// Filesystem-specific implementations arrive in FS-08/FS-10/FS-11. Owned output
/// resources must release the claim and clean up owned temporary files on Drop,
/// including initialization failure. Do not delete pre-existing/user-owned data.
pub trait SetupBackend {
    type Roots;
    type Output;
    type Ready;
    fn load_patterns(&mut self, path: Option<&str>) -> SetupResult<Vec<(String, Regex)>>;
    fn resolve_roots(&mut self, input: &Path, output: &Path) -> SetupResult<Self::Roots>;
    fn claim_output(&mut self, roots: Self::Roots) -> SetupResult<Self::Output>;
    /// Initialize incomplete journals/manifest and the worker pool without starting
    /// discovery or scanning. Output ownership transfers into Ready on success.
    fn initialize(
        &mut self,
        output: Self::Output,
        config: &BatchConfiguration,
    ) -> SetupResult<Self::Ready>;
}

pub struct PreparedBatch<R> {
    pub folder: FolderConfiguration,
    pub configuration: BatchConfiguration,
    pub patterns: Vec<(String, Regex)>,
    pub resources: R,
}

/// All global setup errors are returned once, before any discovery is possible.
/// None means this is an unaffected single-file/stdin/category-list invocation.
pub fn prepare<B: SetupBackend>(
    folder: &FolderOptions,
    matches: &ArgMatches,
    context: SetupContext<'_>,
    backend: &mut B,
) -> Result<Option<PreparedBatch<B::Ready>>, SetupError> {
    let Some(validated) = validate_configuration(folder, matches, &context, |path, retain| {
        let compiled = backend.load_patterns(path)?;
        let definitions = compiled
            .iter()
            .map(|(name, regex)| (name.clone(), regex.as_str().to_owned()))
            .collect();
        Ok(LoadedPatterns {
            definitions,
            compiled: if retain { compiled } else { Vec::new() },
        })
    })?
    else {
        return Ok(None);
    };
    let ValidatedConfiguration {
        folder,
        configuration,
        patterns,
    } = validated;
    let roots = backend
        .resolve_roots(context.input, &folder.output_dir)
        .map_err(|e| SetupError::at(SetupStage::Roots, e))?;
    let output = backend
        .claim_output(roots)
        .map_err(|e| SetupError::at(SetupStage::Output, e))?;
    let resources = backend
        .initialize(output, &configuration)
        .map_err(|e| SetupError::at(SetupStage::Initialize, e))?;
    Ok(Some(PreparedBatch {
        folder,
        configuration,
        patterns,
        resources,
    }))
}

struct ValidatedConfiguration {
    folder: FolderConfiguration,
    configuration: BatchConfiguration,
    patterns: Vec<(String, Regex)>,
}

fn validate_configuration(
    folder: &FolderOptions,
    matches: &ArgMatches,
    context: &SetupContext<'_>,
    load_patterns: impl FnOnce(Option<&str>, bool) -> SetupResult<LoadedPatterns>,
) -> Result<Option<ValidatedConfiguration>, SetupError> {
    let quiet =
        value::<bool>(matches, "quiet").map_err(|e| SetupError::at(SetupStage::Options, e))?;
    let Some(folder) = folder
        .resolve(
            matches,
            context.input_kind,
            context.available_parallelism,
            context.stderr_is_terminal,
            quiet,
        )
        .map_err(|e| SetupError::at(SetupStage::Options, e))?
    else {
        return Ok(None);
    };
    let analysis =
        analysis_configuration(matches).map_err(|e| SetupError::at(SetupStage::Options, e))?;
    let pattern_path = matches
        .try_get_one::<String>("patterns")
        .map_err(|e| SetupError::at(SetupStage::Options, e.to_string()))?;
    let LoadedPatterns {
        mut definitions,
        mut compiled,
    } = load_patterns(pattern_path.map(String::as_str), analysis.strings)
        .map_err(|e| SetupError::at(SetupStage::Patterns, e))?;
    for category in &analysis.categories {
        if !definitions.contains_key(category) {
            return Err(SetupError::at(
                SetupStage::Patterns,
                format!("unknown category: {category}"),
            ));
        }
    }
    if !analysis.categories.is_empty() {
        definitions.retain(|name, _| analysis.categories.contains(name));
        compiled.retain(|(name, _)| analysis.categories.contains(name));
    }
    let configuration = BatchConfiguration {
        jobs: folder.jobs,
        work_queue_capacity: folder.work_queue_capacity,
        recursive: folder.recursive,
        fail_fast: folder.fail_fast,
        patterns_sha256: pattern_fingerprint(
            definitions
                .iter()
                .map(|(name, pattern)| (name.as_str(), pattern.as_str())),
        ),
        analysis,
    };
    Ok(Some(ValidatedConfiguration {
        folder,
        configuration,
        patterns: compiled,
    }))
}

/// Immutable preflight result, shareable with workers through Arc. No output has
/// been claimed, no manifest created, and no discovery started. Resource setup
/// must succeed before this can become an executable batch.
pub struct FrozenBatch {
    validated: ValidatedConfiguration,
    roots: super::roots::ResolvedRoots,
}
impl FrozenBatch {
    pub fn folder(&self) -> &FolderConfiguration {
        &self.validated.folder
    }
    pub fn configuration(&self) -> &BatchConfiguration {
        &self.validated.configuration
    }
    pub fn patterns(&self) -> &[(String, Regex)] {
        &self.validated.patterns
    }
    pub fn roots(&self) -> &super::roots::ResolvedRoots {
        &self.roots
    }
}

/// Concrete FS-08 preflight. Detect the mode using metadata only, reuse the real
/// option contract and pattern loader, then resolve native filesystem roots.
/// A single-file/stdin/category-listing request returns None without pattern I/O.
/// Called by the public CLI before claiming output or starting folder execution.
pub fn inspect(
    folder: &FolderOptions,
    matches: &ArgMatches,
    input: Option<&Path>,
    available_parallelism: usize,
    stderr_is_terminal: bool,
) -> Result<Option<FrozenBatch>, SetupError> {
    let listing = value::<bool>(matches, "list_categories")
        .map_err(|e| SetupError::at(SetupStage::Options, e))?;
    let input_kind = super::roots::classify_input(input, listing)
        .map_err(|e| SetupError::at(SetupStage::Roots, e))?;
    let context = SetupContext {
        input: input.unwrap_or_else(|| Path::new("")),
        input_kind,
        available_parallelism,
        stderr_is_terminal,
    };
    let Some(validated) = validate_configuration(
        folder,
        matches,
        &context,
        crate::string_analysis::load_pattern_configuration,
    )?
    else {
        return Ok(None);
    };
    let roots = super::roots::resolve_roots(context.input, &validated.folder.output_dir)
        .map_err(|e| SetupError::at(SetupStage::Roots, e))?;
    Ok(Some(FrozenBatch { validated, roots }))
}

fn value<T: Clone + Send + Sync + 'static>(matches: &ArgMatches, id: &str) -> Result<T, String> {
    matches
        .try_get_one::<T>(id)
        .map_err(|e| e.to_string())?
        .cloned()
        .ok_or_else(|| format!("missing parsed option: {id}"))
}

/// Normalize the existing CLI grammar without cloning its definitions. Encoding
/// uses clap's already-validated raw token because its value enum belongs to the
/// scanner; other values retain their parsed numeric/bool types.
pub fn analysis_configuration(matches: &ArgMatches) -> Result<AnalysisConfiguration, String> {
    let encoding = matches
        .try_get_raw("encoding")
        .map_err(|e| e.to_string())?
        .and_then(|mut values| values.next().map(|s| s.to_string_lossy().into_owned()));
    let scan_utf16 = value::<bool>(matches, "scan_utf16")?;
    let matches_only = value::<bool>(matches, "matches_only")?;
    let mut categories: Vec<String> = matches
        .try_get_many::<String>("categories")
        .map_err(|e| e.to_string())?
        .map(|values| values.cloned().collect())
        .unwrap_or_default();
    categories.sort();
    categories.dedup();
    let config = AnalysisConfiguration {
        strings: value::<bool>(matches, "strings")?
            || matches_only
            || scan_utf16
            || encoding.is_some()
            || !categories.is_empty(),
        matches_only: matches_only || !categories.is_empty(),
        no_decode: value(matches, "no_decode")?,
        max_string_bytes: value(matches, "max_string_bytes")?,
        max_decode_bytes: value(matches, "max_decode_bytes")?,
        encoding: encoding.unwrap_or_else(|| "auto".into()),
        scan_utf16,
        offset: value(matches, "offset")?,
        length: matches
            .try_get_one::<u64>("length")
            .map_err(|e| e.to_string())?
            .copied(),
        min_length: value(matches, "min_length")?,
        categories,
        decode_depth: value(matches, "decode_depth")?,
        entropy: value(matches, "entropy")?,
        entropy_window: value(matches, "entropy_window")?,
        entropy_threshold: value(matches, "entropy_threshold")?,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
pub(super) fn storage_fixture(input: &Path, output: &Path) -> FrozenBatch {
    let manifest: super::Manifest = serde_json::from_str(include_str!(
        "../../tests/fixtures/batch/manifest-empty.json"
    ))
    .unwrap();
    let mut configuration = manifest.configuration;
    configuration.jobs = 1;
    configuration.work_queue_capacity = 2;
    configuration.analysis.entropy = true; // Exercises private snapshot storage too.
    let patterns = crate::string_analysis::load_patterns(None).unwrap();
    configuration.patterns_sha256 =
        pattern_fingerprint(patterns.iter().map(|(n, r)| (n.as_str(), r.as_str())));
    FrozenBatch {
        roots: super::roots::resolve_roots(input, output).unwrap(),
        validated: ValidatedConfiguration {
            folder: FolderConfiguration {
                recursive: false,
                jobs: 1,
                work_queue_capacity: 2,
                output_dir: output.into(),
                fail_fast: false,
                progress: super::cli::ProgressMode::Disabled,
                human_summary: false,
            },
            configuration,
            patterns,
        },
    }
}

#[cfg(test)]
impl FrozenBatch {
    pub(super) fn test_fail_fast(&mut self) {
        self.validated.configuration.fail_fast = true;
        self.validated.folder.fail_fast = true;
    }
    pub(super) fn test_limited_strings(&mut self) {
        self.validated.configuration.analysis.strings = true;
        self.validated.configuration.analysis.max_string_bytes = 4;
    }
    pub(super) fn test_jobs(&mut self, jobs: usize) {
        self.validated.configuration.jobs = jobs;
        self.validated.configuration.work_queue_capacity = jobs.checked_mul(2).unwrap();
        self.validated.folder.jobs = jobs;
        self.validated.folder.work_queue_capacity = jobs * 2;
    }
    pub(super) fn test_offset(&mut self, offset: u64) {
        self.validated.configuration.analysis.offset = offset;
    }
}
