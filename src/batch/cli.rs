//
// VULNEX -BinSith-
//
// File: batch/cli.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::selection::{NativeEncoding, Selection, SelectionConfiguration};
use clap::{parser::ValueSource, ArgMatches};
use std::path::PathBuf;

pub const FOLDER_OPTION_IDS: &[&str] = &[
    "recursive",
    "jobs",
    "output_dir",
    "progress",
    "fail_fast",
    "include",
    "exclude",
    "max_depth",
    "max_file_bytes",
];

fn decimal_limit(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected an unsigned decimal integer".into());
    }
    value.parse().map_err(|_| "limit exceeds u64".into())
}

/// Folder options shared by preflight and the public CLI.
#[derive(clap::Args, Debug, Default)]
pub struct FolderOptions {
    /// Include files matching a case-sensitive root-relative native glob (repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub include: Vec<String>,
    /// Exclude matching files; trailing / excludes a directory subtree (repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub exclude: Vec<String>,
    /// Maximum file depth, with root children at zero; requires --recursive
    #[arg(long, value_parser = decimal_limit)]
    pub max_depth: Option<u64>,
    /// Maximum full logical file size in decimal bytes, inclusive
    #[arg(long, value_parser = decimal_limit)]
    pub max_file_bytes: Option<u64>,
    /// Include subdirectories
    #[arg(long)]
    pub recursive: bool,
    /// Maximum concurrent scans (default: available CPUs, capped at 4)
    #[arg(long)]
    pub jobs: Option<usize>,
    /// New or empty destination exclusively owned by this batch
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
    /// Show progress, including when stderr is redirected
    #[arg(long)]
    pub progress: bool,
    /// Stop admission after the first file or discovery error
    #[arg(long)]
    pub fail_fast: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    Directory,
    File,
    Stdin,
    CategoryListing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressMode {
    Disabled,
    Interactive,
    Plain,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FolderConfiguration {
    pub selection: Option<Selection>,
    pub recursive: bool,
    pub jobs: usize,
    pub work_queue_capacity: usize,
    pub output_dir: PathBuf,
    pub fail_fast: bool,
    pub progress: ProgressMode,
    pub human_summary: bool,
}

impl FolderOptions {
    /// Validate before pattern loading, output creation, or traversal. InputKind is
    /// supplied by root preflight; this function performs no filesystem operations.
    pub fn resolve(
        &self,
        matches: &ArgMatches,
        input: InputKind,
        available_parallelism: usize,
        stderr_is_terminal: bool,
        quiet: bool,
    ) -> Result<Option<FolderConfiguration>, String> {
        let explicit = |id: &str| {
            matches.try_contains_id(id).unwrap_or(false)
                && matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let folder_requested = FOLDER_OPTION_IDS.iter().any(|id| explicit(id));
        if input != InputKind::Directory {
            return if folder_requested {
                Err(
                    "folder options require directory input and cannot accompany category listing"
                        .into(),
                )
            } else {
                Ok(None)
            };
        }
        for id in [
            "output",
            "jsonl",
            "live_jsonl",
            "export_indicators",
            "export_format",
            "export_validation",
            "compare",
            "hex",
            "match_exit_code",
            "no_match_exit_code",
            "inconclusive_exit_code",
            "list_categories",
        ] {
            if explicit(id) {
                return Err(format!("option {id} is not supported in folder mode"));
            }
        }
        let selection = if !self.include.is_empty()
            || !self.exclude.is_empty()
            || self.max_depth.is_some()
            || self.max_file_bytes.is_some()
        {
            Some(Selection::compile(
                SelectionConfiguration {
                    grammar: "native_glob_v1".into(),
                    native_encoding: NativeEncoding::current(),
                    includes: self.include.clone(),
                    excludes: self.exclude.clone(),
                    max_depth: self.max_depth,
                    max_file_bytes: self.max_file_bytes,
                },
                self.recursive,
            )?)
        } else {
            None
        };
        let output_dir = self
            .output_dir
            .clone()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or("folder mode requires --output-dir")?;
        let jobs = self.jobs.unwrap_or(available_parallelism.clamp(1, 4));
        if jobs == 0 {
            return Err("--jobs must be positive".into());
        }
        let work_queue_capacity = jobs
            .checked_mul(2)
            .ok_or("--jobs overflows queue capacity")?;
        let progress = if self.progress || (!quiet && stderr_is_terminal) {
            if stderr_is_terminal {
                ProgressMode::Interactive
            } else {
                ProgressMode::Plain
            }
        } else {
            ProgressMode::Disabled
        };
        Ok(Some(FolderConfiguration {
            selection,
            recursive: self.recursive,
            jobs,
            work_queue_capacity,
            output_dir,
            fail_fast: self.fail_fast,
            progress,
            human_summary: !quiet,
        }))
    }
}
