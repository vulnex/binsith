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

use clap::{parser::ValueSource, ArgMatches};
use std::path::PathBuf;

/// Composable grammar; not attached to the public CLI until execution is ready.
#[derive(clap::Args, Debug, Default)]
pub struct FolderOptions {
    /// Include subdirectories
    #[arg(long)]
    pub recursive: bool,
    /// Maximum concurrent scans
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
        let folder_requested = ["recursive", "jobs", "output_dir", "progress", "fail_fast"]
            .iter()
            .any(|id| explicit(id));
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
