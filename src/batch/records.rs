//
// VULNEX -BinSith-
//
// File: batch/records.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::RelativePath;
use serde::{Deserialize, Serialize};

// Unlike serde's default Option handling, require the key while accepting null.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Unsupported schema versions fail explicitly; unknown additive fields are accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchemaVersion;
impl Serialize for SchemaVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}
impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u64::deserialize(deserializer)? {
            1 => Ok(Self),
            _ => Err(serde::de::Error::custom("unsupported batch schema version")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub schema_version: SchemaVersion,
    pub batch_id: String,
    pub sequence: u64,
    pub entry_id: u64,
    pub path: RelativePath,
    pub display_path: String,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum Event {
    Admission,
    Terminal { outcome: Outcome },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Complete { report: Report },
    Limited { report: Report },
    Failed { reason: String },
    Skipped { reason: String },
    Cancelled { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub report_id: String,
    pub location: String,
    pub selected_bytes: u64,
    pub duration_ms: u64,
    /// None means not analyzed; false means analyzed without an actionable match.
    #[serde(deserialize_with = "required_nullable")]
    pub has_actionable_indicators: Option<bool>,
}
impl JournalRecord {
    /// Validate cross-field identity after parsing or before publication.
    /// Sequence continuity and admission/terminal pairing are coordinator concerns.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.batch_id.is_empty() || self.sequence == 0 || self.entry_id == 0 {
            return Err("batch ID must be nonempty and sequence/entry IDs start at one");
        }
        match &self.event {
            Event::Terminal {
                outcome: Outcome::Complete { report } | Outcome::Limited { report },
            } => {
                if report.report_id != self.path.report_id()
                    || report.location != self.path.report_location()
                {
                    return Err("report identity does not match journal path");
                }
            }
            Event::Terminal {
                outcome:
                    Outcome::Failed { reason }
                    | Outcome::Skipped { reason }
                    | Outcome::Cancelled { reason },
            } if reason.is_empty() => {
                return Err("terminal reason must be nonempty");
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorScope {
    File,
    Discovery,
    Batch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub schema_version: SchemaVersion,
    pub batch_id: String,
    pub entry_id: Option<u64>,
    pub scope: ErrorScope,
    pub display_path: Option<String>,
    pub stage: String,
    pub code: String,
    pub message: String,
}

/// A coherent checkpoint, not a counter of arbitrary filesystem lookups.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub observed_entries: u64,
    pub eligible: u64,
    pub policy_skipped: u64,
    pub discovery_errors: u64,
    pub queued: u64,
    pub active: u64,
    pub complete: u64,
    pub limited: u64,
    pub failed: u64,
    pub cancelled: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub files_with_indicators: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub limited_files_with_indicators: Option<u64>,
}
impl Counters {
    pub fn validate(&self) -> Result<(), &'static str> {
        let sum = [
            self.queued,
            self.active,
            self.complete,
            self.limited,
            self.failed,
            self.cancelled,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add);
        if sum != Some(self.eligible)
            || self.eligible.checked_add(self.policy_skipped) != Some(self.observed_entries)
        {
            return Err("inconsistent or overflowing batch counters");
        }
        match (
            self.files_with_indicators,
            self.limited_files_with_indicators,
        ) {
            (None, None) => Ok(()),
            (Some(all), Some(limited))
                if limited <= self.limited && limited <= all && all - limited <= self.complete =>
            {
                Ok(())
            }
            _ => Err("inconsistent indicator counters"),
        }
    }
}

/// Completion of orchestration is distinct from success of every file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Success,
    ExecutionFailure,
    SetupFailure,
    Interrupted,
}
impl ExitStatus {
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::ExecutionFailure => 1,
            Self::SetupFailure => 2,
            Self::Interrupted => 130,
        }
    }

    /// Stop state is supplied by the coordinator, never inferred from matches.
    pub fn for_execution(
        counters: &Counters,
        orchestration_finished: bool,
        interrupted: bool,
    ) -> Self {
        if interrupted {
            return Self::Interrupted;
        }
        if counters.validate().is_err()
            || !orchestration_finished
            || counters.queued != 0
            || counters.active != 0
            || counters.cancelled != 0
            || counters.failed != 0
            || counters.limited != 0
            || counters.discovery_errors != 0
        {
            Self::ExecutionFailure
        } else {
            Self::Success
        }
    }
}
