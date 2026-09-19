//
// VULNEX -BinSith-
//
// File: batch/manifest.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use super::{Counters, SchemaVersion};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildIdentity {
    pub version: String,
    pub revision: String,
    pub source_sha256: String,
    pub target: String,
    pub profile: String,
}

/// Normalized values: summary is always enabled by folder JSON reporting.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalysisConfiguration {
    pub strings: bool,
    pub matches_only: bool,
    pub no_decode: bool,
    pub max_string_bytes: usize,
    pub max_decode_bytes: usize,
    pub encoding: String,
    pub scan_utf16: bool,
    pub offset: u64,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub length: Option<u64>,
    pub min_length: usize,
    pub categories: Vec<String>,
    pub decode_depth: u8,
    pub entropy: bool,
    pub entropy_window: usize,
    pub entropy_threshold: f64,
}
impl AnalysisConfiguration {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_string_bytes < 4
            || self.min_length == 0
            || self.entropy_window == 0
            || self.decode_depth > 8
            || !self.entropy_threshold.is_finite()
            || !(0.0..=8.0).contains(&self.entropy_threshold)
            || self
                .length
                .is_some_and(|n| self.offset.checked_add(n).is_none())
            || !matches!(
                self.encoding.as_str(),
                "auto" | "utf8" | "utf16le" | "utf16be"
            )
        {
            return Err("invalid analysis configuration");
        }
        if !self.strings
            && (self.matches_only
                || self.scan_utf16
                || !self.categories.is_empty()
                || self.encoding != "auto")
        {
            return Err("string-dependent options require normalized strings=true");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchConfiguration {
    pub jobs: usize,
    pub work_queue_capacity: usize,
    pub recursive: bool,
    pub fail_fast: bool,
    pub analysis: AnalysisConfiguration,
    /// SHA-256 over the ordered effective pattern name/expression pairs.
    pub patterns_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Incomplete,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnumerationPolicy {
    #[serde(rename = "observed_entries_v1")]
    ObservedEntriesV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLocations {
    pub files: String,
    pub errors: String,
    pub reports: String,
}
impl Default for ArtifactLocations {
    fn default() -> Self {
        Self {
            files: "files.jsonl".into(),
            errors: "errors.jsonl".into(),
            reports: "results".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: SchemaVersion,
    pub batch_id: String,
    pub build: BuildIdentity,
    pub configuration: BatchConfiguration,
    /// Display only: source entry identities are the lossless journal paths.
    pub input_root_display: String,
    pub output_root_display: String,
    pub enumeration_policy: EnumerationPolicy,
    pub started_unix_ms: u64,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub discovery_started_unix_ms: Option<u64>,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub discovery_finished_unix_ms: Option<u64>,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub finished_unix_ms: Option<u64>,
    /// Measured with a monotonic clock, never derived from wall-clock subtraction.
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub elapsed_ms: Option<u64>,
    pub discovery_complete: bool,
    pub status: BatchStatus,
    pub stop_reasons: Vec<String>,
    pub counters: Counters,
    pub artifacts: ArtifactLocations,
}

impl Manifest {
    /// Semantic checks do not establish that reports exist or journals were flushed;
    /// the publishing coordinator must establish those facts before completion.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.counters.validate()?;
        self.configuration.analysis.validate()?;
        if self.batch_id.is_empty()
            || self.input_root_display.is_empty()
            || self.output_root_display.is_empty()
            || self.configuration.jobs == 0
            || self.configuration.jobs.checked_mul(2)
                != Some(self.configuration.work_queue_capacity)
            || !sha256_hex(&self.configuration.patterns_sha256)
            || !sha256_hex(&self.build.source_sha256)
            || [
                &self.build.version,
                &self.build.revision,
                &self.build.target,
                &self.build.profile,
            ]
            .iter()
            .any(|s| s.is_empty())
            || self.artifacts != ArtifactLocations::default()
            || self.stop_reasons.iter().any(String::is_empty)
        {
            return Err("invalid manifest identity, configuration, or artifact locations");
        }
        if self.configuration.analysis.strings != self.counters.files_with_indicators.is_some() {
            return Err("indicator counters disagree with enabled analysis");
        }
        if self.discovery_finished_unix_ms.is_some() && self.discovery_started_unix_ms.is_none()
            || self.discovery_complete && self.discovery_finished_unix_ms.is_none()
            || self.finished_unix_ms.is_some() != self.elapsed_ms.is_some()
        {
            return Err("inconsistent lifecycle timestamps");
        }
        // Wall clocks may move backward; timestamps are not ordered here.
        if self.status == BatchStatus::Complete
            && (!self.discovery_complete
                || self.finished_unix_ms.is_none()
                || !self.stop_reasons.is_empty()
                || self.counters.queued != 0
                || self.counters.active != 0
                || self.counters.cancelled != 0)
        {
            return Err("unfinished or stopped batch cannot be marked complete");
        }
        Ok(())
    }
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Hash exact effective pattern order with length-delimited UTF-8 fields.
pub fn pattern_fingerprint<'a>(patterns: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"binsith:patterns:v1\0");
    for (name, expression) in patterns {
        for value in [name, expression] {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
    }
    format!("{:x}", hash.finalize())
}
