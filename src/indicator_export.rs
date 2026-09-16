use crate::{
    file_summary::FileSummary,
    string_analysis::{MatchDetail, StringFinding},
    validation::Status,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Json,
    Csv,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFilter {
    #[default]
    All,
    Actionable,
    Validated,
}
impl ValidationFilter {
    fn accepts(self, status: &Status) -> bool {
        match self {
            Self::All => true,
            Self::Actionable => !matches!(status, Status::Invalid),
            Self::Validated => matches!(status, Status::Validated),
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
struct Location {
    source_offset: usize,
    source_end_offset: usize,
    source_encoding: &'static str,
    extraction: &'static str,
    decode_depth: usize,
    decode_encoding: Option<&'static str>,
    decoded_offset: Option<usize>,
    decoded_end_offset: Option<usize>,
}
#[derive(Serialize)]
struct Indicator {
    category: String,
    value: String,
    validation_status: &'static str,
    validation_reason: &'static str,
    observed_occurrences: u64,
    locations: Vec<Location>,
    locations_omitted: u64,
}
#[derive(Default, Serialize)]
struct LimitsReached {
    skipped_occurrences: u64,
    omitted_locations: u64,
}
pub struct Index {
    entries: BTreeMap<(String, String, &'static str), Indicator>,
    value_bytes: usize,
    filter: ValidationFilter,
    filtered_occurrences: u64,
    limits: LimitsReached,
}
impl Default for Index {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            value_bytes: 0,
            filter: ValidationFilter::All,
            filtered_occurrences: 0,
            limits: LimitsReached::default(),
        }
    }
}
const MAX_INDICATORS: usize = 10000;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOCATIONS: usize = 64;
impl Index {
    pub fn new(filter: ValidationFilter) -> Self {
        Self {
            filter,
            ..Self::default()
        }
    }
    fn insert(&mut self, detail: &MatchDetail, location: Location) {
        if !self.filter.accepts(&detail.validation.status) {
            self.filtered_occurrences += 1;
            return;
        }
        let status = match detail.validation.status {
            Status::Candidate => "candidate",
            Status::Validated => "validated",
            Status::Invalid => "invalid",
        };
        let key = (detail.pattern.clone(), detail.text.clone(), status);
        let bytes = detail.pattern.len().saturating_add(detail.text.len());
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= MAX_INDICATORS
                || bytes > MAX_VALUE_BYTES.saturating_sub(self.value_bytes)
            {
                self.limits.skipped_occurrences += 1;
                return;
            }
            self.value_bytes += bytes;
            self.entries.insert(
                key.clone(),
                Indicator {
                    category: detail.pattern.clone(),
                    value: detail.text.clone(),
                    validation_status: status,
                    validation_reason: detail.validation.reason,
                    observed_occurrences: 0,
                    locations: Vec::new(),
                    locations_omitted: 0,
                },
            );
        }
        let entry = self.entries.get_mut(&key).unwrap();
        entry.observed_occurrences += 1;
        if entry.locations.contains(&location) {
            return;
        }
        if entry.locations.len() == MAX_LOCATIONS {
            entry.locations_omitted += 1;
            self.limits.omitted_locations += 1;
        } else {
            entry.locations.push(location);
        }
    }
    pub fn observe(&mut self, finding: &StringFinding) {
        for detail in &finding.match_details {
            self.insert(
                detail,
                Location {
                    source_offset: detail.offset,
                    source_end_offset: detail.end_offset,
                    source_encoding: finding.encoding,
                    extraction: finding.extraction,
                    decode_depth: 0,
                    decode_encoding: None,
                    decoded_offset: None,
                    decoded_end_offset: None,
                },
            );
        }
        for layer in &finding.decoded_layers {
            for detail in &layer.match_details {
                self.insert(
                    detail,
                    Location {
                        source_offset: layer.source_offset,
                        source_end_offset: layer.source_end_offset,
                        source_encoding: finding.encoding,
                        extraction: finding.extraction,
                        decode_depth: layer.depth,
                        decode_encoding: Some(layer.encoding),
                        decoded_offset: Some(detail.offset),
                        decoded_end_offset: Some(detail.end_offset),
                    },
                );
            }
        }
    }
    pub fn limited(&self) -> bool {
        self.limits.skipped_occurrences > 0 || self.limits.omitted_locations > 0
    }
    pub fn write(
        &self,
        out: &mut impl Write,
        format: Format,
        summary: &FileSummary,
        metadata: &serde_json::Value,
        coverage: &serde_json::Value,
    ) -> io::Result<()> {
        let context = serde_json::json!({"schema_version":1, "kind":"indicator_export", "processing_complete":true,
            "file_summary":summary, "metadata":metadata, "analysis_coverage":coverage,
            "validation_filter":self.filter, "filtered_occurrences":self.filtered_occurrences,
            "export_limited":self.limited(), "export_limits":self.limits,
            "max_indicators":MAX_INDICATORS,"max_value_bytes":MAX_VALUE_BYTES,"max_locations_per_indicator":MAX_LOCATIONS,
            "indicator_count":self.entries.len(), "scope":"primary_input_only",
            "count_semantics":"Observed retained match details across all extraction passes; omitted upstream details are not counted."});
        match format {
            Format::Json => {
                // Stream entries rather than constructing a second copy of the index.
                write!(out, "{{\"context\":")?;
                serde_json::to_writer(&mut *out, &context)?;
                write!(out, ",\"indicators\":[")?;
                for (i, entry) in self.entries.values().enumerate() {
                    if i > 0 {
                        write!(out, ",")?;
                    }
                    serde_json::to_writer(&mut *out, entry)?;
                }
                writeln!(out, "]}}")?;
            }
            Format::Csv => {
                row(
                    out,
                    &[
                        "record_type",
                        "category",
                        "value",
                        "validation_status",
                        "validation_reason",
                        "observed_occurrences",
                        "locations_json",
                        "locations_omitted",
                        "context_json",
                    ],
                )?;
                for entry in self.entries.values() {
                    row(
                        out,
                        &[
                            "indicator",
                            &entry.category,
                            &entry.value,
                            entry.validation_status,
                            entry.validation_reason,
                            &entry.observed_occurrences.to_string(),
                            &serde_json::to_string(&entry.locations)?,
                            &entry.locations_omitted.to_string(),
                            "",
                        ],
                    )?;
                }
                row(
                    out,
                    &[
                        "context",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        &serde_json::to_string(&context)?,
                    ],
                )?;
            }
        }
        out.flush()
    }
}
fn row(out: &mut impl Write, fields: &[&str]) -> io::Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            write!(out, ",")?;
        }
        write!(out, "\"{}\"", field.replace('"', "\"\""))?;
    }
    write!(out, "\r\n")
}

/// Fully write and flush before replacing a named destination.
pub fn save(
    index: &Index,
    path: &str,
    format: Format,
    summary: &FileSummary,
    metadata: &serde_json::Value,
    coverage: &serde_json::Value,
) -> io::Result<()> {
    if path == "-" {
        return index.write(
            &mut io::BufWriter::new(io::stdout()),
            format,
            summary,
            metadata,
            coverage,
        );
    }
    let destination = std::path::Path::new(path);
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    index.write(
        &mut io::BufWriter::new(file.as_file_mut()),
        format,
        summary,
        metadata,
        coverage,
    )?;
    file.persist(destination).map_err(|e| e.error)?;
    Ok(())
}

pub fn destination_identity(path: &str) -> io::Result<std::path::PathBuf> {
    let path = std::path::Path::new(path);
    if path.exists() {
        return path.canonicalize();
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    Ok(parent.canonicalize()?.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("output must name a file"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn detail(text: String) -> MatchDetail {
        MatchDetail {
            pattern: "test".into(),
            text,
            offset: 0,
            end_offset: 1,
            validation: crate::validation::Validation {
                status: Status::Candidate,
                reason: "fixture",
            },
        }
    }
    fn location(offset: usize) -> Location {
        Location {
            source_offset: offset,
            source_end_offset: offset + 1,
            source_encoding: "ASCII",
            extraction: "text",
            decode_depth: 0,
            decode_encoding: None,
            decoded_offset: None,
            decoded_end_offset: None,
        }
    }
    #[test]
    fn index_limits_keep_existing_counts_and_signal_omissions() {
        let mut index = Index::default();
        for i in 0..=MAX_INDICATORS {
            index.insert(&detail(format!("value-{i}")), location(i));
        }
        assert_eq!(index.entries.len(), MAX_INDICATORS);
        assert_eq!(index.limits.skipped_occurrences, 1);
        for i in 0..=MAX_LOCATIONS {
            index.insert(&detail("value-0".into()), location(i));
        }
        let entry = &index.entries[&("test".into(), "value-0".into(), "candidate")];
        assert_eq!(entry.observed_occurrences, (MAX_LOCATIONS + 2) as u64);
        assert_eq!(entry.locations.len(), MAX_LOCATIONS);
        assert_eq!(entry.locations_omitted, 1);
        assert!(index.limited());
    }
    #[test]
    fn oversized_value_is_omitted_without_losing_following_indicators() {
        let mut index = Index::default();
        index.insert(&detail("x".repeat(MAX_VALUE_BYTES + 1)), location(0));
        assert!(index.entries.is_empty());
        assert_eq!(index.value_bytes, 0);
        assert_eq!(index.limits.skipped_occurrences, 1);
        index.insert(&detail("small".into()), location(1));
        assert_eq!(index.entries.len(), 1);
        assert!(index.limited());
    }
    #[test]
    fn csv_quotes_delimiters_newlines_and_quotes() {
        let mut out = Vec::new();
        row(&mut out, &["a,b", "line\r\nnext", "quoted\"value", ""]).unwrap();
        assert_eq!(
            out,
            b"\"a,b\",\"line\r\nnext\",\"quoted\"\"value\",\"\"\r\n"
        );
    }
    #[test]
    fn export_write_and_flush_failures_propagate() {
        struct Fail(bool);
        impl Write for Fail {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::Error::other("write failed"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }
        let index = Index::default();
        let summary = crate::file_summary::summarize("fixture", b"");
        for format in [Format::Json, Format::Csv] {
            for fail_write in [false, true] {
                assert!(index
                    .write(
                        &mut Fail(fail_write),
                        format,
                        &summary,
                        &serde_json::Value::Null,
                        &serde_json::Value::Null
                    )
                    .is_err());
            }
        }
    }
}
