//! Offline combined indicators. Completion is the atomic publication of manifest.json;
//! earlier failures can leave payloads but never a completed bundle. Samples are not read.
mod summary;

use super::{observations::Observation, *};
use crate::scanner::CancellationToken;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFilter {
    #[default]
    All,
    Actionable,
    Validated,
}
impl ValidationFilter {
    fn accepts(self, status: &str) -> bool {
        match self {
            Self::All => true,
            Self::Actionable => status != "invalid",
            Self::Validated => status == "validated",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub keys: usize,
    pub key_bytes: usize,
    pub locations_per_key: usize,
    pub location_bytes: usize,
    pub reasons_per_key: usize,
    pub reason_bytes: usize,
    pub bundle_bytes: u64,
    pub summary_keys: usize,
    pub summary_sources_per_key: usize,
    pub summary_reason_keys: usize,
    pub summary_reason_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            keys: 10_000,
            key_bytes: 16 * 1024 * 1024,
            locations_per_key: 64,
            location_bytes: 16 * 1024 * 1024,
            reasons_per_key: 16,
            reason_bytes: 1024 * 1024,
            bundle_bytes: 256 * 1024 * 1024,
            summary_keys: 20,
            summary_sources_per_key: 8,
            summary_reason_keys: 128,
            summary_reason_bytes: 64 * 1024,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub csv: bool,
    pub validation: ValidationFilter,
    pub limits: Limits,
    pub reader_limits: super::Limits,
}
#[derive(Debug, Serialize)]
struct Location {
    path: RelativePath,
    report_id: String,
    report_location: String,
    source_offset: u64,
    source_end_offset: u64,
    source_encoding: String,
    extraction: String,
    decode_depth: u64,
    decode_encoding: Option<String>,
    decoded_offset: Option<u64>,
    decoded_end_offset: Option<u64>,
}
#[derive(Debug, Serialize)]
struct Indicator {
    category: String,
    value: String,
    validation_status: String,
    observed_occurrences: u64,
    distinct_file_entries: u64,
    locations: Vec<Location>,
    location_observations_omitted: u64,
    validation_reasons: BTreeMap<String, u64>,
    reason_observations_omitted: u64,
    #[serde(skip)]
    last_entry: Option<u64>,
}
fn add(n: &mut u64, amount: u64) -> Result<()> {
    *n = n
        .checked_add(amount)
        .ok_or_else(|| invalid("aggregate counter overflow"))?;
    Ok(())
}
#[derive(Default, Serialize)]
struct Totals {
    observed_occurrences: u64,
    filtered_observations: u64,
    unretained_key_observations: u64,
    location_observations_omitted: u64,
    reason_observations_omitted: u64,
}
struct Index {
    entries: BTreeMap<(String, String, String), Indicator>,
    totals: Totals,
    key_bytes: usize,
    location_bytes: usize,
    reason_bytes: usize,
    keys_frozen: bool,
    locations_frozen: bool,
    reasons_frozen: bool,
    options: Options,
}
impl Index {
    fn new(options: Options) -> Self {
        Self {
            entries: BTreeMap::new(),
            totals: Totals::default(),
            key_bytes: 0,
            location_bytes: 0,
            reason_bytes: 0,
            keys_frozen: false,
            locations_frozen: false,
            reasons_frozen: false,
            options,
        }
    }
    fn observe(&mut self, entry: &JournalRecord, o: Observation) -> Result<()> {
        add(&mut self.totals.observed_occurrences, 1)?;
        if !self.options.validation.accepts(&o.validation_status) {
            return add(&mut self.totals.filtered_observations, 1);
        }
        let key = (
            o.category.clone(),
            o.value.clone(),
            o.validation_status.clone(),
        );
        let limits = &self.options.limits;
        if !self.entries.contains_key(&key) {
            let bytes = o
                .category
                .len()
                .checked_add(o.value.len())
                .ok_or_else(|| invalid("key byte overflow"))?;
            if self.keys_frozen
                || self.entries.len() >= limits.keys
                || bytes > limits.key_bytes.saturating_sub(self.key_bytes)
            {
                self.keys_frozen = true;
                return add(&mut self.totals.unretained_key_observations, 1);
            }
            self.key_bytes += bytes;
            self.entries.insert(
                key.clone(),
                Indicator {
                    category: o.category,
                    value: o.value,
                    validation_status: o.validation_status,
                    observed_occurrences: 0,
                    distinct_file_entries: 0,
                    locations: Vec::new(),
                    location_observations_omitted: 0,
                    validation_reasons: BTreeMap::new(),
                    reason_observations_omitted: 0,
                    last_entry: None,
                },
            );
        }
        let indicator = self.entries.get_mut(&key).unwrap();
        add(&mut indicator.observed_occurrences, 1)?;
        if indicator.last_entry != Some(entry.entry_id) {
            add(&mut indicator.distinct_file_entries, 1)?;
            indicator.last_entry = Some(entry.entry_id);
        }
        if let Some(count) = indicator.validation_reasons.get_mut(&o.reason) {
            add(count, 1)?;
        } else if indicator.validation_reasons.len() >= limits.reasons_per_key
            || self.reasons_frozen
            || o.reason.len() > limits.reason_bytes.saturating_sub(self.reason_bytes)
        {
            if o.reason.len() > limits.reason_bytes.saturating_sub(self.reason_bytes) {
                self.reasons_frozen = true;
            }
            add(&mut indicator.reason_observations_omitted, 1)?;
            add(&mut self.totals.reason_observations_omitted, 1)?;
        } else {
            self.reason_bytes += o.reason.len();
            indicator.validation_reasons.insert(o.reason, 1);
        }
        let location = Location {
            path: entry.path.clone(),
            report_id: report_ref(entry)
                .ok_or_else(|| invalid("missing report"))?
                .report_id
                .clone(),
            report_location: report_ref(entry)
                .ok_or_else(|| invalid("missing report"))?
                .location
                .clone(),
            source_offset: o.source_offset,
            source_end_offset: o.source_end_offset,
            source_encoding: o.source_encoding,
            extraction: o.extraction,
            decode_depth: o.decode_depth,
            decode_encoding: o.decode_encoding,
            decoded_offset: o.decoded_offset,
            decoded_end_offset: o.decoded_end_offset,
        };
        let bytes = serde_json::to_vec(&location)?.len();
        if indicator.locations.len() < limits.locations_per_key
            && bytes > limits.location_bytes.saturating_sub(self.location_bytes)
        {
            self.locations_frozen = true;
        }
        if self.locations_frozen || indicator.locations.len() >= limits.locations_per_key {
            add(&mut indicator.location_observations_omitted, 1)?;
            add(&mut self.totals.location_observations_omitted, 1)?;
        } else {
            self.location_bytes += bytes;
            indicator.locations.push(location);
        }
        Ok(())
    }
    fn limited(&self) -> bool {
        self.keys_frozen
            || self.totals.location_observations_omitted > 0
            || self.totals.reason_observations_omitted > 0
    }
}

#[derive(Serialize)]
struct Payload<'a> {
    kind: &'static str,
    schema_version: u8,
    source_batch_id: &'a str,
    processing_complete: bool,
    validation_filter: ValidationFilter,
    coverage: &'a serde_json::Value,
    scope: &'a serde_json::Value,
    counts: &'a serde_json::Value,
    indicators: Vec<&'a Indicator>,
}
#[derive(Debug, Serialize)]
struct Receipt {
    bytes: u64,
    sha256: String,
}
struct BundleWriter<'a> {
    file: std::fs::File,
    used: &'a mut u64,
    cap: u64,
    bytes: u64,
    hash: Sha256,
    token: &'a CancellationToken,
}
impl Write for BundleWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.token.is_cancelled() {
            return Err(io::Error::other(Error::Interrupted));
        }
        if bytes.len() as u64 > self.cap.saturating_sub(*self.used) {
            return Err(io::Error::other(Error::Resource(
                "output bundle byte limit exceeded",
            )));
        }
        let n = self.file.write(bytes)?;
        *self.used += n as u64;
        self.bytes += n as u64;
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn payload(
    root: &fs::Root,
    name: &str,
    used: &mut u64,
    cap: u64,
    token: &CancellationToken,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<(Receipt, Snapshot)> {
    let mut writer = BundleWriter {
        file: root.create_file(name)?,
        used,
        cap,
        bytes: 0,
        hash: Sha256::new(),
        token,
    };
    {
        let mut buffered = io::BufWriter::new(&mut writer);
        write(&mut buffered)?;
        buffered.flush()?;
    }
    writer.flush()?;
    let stamp = Snapshot::opened(&writer.file)?;
    Ok((
        Receipt {
            bytes: writer.bytes,
            sha256: format!("{:x}", writer.hash.finalize()),
        },
        stamp,
    ))
}
fn write_json(out: &mut dyn Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(|e| {
        if e.is_io() {
            Error::Resource("cannot write bundle payload (I/O or byte limit)")
        } else {
            invalid("cannot serialize bundle")
        }
    })?;
    out.write_all(b"\n")?;
    Ok(())
}
fn csv_row(out: &mut dyn Write, fields: &[String]) -> Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i != 0 {
            out.write_all(b",")?;
        }
        out.write_all(b"\"")?;
        for part in field.split_inclusive('"') {
            out.write_all(part.as_bytes())?;
            if part.ends_with('"') {
                out.write_all(b"\"")?;
            }
        }
        out.write_all(b"\"")?;
    }
    out.write_all(b"\r\n")?;
    Ok(())
}

/// Import and publish one new bundle. Diagnostics must be successfully written
/// before publication; after publication the recorded status wins over interrupts.
/// The returned code is 0 for complete scope, 1 for source/aggregation limitations.
/// Invalid inputs return Error (2); operational errors 1 and interruption 130.
pub fn run(
    source: &Path,
    destination: &Path,
    options: Options,
    token: CancellationToken,
    mut diagnostic: impl FnMut(&str) -> io::Result<()>,
) -> Result<u8> {
    let result = run_inner(source, destination, options, &token, &mut diagnostic);
    // A successful return means publication committed. Do not override its status.
    match result {
        Err(_) if token.is_cancelled() => Err(Error::Interrupted),
        other => other,
    }
}
fn run_inner(
    source: &Path,
    destination: &Path,
    options: Options,
    token: &CancellationToken,
    diagnostic: &mut impl FnMut(&str) -> io::Result<()>,
) -> Result<u8> {
    diagnostic("Validating completed batch artifacts...")?;
    let mut batch = super::read(source, options.reader_limits.clone(), token.clone())?;
    let mut index = Index::new(options.clone());
    let mut omissions = BTreeMap::<String, u64>::new();
    let mut omission_bytes = 0usize;
    diagnostic("Aggregating indicators in canonical path order...")?;
    batch.observations(
        |entry, value| index.observe(entry, value),
        |category, count| {
            if count == 0 {
                return Ok(());
            }
            if !omissions.contains_key(category) {
                if omissions.len() >= 256
                    || category.len() > (1024 * 1024usize).saturating_sub(omission_bytes)
                {
                    return Err(invalid("upstream omission category limit exceeded"));
                }
                omission_bytes += category.len();
            }
            add(omissions.entry(category.into()).or_default(), count)
        },
    )?;
    let inventory = summary::Inventory::read(&batch, &options.limits)?;
    let m = batch.manifest();
    let c = &m.counters;
    let source_failed = !m.discovery_complete
        || c.discovery_errors > 0
        || c.failed > 0
        || c.cancelled > 0
        || !m.stop_reasons.is_empty();
    let source_limited = c.limited > 0;
    let analyzed = m.configuration.analysis.strings || c.eligible == 0;
    let limited = source_failed || source_limited || index.limited();
    let exit_code = u8::from(limited);
    let coverage = json!({
        "discovery": if m.discovery_complete && c.discovery_errors == 0 { "complete" } else { "limited" },
        "selection": if m.selection.is_some() { "explicit_policy" } else { "all_eligible" },
        "string_analysis": if m.configuration.analysis.strings { "enabled" } else { "not_analyzed" },
        "scan": if source_failed { "incomplete" } else if c.eligible == 0 { "empty" } else if source_limited { "limited" } else if !analyzed { "not_analyzed" } else { "complete_within_configured_scope" },
        "import": "valid_complete_batch", "aggregation": if !analyzed { "not_analyzed" } else if index.limited() { "limited" } else { "complete" },
        "presentation": options.validation
    });
    let scope = json!({ "configuration": m.configuration, "selection": m.selection, "enumeration_policy": m.enumeration_policy });
    let metric = |n: u64| analyzed.then_some(n);
    let counts = json!({
        "file_entries": c.eligible, "source_counters": c,
        "selected_bytes": inventory.selected_bytes,
        "retained_unique_keys": metric(index.entries.len() as u64),
        "total_unique_keys": if index.keys_frozen { None } else { metric(index.entries.len() as u64) },
        "observed_occurrences": metric(index.totals.observed_occurrences),
        "filtered_observations": metric(index.totals.filtered_observations),
        "unretained_key_observations": metric(index.totals.unretained_key_observations),
        "location_observations_omitted": metric(index.totals.location_observations_omitted),
        "reason_observations_omitted": metric(index.totals.reason_observations_omitted),
        "upstream_omitted_details": if analyzed { Some(&omissions) } else { None },
        "unreferenced_artifact_entries": batch.unreferenced_artifact_entries()
    });
    let indicators = Payload {
        kind: "batch_indicator_export",
        schema_version: 1,
        source_batch_id: &m.batch_id,
        processing_complete: true,
        validation_filter: options.validation,
        coverage: &coverage,
        scope: &scope,
        counts: &counts,
        indicators: index.entries.values().collect(),
    };
    let summary = summary::Summary {
        kind: "batch_summary",
        schema_version: 1,
        source_batch_id: &m.batch_id,
        processing_complete: true,
        validation_filter: options.validation,
        coverage: &coverage,
        scope: &scope,
        counts: &counts,
        ranking: summary::Ranking::new(&index, analyzed),
        outcome_reasons: &inventory.outcome_reasons,
        presentation_limits: (&options.limits).into(),
    };
    diagnostic("Writing export bundle...")?;
    if token.is_cancelled() {
        return Err(Error::Interrupted);
    }
    let output = batch.root.create_output(destination)?;
    let mut used = 0;
    let mut artifacts = BTreeMap::new();
    let mut stamps = Vec::new();
    for name in ["indicators.json", "summary.json"] {
        let (receipt, stamp) = payload(
            &output,
            name,
            &mut used,
            options.limits.bundle_bytes,
            token,
            |out| {
                if name == "indicators.json" {
                    write_json(out, &indicators)
                } else {
                    write_json(out, &summary)
                }
            },
        )?;
        artifacts.insert(name, receipt);
        stamps.push((name, stamp));
    }
    if options.csv {
        let (receipt, stamp) = payload(
            &output,
            "indicators.csv",
            &mut used,
            options.limits.bundle_bytes,
            token,
            |out| {
                csv_row(
                    out,
                    &[
                        "category",
                        "value",
                        "validation_status",
                        "observed_occurrences",
                        "distinct_file_entries",
                        "location_observations_omitted",
                        "locations",
                        "validation_reasons",
                        "reason_observations_omitted",
                    ]
                    .map(str::to_owned),
                )?;
                for indicator in index.entries.values() {
                    csv_row(
                        out,
                        &[
                            indicator.category.clone(),
                            indicator.value.clone(),
                            indicator.validation_status.clone(),
                            indicator.observed_occurrences.to_string(),
                            indicator.distinct_file_entries.to_string(),
                            indicator.location_observations_omitted.to_string(),
                            serde_json::to_string(&indicator.locations)?,
                            serde_json::to_string(&indicator.validation_reasons)?,
                            indicator.reason_observations_omitted.to_string(),
                        ],
                    )?;
                }
                Ok(())
            },
        )?;
        artifacts.insert("indicators.csv", receipt);
        stamps.push(("indicators.csv", stamp));
    }
    let manifest = json!({ "kind": "batch_export_bundle", "schema_version": 1, "source_batch_id": m.batch_id,
        "input_manifest_sha256": batch.manifest_sha256, "processing_complete": true, "exit_code": exit_code,
        "build": { "version": env!("CARGO_PKG_VERSION"), "revision": env!("BINSITH_REVISION"), "source_sha256": env!("BINSITH_SOURCE_SHA256"), "target": env!("BINSITH_TARGET"), "profile": env!("BINSITH_PROFILE") },
        "source_build": m.build, "validation_filter": options.validation, "coverage": coverage, "limits": options.limits,
        "reader_limits": options.reader_limits, "artifacts": artifacts,
        "imported_bytes": batch.imported_bytes(), "scratch_high_water_bytes": batch.scratch_high_water_bytes()
    });
    let (_, stamp) = payload(
        &output,
        ".manifest.pending",
        &mut used,
        options.limits.bundle_bytes,
        token,
        |out| write_json(out, &manifest),
    )?;
    stamps.push((".manifest.pending", stamp.clone()));
    diagnostic("Checking source and publishing completion...")?;
    batch.verify_unchanged()?;
    for (name, stamp) in stamps {
        output.verify(name, &stamp)?;
    }
    if token.is_cancelled() {
        return Err(Error::Interrupted);
    }
    output.publish_manifest(&stamp)?;
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry() -> JournalRecord {
        serde_json::from_str(
            include_str!("../../../tests/fixtures/batch/released-v0.5/files.jsonl")
                .lines()
                .nth(1)
                .unwrap(),
        )
        .unwrap()
    }
    fn observation(value: &str) -> Observation {
        Observation {
            category: "x".into(),
            value: value.into(),
            validation_status: "candidate".into(),
            reason: "synthetic".into(),
            source_offset: 0,
            source_end_offset: 1,
            source_encoding: "ASCII".into(),
            extraction: "text".into(),
            decode_depth: 0,
            decode_encoding: None,
            decoded_offset: None,
            decoded_end_offset: None,
        }
    }
    #[test]
    fn key_byte_failure_freezes_smaller_later_keys_but_counts_existing_keys() {
        let mut options = Options::default();
        options.limits.key_bytes = 5;
        let mut index = Index::new(options);
        for value in ["a", "too-long", "b", "a"] {
            index.observe(&entry(), observation(value)).unwrap();
        }
        assert_eq!(index.entries.len(), 1);
        assert_eq!(
            index.entries.values().next().unwrap().observed_occurrences,
            2
        );
        assert_eq!(
            index.entries.values().next().unwrap().distinct_file_entries,
            1
        );
        assert_eq!(index.totals.unretained_key_observations, 2);
        assert!(index.keys_frozen);
    }
    #[test]
    fn repeated_locations_are_observations_not_deduplicated() {
        let mut index = Index::new(Options::default());
        for _ in 0..3 {
            index.observe(&entry(), observation("a")).unwrap();
        }
        assert_eq!(index.entries.values().next().unwrap().locations.len(), 3);
    }
    #[test]
    fn counter_overflow_is_invalid() {
        let mut count = u64::MAX;
        assert_eq!(add(&mut count, 1).unwrap_err().exit_code(), 2);
    }
}
