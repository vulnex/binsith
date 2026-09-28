use super::{
    invalid,
    json::{Event, Parser, Segment},
    Result,
};
use crate::batch::{
    AnalysisConfiguration, Event as JournalEvent, JournalRecord, Manifest, Outcome,
};
use serde_json::{Map, Value};
use std::io::BufRead;

fn key(segment: &Segment) -> Option<&str> {
    match segment {
        Segment::Key(k) => Some(k),
        _ => None,
    }
}
fn get<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name).ok_or_else(|| invalid("missing report field"))
}
fn number(v: &Value, name: &str) -> Result<u64> {
    get(v, name)?
        .as_u64()
        .ok_or_else(|| invalid("invalid report integer"))
}
fn boolean(v: &Value, name: &str) -> Result<bool> {
    get(v, name)?
        .as_bool()
        .ok_or_else(|| invalid("invalid report boolean"))
}
fn string<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    get(v, name)?
        .as_str()
        .ok_or_else(|| invalid("invalid report string"))
}
fn span(start: u64, end: u64, low: u64, high: u64) -> Result<()> {
    if start < low || end < start || end > high {
        return Err(invalid("report span outside its declared range"));
    }
    Ok(())
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("report counter overflow"))
}
fn hash(v: &str, size: usize) -> bool {
    v.len() == size
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Bounded capture for small metadata and individual match details, never report
/// arrays or whole findings. Account node overhead as well as decoded text.
#[derive(Default)]
pub(super) struct Capture {
    stack: Vec<(Option<Segment>, Value)>,
    bytes: usize,
    pub(super) value: Option<Value>,
}
impl Capture {
    pub(super) fn event(&mut self, path: &[Segment], event: Event) -> Result<()> {
        let cost = match &event {
            Event::Scalar(Value::String(s)) => s.len(),
            _ => 0,
        } + 64
            + path.last().and_then(key).map_or(0, str::len);
        self.bytes = self
            .bytes
            .checked_add(cost)
            .ok_or_else(|| invalid("capture overflow"))?;
        if self.bytes > 16 * 1024 * 1024 {
            return Err(invalid("report field capture limit exceeded"));
        }
        match event {
            Event::ObjectStart => self
                .stack
                .push((path.last().cloned(), Value::Object(Map::new()))),
            Event::ArrayStart => self
                .stack
                .push((path.last().cloned(), Value::Array(Vec::new()))),
            Event::ObjectEnd | Event::ArrayEnd => {
                let (key, value) = self
                    .stack
                    .pop()
                    .ok_or_else(|| invalid("invalid report container"))?;
                self.attach(key, value)?;
            }
            Event::Scalar(value) => self.attach(path.last().cloned(), value)?,
        }
        Ok(())
    }
    fn attach(&mut self, key: Option<Segment>, value: Value) -> Result<()> {
        match self.stack.last_mut() {
            Some((_, Value::Object(map))) => {
                let Some(Segment::Key(key)) = key else {
                    return Err(invalid("invalid object member"));
                };
                map.insert(key, value);
            }
            Some((_, Value::Array(array))) => array.push(value),
            None => self.value = Some(value),
            _ => return Err(invalid("invalid captured JSON")),
        }
        Ok(())
    }
}
#[derive(Default)]
struct Details {
    count: u64,
    low: Option<u64>,
    high: u64,
    actionable: bool,
}
impl Details {
    fn observe(&mut self, v: &Value) -> Result<()> {
        let start = number(v, "offset")?;
        let end = number(v, "end_offset")?;
        if end < start || string(v, "pattern")?.is_empty() {
            return Err(invalid("invalid match detail"));
        }
        string(v, "text")?;
        let validation = get(v, "validation")?;
        let status = string(validation, "status")?;
        if !matches!(status, "candidate" | "validated" | "invalid")
            || string(validation, "reason")?.is_empty()
        {
            return Err(invalid("invalid indicator validation"));
        }
        let evidence = get(v, "evidence")?;
        string(evidence, "before")?;
        string(evidence, "after")?;
        let warning = get(evidence, "boundary_warning")?;
        if !warning.is_null() && !warning.is_string() {
            return Err(invalid("invalid boundary warning"));
        }
        self.count = add(self.count, 1)?;
        self.low = Some(self.low.map_or(start, |low| low.min(start)));
        self.high = self.high.max(end);
        self.actionable |= status != "invalid";
        Ok(())
    }
    fn validate(&self, low: u64, high: u64, actionable: bool) -> Result<()> {
        if let Some(start) = self.low {
            span(start, self.high, low, high)?;
        }
        if self.actionable && !actionable {
            return Err(invalid("actionable match flag disagrees with details"));
        }
        Ok(())
    }
}
#[derive(Default)]
struct Frame {
    fields: Map<String, Value>,
    details: Details,
    arrays: std::collections::BTreeSet<String>,
    omissions: u64,
    omissions_seen: bool,
    layers: u64,
    layer_low: Option<u64>,
    layer_high: u64,
    layer_limited: u64,
    decode_limited: bool,
}
impl Frame {
    fn field(&mut self, path: &[Segment], event: &Event) -> Result<()> {
        let Some(name) = path.first().and_then(key) else {
            return Err(invalid("invalid report frame"));
        };
        if path.len() == 1 {
            match name {
                "matches" | "match_details" | "decoded_layers" => {
                    if matches!(event, Event::ArrayStart) {
                        self.arrays.insert(name.into());
                    } else if !matches!(event, Event::ArrayEnd) {
                        return Err(invalid("report collection must be an array"));
                    }
                }
                "match_details_omitted" => {
                    if matches!(event, Event::ObjectStart) {
                        self.omissions_seen = true;
                    } else if !matches!(event, Event::ObjectEnd) {
                        return Err(invalid("omissions must be an object"));
                    }
                }
                "offset"
                | "encoding"
                | "extraction"
                | "length"
                | "value"
                | "has_actionable_match"
                | "match_details_truncated"
                | "decoded"
                | "truncated"
                | "decode_status"
                | "depth"
                | "source_offset"
                | "source_end_offset"
                | "offset_space"
                | "text"
                | "next_decode" => {
                    let Event::Scalar(value) = event else {
                        return Err(invalid("invalid report scalar field"));
                    };
                    let valid = match name {
                        "offset" | "length" | "depth" | "source_offset" | "source_end_offset" => {
                            value.as_u64().is_some()
                        }
                        "has_actionable_match" | "match_details_truncated" | "truncated" => {
                            value.is_boolean()
                        }
                        "decoded" => value.is_null() || value.is_string(),
                        "value" | "text" => value.is_string(),
                        _ => value.as_str().is_some_and(|s| s.len() <= 64),
                    };
                    if !valid {
                        return Err(invalid("invalid report frame scalar type or label length"));
                    }
                    self.fields.insert(name.into(), value.clone());
                }
                _ => (),
            }
        } else if path.len() == 2 && name == "match_details_omitted" {
            let Event::Scalar(value) = event else {
                return Err(invalid("invalid omitted-detail count"));
            };
            self.omissions = add(
                self.omissions,
                value
                    .as_u64()
                    .ok_or_else(|| invalid("invalid omitted-detail count"))?,
            )?;
        } else if path.len() == 2
            && name == "matches"
            && !matches!(event, Event::Scalar(Value::String(_)))
        {
            return Err(invalid("match categories must be strings"));
        }
        Ok(())
    }
    fn common(&self) -> Result<(bool, bool)> {
        let v = Value::Object(self.fields.clone());
        if !self.arrays.contains("matches")
            || !self.arrays.contains("match_details")
            || !self.omissions_seen
        {
            return Err(invalid("missing report match collections"));
        }
        let limited = boolean(&v, "match_details_truncated")?;
        if limited != (self.omissions > 0) {
            return Err(invalid("omission flag and counts disagree"));
        }
        Ok((boolean(&v, "has_actionable_match")?, limited))
    }
}

pub(super) fn validate(
    input: impl BufRead,
    manifest: &Manifest,
    record: &JournalRecord,
) -> Result<()> {
    validate_events(input, manifest, record, |_, _| Ok(()))
}

pub(super) fn validate_events(
    input: impl BufRead,
    manifest: &Manifest,
    record: &JournalRecord,
    mut visit: impl FnMut(&[Segment], &Event) -> Result<()>,
) -> Result<()> {
    let JournalEvent::Terminal { outcome } = &record.event else {
        return Err(invalid("report lacks terminal"));
    };
    let (report, limited) = match outcome {
        Outcome::Complete { report } => (report, false),
        Outcome::Limited { report } => (report, true),
        _ => return Err(invalid("outcome has no report")),
    };
    let config = &manifest.configuration.analysis;
    let end = add(config.offset, report.selected_bytes)?;
    let mut top = Map::new();
    let mut captures = std::collections::BTreeMap::<String, Capture>::new();
    let mut finding = Frame::default();
    let mut layer = Frame::default();
    let mut detail = Capture::default();
    let mut region = Capture::default();
    let mut entropy_end = config.offset;
    let mut strings_seen = false;
    let mut entropy_seen = false;
    let mut matched = false;
    let mut counts = [0_u64; 4];
    Parser::new(input).parse(|path, event| {
        visit(path, &event)?;
        if path.is_empty() {
            return if matches!(event, Event::ObjectStart | Event::ObjectEnd) {
                Ok(())
            } else {
                Err(invalid("report root must be an object"))
            };
        }
        let name = key(&path[0]).ok_or_else(|| invalid("invalid report root"))?;
        match name {
            "file_summary" | "scan_range" | "metadata" | "analysis_coverage" => captures
                .entry(name.into())
                .or_default()
                .event(path, event)?,
            "schema_version" | "complete" | "processing_complete" if path.len() == 1 => {
                let Event::Scalar(value) = event else {
                    return Err(invalid("invalid report completion field"));
                };
                top.insert(name.into(), value);
            }
            "strings" if path.len() == 1 => match &event {
                Event::ArrayStart if config.strings => strings_seen = true,
                Event::ArrayEnd if config.strings => (),
                Event::Scalar(Value::Null) if !config.strings => strings_seen = true,
                _ => {
                    return Err(invalid(
                        "strings field disagrees with analysis configuration",
                    ))
                }
            },
            "strings" if path.len() == 2 => match event {
                Event::ObjectStart => finding = Frame::default(),
                Event::ObjectEnd => {
                    let (actionable, omitted) = finding.common()?;
                    if !finding.arrays.contains("decoded_layers") {
                        return Err(invalid("missing decoded layers"));
                    }
                    let v = Value::Object(std::mem::take(&mut finding.fields));
                    let value = string(&v, "value")?;
                    let offset = number(&v, "offset")?;
                    let encoding = string(&v, "encoding")?;
                    if !matches!(encoding, "ASCII" | "UTF-8" | "UTF-16LE" | "UTF-16BE") {
                        return Err(invalid("unknown string encoding"));
                    }
                    if !matches!(
                        string(&v, "extraction")?,
                        "text" | "embedded_utf16_candidate"
                    ) {
                        return Err(invalid("unknown extraction method"));
                    }
                    let bytes = if encoding.starts_with("UTF-16") {
                        (value.encode_utf16().count() as u64) * 2
                    } else {
                        value.len() as u64
                    };
                    let retained_end = add(offset, bytes)?;
                    span(offset, retained_end, config.offset, end)?;
                    let truncated = boolean(&v, "truncated")?;
                    let length = number(&v, "length")?;
                    if length < value.chars().count() as u64
                        || (!truncated && length != value.chars().count() as u64)
                    {
                        return Err(invalid("invalid retained string length"));
                    }
                    let decoded = get(&v, "decoded")?;
                    if !decoded.is_null() && !decoded.is_string() {
                        return Err(invalid("invalid decoded string"));
                    }
                    let status = string(&v, "decode_status")?;
                    if !matches!(
                        status,
                        "disabled"
                            | "truncated"
                            | "not_base64"
                            | "not_utf8_base64"
                            | "decoded"
                            | "limit"
                    ) {
                        return Err(invalid("unknown decode status"));
                    }
                    finding.details.validate(offset, retained_end, actionable)?;
                    if let Some(low) = finding.layer_low {
                        span(low, finding.layer_high, offset, retained_end)?;
                    }
                    counts[0] = add(counts[0], u64::from(truncated))?;
                    counts[1] = add(counts[1], u64::from(omitted))?;
                    counts[2] = add(counts[2], finding.layer_limited)?;
                    counts[3] = add(
                        counts[3],
                        u64::from(status == "limit" || finding.decode_limited),
                    )?;
                    matched |= actionable;
                }
                _ => return Err(invalid("finding must be an object")),
            },
            "strings" => {
                let field = path.get(2).and_then(key).unwrap_or("");
                if field == "match_details" && path.len() >= 4 {
                    if path.len() == 4 && matches!(event, Event::ObjectStart) {
                        detail = Capture::default();
                    }
                    detail.event(&path[3..], event)?;
                    if let Some(value) = detail.value.take() {
                        finding.details.observe(&value)?;
                    }
                } else if field == "decoded_layers" && path.len() >= 4 {
                    if path.len() == 4 {
                        match event {
                            Event::ObjectStart => layer = Frame::default(),
                            Event::ObjectEnd => {
                                let (actionable, omitted) = layer.common()?;
                                let v = Value::Object(std::mem::take(&mut layer.fields));
                                let depth = number(&v, "depth")?;
                                if depth == 0
                                    || depth > u64::from(config.decode_depth)
                                    || config.no_decode
                                    || config.max_decode_bytes == 0
                                    || string(&v, "encoding")? != "base64"
                                    || string(&v, "offset_space")? != "decoded_layer_utf8"
                                {
                                    return Err(invalid("invalid decoded-layer configuration"));
                                }
                                let start = number(&v, "source_offset")?;
                                let finish = number(&v, "source_end_offset")?;
                                span(start, finish, config.offset, end)?;
                                layer.details.validate(
                                    0,
                                    string(&v, "text")?.len() as u64,
                                    actionable,
                                )?;
                                let next = string(&v, "next_decode")?;
                                if !matches!(
                                    next,
                                    "byte_limit" | "depth_limit" | "not_utf8_base64" | "decoded"
                                ) {
                                    return Err(invalid("unknown next-decode state"));
                                }
                                finding.layer_low =
                                    Some(finding.layer_low.map_or(start, |n| n.min(start)));
                                finding.layer_high = finding.layer_high.max(finish);
                                finding.layers = add(finding.layers, 1)?;
                                finding.layer_limited =
                                    add(finding.layer_limited, u64::from(omitted))?;
                                finding.decode_limited |=
                                    matches!(next, "byte_limit" | "depth_limit");
                                matched |= actionable;
                            }
                            _ => return Err(invalid("decoded layer must be an object")),
                        }
                    } else if path.get(4).and_then(key) == Some("match_details") && path.len() >= 6
                    {
                        if path.len() == 6 && matches!(event, Event::ObjectStart) {
                            detail = Capture::default();
                        }
                        detail.event(&path[5..], event)?;
                        if let Some(value) = detail.value.take() {
                            layer.details.observe(&value)?;
                        }
                    } else {
                        layer.field(&path[4..], &event)?;
                    }
                } else {
                    finding.field(&path[2..], &event)?;
                }
            }
            "entropy_regions" if path.len() == 1 => {
                if !config.entropy || !matches!(event, Event::ArrayStart | Event::ArrayEnd) {
                    return Err(invalid("unexpected entropy regions"));
                }
                entropy_seen = true;
            }
            "entropy_regions" => {
                if path.len() == 2 && matches!(event, Event::ObjectStart) {
                    region = Capture::default();
                }
                region.event(&path[1..], event)?;
                if let Some(value) = region.value.take() {
                    let offset = number(&value, "offset")?;
                    let length = number(&value, "length")?;
                    let entropy = get(&value, "entropy")?
                        .as_f64()
                        .ok_or_else(|| invalid("invalid entropy"))?;
                    if offset != entropy_end
                        || length == 0
                        || length > config.entropy_window as u64
                        || !(0.0..=8.0).contains(&entropy)
                        || boolean(&value, "high")? != (entropy >= config.entropy_threshold)
                    {
                        return Err(invalid("invalid entropy region"));
                    }
                    entropy_end = add(offset, length)?;
                    span(offset, entropy_end, config.offset, end)?;
                }
            }
            _ => (),
        }
        Ok(())
    })?;
    for (name, capture) in captures {
        top.insert(
            name,
            capture
                .value
                .ok_or_else(|| invalid("incomplete report field"))?,
        );
    }
    let root = Value::Object(top);
    if number(&root, "schema_version")? != 1
        || !boolean(&root, "complete")?
        || !boolean(&root, "processing_complete")?
        || !strings_seen
        || (config.entropy && (!entropy_seen || entropy_end != end))
    {
        return Err(invalid("incomplete or incompatible report"));
    }
    let summary = get(&root, "file_summary")?;
    let range = get(&root, "scan_range")?;
    if string(summary, "file_path")? != record.display_path
        || number(summary, "size_bytes")? != report.selected_bytes
        || number(range, "offset")? != config.offset
        || number(range, "length")? != report.selected_bytes
        || get(range, "requested_length")? != &serde_json::to_value(config.length)?
        || config.length.is_some_and(|n| report.selected_bytes > n)
    {
        return Err(invalid("report range/identity mismatch"));
    }
    string(summary, "mime_type")?;
    let entropy = get(summary, "entropy")?
        .as_f64()
        .ok_or_else(|| invalid("invalid summary entropy"))?;
    if !(0.0..=8.0).contains(&entropy)
        || !hash(string(summary, "md5")?, 32)
        || !hash(string(summary, "sha256")?, 64)
    {
        return Err(invalid("invalid report summary/hash"));
    }
    let metadata = get(&root, "metadata")?;
    let actual: AnalysisConfiguration =
        serde_json::from_value(get(metadata, "configuration")?.clone())
            .map_err(|_| invalid("invalid report configuration"))?;
    if actual != *config
        || string(metadata, "patterns_sha256")? != manifest.configuration.patterns_sha256
        || boolean(metadata, "strings_enabled")? != config.strings
        || string(metadata, "tool")? != "binsith"
    {
        return Err(invalid("report configuration mismatch"));
    }
    for (name, expected) in [
        ("version", &manifest.build.version),
        ("revision", &manifest.build.revision),
        ("source_sha256", &manifest.build.source_sha256),
        ("target", &manifest.build.target),
        ("profile", &manifest.build.profile),
    ] {
        if string(metadata, name)? != expected {
            return Err(invalid("report build identity mismatch"));
        }
    }
    if report.has_actionable_indicators != config.strings.then_some(matched) {
        return Err(invalid("report indicator flag mismatch"));
    }
    let coverage = get(&root, "analysis_coverage")?;
    let limits = get(coverage, "limitations")?;
    for (name, observed) in [
        "truncated_strings",
        "strings_with_omitted_details",
        "decoded_layers_with_omitted_details",
        "decode_limited_strings",
    ]
    .into_iter()
    .zip(counts)
    {
        if number(limits, name)? != observed {
            return Err(invalid("coverage counts disagree with findings"));
        }
    }
    if boolean(limits, "comparison_limited")? || boolean(limits, "indicator_export_limited")? {
        return Err(invalid("unexpected batch-report coverage flags"));
    }
    let actual_limited = counts.iter().any(|n| *n > 0);
    if actual_limited != limited
        || string(coverage, "status")?
            != if limited {
                "limited"
            } else {
                "complete_within_configured_scope"
            }
    {
        return Err(invalid("coverage/outcome mismatch"));
    }
    Ok(())
}
