//! Field-order-independent extraction. Details spill to shared, bounded scratch;
//! neither a finding nor its layer arrays are retained in memory.
use super::{
    json::{Event, Segment},
    report::{self, Capture},
    sort::{self, Scratch, Writer},
    *,
};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Observation {
    pub category: String,
    pub value: String,
    pub validation_status: String,
    pub reason: String,
    pub source_offset: u64,
    pub source_end_offset: u64,
    pub source_encoding: String,
    pub extraction: String,
    pub decode_depth: u64,
    pub decode_encoding: Option<String>,
    pub decoded_offset: Option<u64>,
    pub decoded_end_offset: Option<u64>,
}
fn key(path: &[Segment], i: usize) -> Option<&str> {
    match path.get(i) {
        Some(Segment::Key(k)) => Some(k),
        _ => None,
    }
}
fn text(v: &Value, name: &str) -> Result<String> {
    v.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid("missing observation string"))
}
fn num(v: &Value, name: &str) -> Result<u64> {
    v.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("missing observation integer"))
}
fn observation(v: Value) -> Result<Observation> {
    Ok(Observation {
        category: text(&v, "pattern")?,
        value: text(&v, "text")?,
        validation_status: text(&v["validation"], "status")?,
        reason: text(&v["validation"], "reason")?,
        source_offset: num(&v, "offset")?,
        source_end_offset: num(&v, "end_offset")?,
        source_encoding: String::new(),
        extraction: String::new(),
        decode_depth: 0,
        decode_encoding: None,
        decoded_offset: None,
        decoded_end_offset: None,
    })
}
struct Extraction {
    scratch: Scratch,
    primary: Option<Writer>,
    decoded: Option<Writer>,
    layer: Option<Writer>,
    finding_meta: Map<String, Value>,
    layer_meta: Map<String, Value>,
    detail: Capture,
}
impl Extraction {
    fn new(scratch: Scratch) -> Self {
        Self {
            scratch,
            primary: None,
            decoded: None,
            layer: None,
            finding_meta: Map::new(),
            layer_meta: Map::new(),
            detail: Capture::default(),
        }
    }
    fn event(
        &mut self,
        path: &[Segment],
        event: &Event,
        visit: &mut impl FnMut(Observation) -> Result<()>,
        omitted: &mut impl FnMut(&str, u64) -> Result<()>,
    ) -> Result<()> {
        if key(path, 0) != Some("strings") {
            return Ok(());
        }
        if path.len() == 2 {
            match event {
                Event::ObjectStart => {
                    self.finding_meta.clear();
                    self.primary = Some(Writer::new(self.scratch.clone())?);
                    self.decoded = Some(Writer::new(self.scratch.clone())?);
                }
                Event::ObjectEnd => {
                    let meta = Value::Object(std::mem::take(&mut self.finding_meta));
                    let encoding = text(&meta, "encoding")?;
                    let extraction = text(&meta, "extraction")?;
                    for writer in [self.primary.take(), self.decoded.take()] {
                        let run = writer
                            .ok_or_else(|| invalid("missing observation spool"))?
                            .finish()?;
                        let mut reader = run.reader()?;
                        while let Some((_, bytes)) = sort::next(&mut reader)? {
                            let mut value: Observation = serde_json::from_slice(&bytes)?;
                            value.source_encoding.clone_from(&encoding);
                            value.extraction.clone_from(&extraction);
                            visit(value)?;
                        }
                    }
                }
                _ => (),
            }
        }
        if path.len() == 3 && matches!(key(path, 2), Some("encoding" | "extraction")) {
            if let Event::Scalar(value) = event {
                self.finding_meta
                    .insert(key(path, 2).unwrap().into(), value.clone());
            }
        }
        let layer = key(path, 2) == Some("decoded_layers");
        if layer && path.len() == 4 {
            match event {
                Event::ObjectStart => {
                    self.layer_meta.clear();
                    self.layer = Some(Writer::new(self.scratch.clone())?);
                }
                Event::ObjectEnd => {
                    let meta = Value::Object(std::mem::take(&mut self.layer_meta));
                    let run = self
                        .layer
                        .take()
                        .ok_or_else(|| invalid("missing layer spool"))?
                        .finish()?;
                    let mut reader = run.reader()?;
                    while let Some((_, bytes)) = sort::next(&mut reader)? {
                        let mut value: Observation = serde_json::from_slice(&bytes)?;
                        value.decoded_offset = Some(value.source_offset);
                        value.decoded_end_offset = Some(value.source_end_offset);
                        value.source_offset = num(&meta, "source_offset")?;
                        value.source_end_offset = num(&meta, "source_end_offset")?;
                        value.decode_depth = num(&meta, "depth")?;
                        value.decode_encoding = Some(text(&meta, "encoding")?);
                        self.decoded
                            .as_mut()
                            .ok_or_else(|| invalid("missing decoded spool"))?
                            .row(&(Vec::new(), serde_json::to_vec(&value)?))?;
                    }
                }
                _ => (),
            }
        }
        if layer
            && path.len() == 5
            && matches!(
                key(path, 4),
                Some("source_offset" | "source_end_offset" | "depth" | "encoding")
            )
        {
            if let Event::Scalar(value) = event {
                self.layer_meta
                    .insert(key(path, 4).unwrap().into(), value.clone());
            }
        }
        let field = if layer { 4 } else { 2 };
        if key(path, field) == Some("match_details_omitted") && path.len() == field + 2 {
            if let (Some(category), Event::Scalar(value)) = (key(path, field + 1), event) {
                omitted(
                    category,
                    value
                        .as_u64()
                        .ok_or_else(|| invalid("invalid omitted count"))?,
                )?;
            }
        }
        if key(path, field) == Some("match_details") && path.len() >= field + 2 {
            if path.len() == field + 2 && matches!(event, Event::ObjectStart) {
                self.detail = Capture::default();
            }
            self.detail.event(&path[field + 1..], event.clone())?;
            if let Some(value) = self.detail.value.take() {
                let value = observation(value)?;
                let writer = if layer {
                    &mut self.layer
                } else {
                    &mut self.primary
                };
                writer
                    .as_mut()
                    .ok_or_else(|| invalid("missing detail spool"))?
                    .row(&(Vec::new(), serde_json::to_vec(&value)?))?;
            }
        }
        Ok(())
    }
}
impl ValidatedBatch {
    /// Re-read reports through the retained root, revalidating their structure.
    /// All read passes share the import-byte cap, and all spools share scratch.
    pub(super) fn observations(
        &mut self,
        mut visit: impl FnMut(&JournalRecord, Observation) -> Result<()>,
        mut omitted: impl FnMut(&str, u64) -> Result<()>,
    ) -> Result<()> {
        self.verify_unchanged()?;
        let mut budget = Budget {
            remaining: self.limits.import_bytes.saturating_sub(self.imported_bytes),
            read: 0,
            token: self.token.clone(),
        };
        let result = self.visit_entries(|entry| {
            if let Some(report) = report_ref(entry) {
                let opened = self.root.open_file(&report.location)?;
                let mut extraction = Extraction::new(self.scratch.clone());
                report::validate_events(
                    BufReader::new(Counted {
                        inner: &opened.file,
                        budget: &mut budget,
                    }),
                    &self.manifest,
                    entry,
                    |path, event| {
                        extraction.event(
                            path,
                            event,
                            &mut |observation| {
                                if self.token.is_cancelled() {
                                    return Err(Error::Interrupted);
                                }
                                visit(entry, observation)
                            },
                            &mut omitted,
                        )
                    },
                )?;
                opened.verify()?;
            }
            Ok(())
        });
        self.imported_bytes += budget.read;
        self.scratch_high_water = self.scratch.high_water();
        result?;
        self.verify_unchanged()
    }
}
