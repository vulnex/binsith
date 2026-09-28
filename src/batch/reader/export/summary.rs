//! Views over the validated inventory and the same index used by indicators.json.
//! Ranking/source caps limit presentation only; the full retained index remains
//! authoritative. Borrow values and locations instead of duplicating their storage.
use super::*;

#[derive(Serialize)]
pub(super) struct Inventory {
    pub selected_bytes: SelectedBytes,
    pub outcome_reasons: OutcomeReasons,
}
#[derive(Default, Serialize)]
pub(super) struct SelectedBytes {
    /// Sum of selected_bytes only for complete/limited reports, never full sizes.
    reported_total: u64,
    reported_entries: u64,
    unreported_eligible_entries: u64,
    eligible_total: Option<u64>,
}
#[derive(Serialize)]
pub(super) struct OutcomeReasons {
    entries: Vec<ReasonCount>,
    unretained_reason_entries: u64,
    unvisited_descendants: &'static str,
}
#[derive(Serialize)]
struct ReasonCount {
    outcome: &'static str,
    reason: String,
    observed_entries: u64,
}
impl Inventory {
    pub fn read(batch: &ValidatedBatch, limits: &Limits) -> Result<Self> {
        let mut bytes = SelectedBytes::default();
        let mut reasons = BTreeMap::<(&'static str, String), u64>::new();
        let mut reason_bytes = 0usize;
        let mut frozen = false;
        let mut omitted = 0;
        batch.visit_entries(|entry| {
            let Event::Terminal { outcome } = &entry.event else {
                return Err(invalid("summary expects terminal inventory"));
            };
            let (status, reason) = match outcome {
                Outcome::Complete { report } | Outcome::Limited { report } => {
                    add(&mut bytes.reported_total, report.selected_bytes)?;
                    add(&mut bytes.reported_entries, 1)?;
                    return Ok(());
                }
                Outcome::Failed { reason } => {
                    add(&mut bytes.unreported_eligible_entries, 1)?;
                    ("failed", reason)
                }
                Outcome::Cancelled { reason } => {
                    add(&mut bytes.unreported_eligible_entries, 1)?;
                    ("cancelled", reason)
                }
                Outcome::Skipped { reason } => ("skipped", reason),
            };
            let key = (status, reason.clone());
            if let Some(count) = reasons.get_mut(&key) {
                return add(count, 1);
            }
            if frozen
                || reasons.len() >= limits.summary_reason_keys
                || reason.len() > limits.summary_reason_bytes.saturating_sub(reason_bytes)
            {
                frozen = true;
                return add(&mut omitted, 1);
            }
            reason_bytes += reason.len();
            reasons.insert(key, 1);
            Ok(())
        })?;
        let c = &batch.manifest().counters;
        if bytes
            .reported_entries
            .checked_add(bytes.unreported_eligible_entries)
            != Some(c.eligible)
        {
            return Err(invalid("summary report counts disagree with inventory"));
        }
        bytes.eligible_total =
            (bytes.unreported_eligible_entries == 0).then_some(bytes.reported_total);
        Ok(Self {
            selected_bytes: bytes,
            outcome_reasons: OutcomeReasons {
                entries: reasons
                    .into_iter()
                    .map(|((outcome, reason), observed_entries)| ReasonCount {
                        outcome,
                        reason,
                        observed_entries,
                    })
                    .collect(),
                unretained_reason_entries: omitted,
                unvisited_descendants: "unknown_not_counted",
            },
        })
    }
}
#[derive(Serialize)]
pub(super) struct Ranking<'a> {
    scope: &'static str,
    order: &'static str,
    retained_keys_considered: Option<usize>,
    retained_shared_keys: Option<usize>,
    keys_not_shown: Option<usize>,
    key_admission_saturated: bool,
    indicator_artifact: &'static str,
    source_location_base: &'static str,
    entries: Vec<RankedKey<'a>>,
}
#[derive(Serialize)]
struct RankedKey<'a> {
    rank: usize,
    /// Zero-based reference into the canonical indicators.json array.
    indicator_index: usize,
    category: &'a str,
    value: &'a str,
    validation_status: &'a str,
    distinct_file_entries: u64,
    observed_occurrences: u64,
    source_entries_not_shown: u64,
    /// First retained observation from each of a bounded set of path entries.
    source_samples: Vec<&'a Location>,
}
impl<'a> Ranking<'a> {
    pub fn new(index: &'a Index, analyzed: bool) -> Self {
        let mut ordered: Vec<_> = index.entries.values().enumerate().collect();
        ordered.sort_by(|(_, a), (_, b)| {
            b.distinct_file_entries
                .cmp(&a.distinct_file_entries)
                .then_with(|| {
                    (&a.category, &a.value, &a.validation_status).cmp(&(
                        &b.category,
                        &b.value,
                        &b.validation_status,
                    ))
                })
        });
        let considered = ordered.len();
        let shared = ordered
            .iter()
            .filter(|(_, i)| i.distinct_file_entries > 1)
            .count();
        let entries: Vec<_> = ordered
            .into_iter()
            .take(index.options.limits.summary_keys)
            .enumerate()
            .map(|(rank, (indicator_index, i))| {
                let mut sources: Vec<&Location> = Vec::new();
                for location in &i.locations {
                    if sources.len() >= index.options.limits.summary_sources_per_key {
                        break;
                    }
                    if sources
                        .last()
                        .is_none_or(|previous| previous.path != location.path)
                    {
                        sources.push(location);
                    }
                }
                RankedKey {
                    rank: rank + 1,
                    indicator_index,
                    category: &i.category,
                    value: &i.value,
                    validation_status: &i.validation_status,
                    distinct_file_entries: i.distinct_file_entries,
                    observed_occurrences: i.observed_occurrences,
                    source_entries_not_shown: i.distinct_file_entries - sources.len() as u64,
                    source_samples: sources,
                }
            })
            .collect();
        Self {
            scope: "retained_keys",
            order: "distinct_file_entries_desc_then_category_value_status_utf8",
            retained_keys_considered: analyzed.then_some(considered),
            retained_shared_keys: analyzed.then_some(shared),
            keys_not_shown: analyzed.then_some(considered - entries.len()),
            key_admission_saturated: index.keys_frozen,
            indicator_artifact: "indicators.json",
            source_location_base: "source_batch_root",
            entries,
        }
    }
}
#[derive(Serialize)]
pub(super) struct Summary<'a> {
    pub kind: &'static str,
    pub schema_version: u8,
    pub source_batch_id: &'a str,
    pub processing_complete: bool,
    pub validation_filter: ValidationFilter,
    pub coverage: &'a serde_json::Value,
    pub scope: &'a serde_json::Value,
    pub counts: &'a serde_json::Value,
    pub ranking: Ranking<'a>,
    pub outcome_reasons: &'a OutcomeReasons,
    pub presentation_limits: PresentationLimits,
}
#[derive(Serialize)]
pub(super) struct PresentationLimits {
    keys: usize,
    sources_per_key: usize,
    reason_keys: usize,
    reason_bytes: usize,
}
impl From<&Limits> for PresentationLimits {
    fn from(limits: &Limits) -> Self {
        Self {
            keys: limits.summary_keys,
            sources_per_key: limits.summary_sources_per_key,
            reason_keys: limits.summary_reason_keys,
            reason_bytes: limits.summary_reason_bytes,
        }
    }
}
