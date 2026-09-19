//
// VULNEX -BinSith-
//
// File: comparison.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use crate::{entropy, file_summary::FileSummary, string_analysis::StringFinding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io};

const MAX_ENTRIES: usize = 10000;
const MAX_POSITIONS: usize = 8;
const MAX_REGIONS: usize = 1000;

#[derive(Debug, Serialize, PartialEq)]
pub struct Entry {
    pub kind: String,
    pub preview: String,
    pub preview_truncated: bool,
    pub count: u64,
    pub offsets: Vec<usize>,
    pub offsets_truncated: bool,
}
#[derive(Default)]
pub struct Index {
    strings: BTreeMap<String, Entry>,
    indicators: BTreeMap<String, Entry>,
    pub incomplete: bool,
}
fn insert(map: &mut BTreeMap<String, Entry>, kind: &str, text: &str, offset: usize) -> bool {
    let mut hash = Sha256::new();
    hash.update((kind.len() as u64).to_le_bytes());
    hash.update(kind);
    hash.update(text);
    let key = format!("{:x}", hash.finalize());
    if !map.contains_key(&key) && map.len() >= MAX_ENTRIES {
        return false;
    }
    let e = map.entry(key).or_insert_with(|| Entry {
        kind: kind.into(),
        preview: text.chars().take(256).collect(),
        preview_truncated: text.chars().count() > 256,
        count: 0,
        offsets: Vec::new(),
        offsets_truncated: false,
    });
    e.count += 1;
    if e.offsets.len() < MAX_POSITIONS {
        e.offsets.push(offset);
    } else {
        e.offsets_truncated = true;
    }
    !e.offsets_truncated
}
impl Index {
    pub fn add(&mut self, finding: &StringFinding) {
        if finding.truncated {
            self.incomplete = true;
        }
        let kind = format!("{}:{}", finding.encoding, finding.extraction);
        self.incomplete |= !insert(&mut self.strings, &kind, &finding.value, finding.offset);
        self.incomplete |= finding.match_details_truncated;
        for d in &finding.match_details {
            let kind = format!("{}:{:?}", d.pattern, d.validation.status);
            self.incomplete |= !insert(&mut self.indicators, &kind, &d.text, d.offset);
        }
        for layer in &finding.decoded_layers {
            self.incomplete |= !insert(
                &mut self.strings,
                &format!("decoded-{}", layer.depth),
                &layer.text,
                layer.source_offset,
            );
            self.incomplete |= layer.match_details_truncated;
            for d in &layer.match_details {
                let kind = format!(
                    "decoded-{}:{}:{:?}",
                    layer.depth, d.pattern, d.validation.status
                );
                self.incomplete |=
                    !insert(&mut self.indicators, &kind, &d.text, layer.source_offset);
            }
        }
    }
}
#[derive(Serialize)]
pub struct Changed {
    pub before: Entry,
    pub after: Entry,
}
#[derive(Serialize)]
pub struct Difference {
    pub added: Vec<Entry>,
    pub removed: Vec<Entry>,
    pub changed: Vec<Changed>,
}
fn difference(mut before: BTreeMap<String, Entry>, after: BTreeMap<String, Entry>) -> Difference {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (key, right) in after {
        match before.remove(&key) {
            None => added.push(right),
            Some(left) if left != right => changed.push(Changed {
                before: left,
                after: right,
            }),
            _ => (),
        }
    }
    Difference {
        added,
        removed: before.into_values().collect(),
        changed,
    }
}
#[derive(Serialize)]
pub struct EntropyChange {
    pub offset: u64,
    pub before: Option<entropy::Region>,
    pub after: Option<entropy::Region>,
}
#[derive(Serialize)]
pub struct Comparison {
    pub other_summary: FileSummary,
    pub identical_content: bool,
    pub strings: Difference,
    pub indicators: Difference,
    pub incomplete_index: bool,
    pub position_sample_limit: usize,
    pub entropy_changes: Vec<EntropyChange>,
    pub entropy_changes_omitted: u64,
}
#[expect(
    clippy::too_many_arguments,
    reason = "Paired input streams/indexes and entropy settings are explicit at this internal boundary"
)]
pub fn compare(
    left_summary: &FileSummary,
    other_summary: FileSummary,
    before: Index,
    after: Index,
    mut left: impl io::Read,
    mut right: impl io::Read,
    base: u64,
    window: usize,
    threshold: f64,
) -> io::Result<Comparison> {
    let mut offset = base;
    let mut changes = Vec::new();
    let mut omitted = 0;
    loop {
        let a = entropy::next_region(&mut left, window, offset, threshold)?;
        let b = entropy::next_region(&mut right, window, offset, threshold)?;
        if a.is_none() && b.is_none() {
            break;
        }
        let differs = match (&a, &b) {
            (Some(a), Some(b)) => a.length != b.length || (a.entropy - b.entropy).abs() > 1e-9,
            _ => true,
        };
        if differs {
            if changes.len() < MAX_REGIONS {
                changes.push(EntropyChange {
                    offset,
                    before: a,
                    after: b,
                });
            } else {
                omitted += 1;
            }
        }
        offset = offset
            .checked_add(window as u64)
            .ok_or_else(|| io::Error::other("offset overflow"))?;
    }
    Ok(Comparison {
        identical_content: left_summary.sha256 == other_summary.sha256,
        other_summary,
        strings: difference(before.strings, after.strings),
        indicators: difference(before.indicators, after.indicators),
        incomplete_index: before.incomplete || after.incomplete,
        position_sample_limit: MAX_POSITIONS,
        entropy_changes: changes,
        entropy_changes_omitted: omitted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn index_bounds_and_position_sampling_are_explicit() {
        let mut map = BTreeMap::new();
        for i in 0..MAX_ENTRIES {
            assert!(insert(&mut map, "text", &format!("value-{i}"), i));
        }
        assert!(!insert(&mut map, "text", "extra", 0));
        assert_eq!(map.len(), MAX_ENTRIES);
        let mut map = BTreeMap::new();
        for i in 0..MAX_POSITIONS {
            assert!(insert(&mut map, "text", "same", i));
        }
        assert!(!insert(&mut map, "text", "same", 50));
        let entry = map.values().next().unwrap();
        assert_eq!(entry.count, 9);
        assert!(entry.offsets_truncated);
    }
}
