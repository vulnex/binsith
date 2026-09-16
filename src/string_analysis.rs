use base64::{engine::general_purpose::STANDARD, Engine};
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct StringFinding {
    pub offset: usize,
    pub encoding: &'static str,
    pub extraction: &'static str,
    pub length: usize,
    pub value: String,
    pub matches: Vec<String>,
    pub has_actionable_match: bool,
    pub match_details: Vec<MatchDetail>,
    pub match_details_truncated: bool,
    pub decoded: Option<String>,
    pub decoded_layers: Vec<DecodedLayer>,
    pub truncated: bool,
    pub decode_status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DecodedLayer {
    pub depth: usize,
    pub encoding: &'static str,
    pub source_offset: usize,
    pub source_end_offset: usize,
    pub offset_space: &'static str,
    pub text: String,
    pub matches: Vec<String>,
    pub has_actionable_match: bool,
    pub match_details: Vec<MatchDetail>,
    pub match_details_truncated: bool,
    pub next_decode: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MatchDetail {
    pub pattern: String,
    pub text: String,
    pub offset: usize,
    /// Exclusive byte offset in the original input.
    pub end_offset: usize,
    pub validation: crate::validation::Validation,
}

// Bound repeated/overlapping custom-pattern results as well as string storage.
const MAX_MATCH_DETAILS: usize = 1000;
const MAX_MATCH_TEXT_BYTES: usize = 1024 * 1024;

fn locate_matches(
    value: &str,
    offset: usize,
    encoding: &str,
    patterns: &[(String, Regex)],
) -> (Vec<String>, Vec<MatchDetail>, bool, bool) {
    // Regex offsets refer to UTF-8 text; UTF-16 requires original-byte boundaries.
    let boundaries = if encoding.starts_with("UTF-16") {
        let mut map = vec![0; value.len() + 1];
        let mut bytes = 0;
        for (index, c) in value.char_indices() {
            map[index] = bytes;
            bytes += c.len_utf16() * 2;
            map[index + c.len_utf8()] = bytes;
        }
        Some(map)
    } else {
        None
    };
    let absolute = |index: usize| offset + boundaries.as_ref().map(|b| b[index]).unwrap_or(index);
    let mut categories = Vec::new();
    let mut details = Vec::new();
    let mut text_bytes = 0;
    let mut omitted = false;
    let mut actionable = false;
    for (name, regex) in patterns {
        let mut category_added = false;
        for matched in regex.find_iter(value) {
            let end =
                crate::validation::match_end(name, regex, value, matched.start(), matched.end());
            let matched_text = &value[matched.start()..end];
            let Some(validation) =
                crate::validation::validate(name, regex, value, matched.start(), end)
            else {
                continue;
            };
            actionable |= validation.status != crate::validation::Status::Invalid;
            if !category_added {
                categories.push(name.clone());
                category_added = true;
            }
            if details.len() >= MAX_MATCH_DETAILS
                || matched_text.len() > MAX_MATCH_TEXT_BYTES - text_bytes
            {
                omitted = true;
                continue;
            }
            text_bytes += matched_text.len();
            details.push(MatchDetail {
                pattern: name.clone(),
                text: matched_text.into(),
                offset: absolute(matched.start()),
                end_offset: absolute(end),
                validation,
            });
        }
    }
    (categories, details, omitted, actionable)
}

#[derive(Clone, Copy, Debug, Default, Serialize, clap::ValueEnum)]
pub enum Encoding {
    #[default]
    Auto,
    Utf8,
    Utf16le,
    Utf16be,
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_string_bytes: usize,
    pub max_decode_bytes: usize,
    pub min_length: usize,
    pub decode_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_string_bytes: 1024 * 1024,
            max_decode_bytes: 256 * 1024,
            min_length: 4,
            decode_depth: 1,
        }
    }
}

#[derive(Default)]
struct Run {
    value: String,
    length: usize,
    truncated: bool,
    ascii: bool,
}
impl Run {
    fn is_empty(&self) -> bool {
        self.length == 0
    }
    fn push(&mut self, c: char, limit: usize) {
        if self.length == 0 {
            self.ascii = true;
        }
        self.length += 1;
        self.ascii &= c.is_ascii();
        if !self.truncated && c.len_utf8() <= limit.saturating_sub(self.value.len()) {
            self.value.push(c);
        } else {
            self.truncated = true;
        }
    }
}

pub fn load_patterns(
    path: Option<&str>,
) -> Result<Vec<(String, Regex)>, Box<dyn std::error::Error>> {
    let source = match path {
        Some(path) => std::fs::read_to_string(path)?,
        None => include_str!("regex_patterns.toml").to_owned(),
    };
    let patterns: std::collections::BTreeMap<String, String> = toml::from_str(&source)?;
    patterns
        .into_iter()
        .map(|(name, pattern)| {
            Regex::new(&pattern)
                .map(|regex| (name.clone(), regex))
                .map_err(|e| format!("invalid pattern {name}: {e}").into())
        })
        .collect()
}

fn base64_shape(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    !body.is_empty()
        && text.len() % 4 == 0
        && text.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}
fn decoded_size(text: &str) -> usize {
    (text.len() / 4 * 3).saturating_sub(text.len() - text.trim_end_matches('=').len())
}
fn decode_text(text: &str) -> Option<String> {
    STANDARD
        .decode(text)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty())
}

fn finish_run(
    run: &mut Run,
    offset: usize,
    encoding: &'static str,
    patterns: &[(String, Regex)],
    decode: bool,
    only_matches: bool,
    limits: Limits,
) -> Option<StringFinding> {
    let Run {
        value,
        length,
        truncated,
        ascii,
    } = std::mem::take(run);
    if length < limits.min_length {
        return None;
    }
    // Do not run regexes against a prefix: anchors could produce false matches.
    let (matches, match_details, match_details_truncated, has_actionable_match) = if truncated {
        (Vec::new(), Vec::new(), false, false)
    } else {
        locate_matches(&value, offset, encoding, patterns)
    };
    let mut decoded = None;
    let mut decoded_layers = Vec::new();
    let mut decode_status = if !decode || limits.decode_depth == 0 {
        "disabled"
    } else if truncated {
        "truncated"
    } else {
        "not_utf8_base64"
    };
    if decode && limits.decode_depth > 0 && !truncated {
        // Token matching does not cross punctuation or padding. One shared byte
        // budget and a candidate cap bound all chains in an extracted run.
        static TOKENS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let tokens = TOKENS.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]+={0,2}").unwrap());
        let candidates: Vec<_> = if base64_shape(&value) {
            vec![(0, value.len())]
        } else {
            tokens
                .find_iter(&value)
                .filter(|m| m.len() >= 8 && base64_shape(m.as_str()))
                .take(129)
                .map(|m| (m.start(), m.end()))
                .collect()
        };
        if candidates.len() > 128 {
            decode_status = "limit";
        }
        let mut used = 0usize;
        for (start, end) in candidates.into_iter().take(128) {
            let candidate = &value[start..end];
            if decoded_size(candidate) > limits.max_decode_bytes.saturating_sub(used) {
                decode_status = "limit";
                continue;
            }
            let Some(mut text) = decode_text(candidate) else {
                continue;
            };
            used += text.len();
            if decoded.is_none() {
                decoded = Some(text.clone());
            }
            if decode_status != "limit" {
                decode_status = "decoded";
            }
            let raw_position = |index: usize| {
                offset
                    + if encoding.starts_with("UTF-16") {
                        value[..index].encode_utf16().count() * 2
                    } else {
                        index
                    }
            };
            for depth in 1..=limits.decode_depth.min(8) {
                let (categories, details, omitted, actionable) =
                    locate_matches(&text, 0, "UTF-8", patterns);
                let (next, state) = if !base64_shape(&text) {
                    (None, "not_utf8_base64")
                } else if depth == limits.decode_depth.min(8) {
                    (None, "depth_limit")
                } else if decoded_size(&text) > limits.max_decode_bytes.saturating_sub(used) {
                    (None, "byte_limit")
                } else {
                    match decode_text(&text) {
                        Some(next) => (Some(next), "decoded"),
                        None => (None, "not_utf8_base64"),
                    }
                };
                decoded_layers.push(DecodedLayer {
                    depth,
                    encoding: "base64",
                    source_offset: raw_position(start),
                    source_end_offset: raw_position(end),
                    offset_space: "decoded_layer_utf8",
                    text,
                    matches: categories,
                    has_actionable_match: actionable,
                    match_details: details,
                    match_details_truncated: omitted,
                    next_decode: state,
                });
                match next {
                    Some(next) => {
                        used += next.len();
                        text = next;
                    }
                    None => break,
                }
            }
        }
    }
    // Matching-only mode also retains indicators found in decoded layers.
    if only_matches
        && matches.is_empty()
        && decoded_layers.iter().all(|l| l.matches.is_empty())
        && !truncated
        && decode_status != "limit"
        && !match_details_truncated
        && !decoded_layers.iter().any(|l| {
            l.match_details_truncated || matches!(l.next_decode, "byte_limit" | "depth_limit")
        })
    {
        return None;
    }
    Some(StringFinding {
        offset,
        encoding: if encoding == "UTF-8" && ascii {
            "ASCII"
        } else {
            encoding
        },
        extraction: "text",
        length,
        value,
        matches,
        has_actionable_match,
        match_details,
        match_details_truncated,
        decoded,
        decoded_layers,
        truncated,
        decode_status,
    })
}

/// Streams findings as runs end, retaining at most the configured prefix.
pub fn analyze_reader_with_encoding(
    reader: impl std::io::Read,
    patterns: &[(String, Regex)],
    decode: bool,
    only_matches: bool,
    limits: Limits,
    selected: Encoding,
    mut emit: impl FnMut(StringFinding) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::{BufReader, Read};
    let mut bytes = BufReader::with_capacity(65536, reader).bytes();
    let first = bytes.next().transpose()?;
    let second = bytes.next().transpose()?;
    let bom = match (first, second) {
        (Some(255), Some(254)) => Some(true),
        (Some(254), Some(255)) => Some(false),
        _ => None,
    };
    let utf16 = match selected {
        Encoding::Auto => bom,
        Encoding::Utf8 => None,
        Encoding::Utf16le => Some(true),
        Encoding::Utf16be => Some(false),
    };
    if let (Some(declared), Some(chosen)) = (bom, utf16) {
        if declared != chosen {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UTF-16 BOM conflicts with selected encoding",
            ));
        }
    }
    let skip_bom = utf16.is_some() && bom == utf16;
    let prefix = if skip_bom {
        Vec::new()
    } else {
        first.into_iter().chain(second).collect::<Vec<_>>()
    };
    let mut bytes = prefix.into_iter().map(Ok).chain(bytes);
    let mut run = Run::default();
    let mut start = 0;
    let mut flush = |run: &mut Run, offset, encoding| -> std::io::Result<()> {
        if let Some(finding) = finish_run(
            run,
            offset,
            encoding,
            patterns,
            decode,
            only_matches,
            limits,
        ) {
            emit(finding)?;
        }
        Ok(())
    };
    if let Some(little) = utf16 {
        let encoding = if little { "UTF-16LE" } else { "UTF-16BE" };
        let mut offset = if skip_bom { 2 } else { 0 };
        let mut pending = None;
        loop {
            let (unit, position) = if let Some(unit) = pending.take() {
                unit
            } else {
                let Some(a) = bytes.next().transpose()? else {
                    break;
                };
                let Some(b) = bytes.next().transpose()? else {
                    break;
                };
                let unit = if little {
                    u16::from_le_bytes([a, b])
                } else {
                    u16::from_be_bytes([a, b])
                };
                let position = offset;
                offset += 2;
                (unit, position)
            };
            let c = if (0xd800..=0xdbff).contains(&unit) {
                match (bytes.next().transpose()?, bytes.next().transpose()?) {
                    (Some(a), Some(b)) => {
                        let low = if little {
                            u16::from_le_bytes([a, b])
                        } else {
                            u16::from_be_bytes([a, b])
                        };
                        let low_offset = offset;
                        offset += 2;
                        if (0xdc00..=0xdfff).contains(&low) {
                            char::from_u32(
                                0x10000 + ((unit as u32 - 0xd800) << 10) + (low as u32 - 0xdc00),
                            )
                        } else {
                            pending = Some((low, low_offset));
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                char::from_u32(unit as u32)
            };
            match c {
                Some(c) if !c.is_control() => {
                    if run.is_empty() {
                        start = position;
                    }
                    run.push(c, limits.max_string_bytes);
                }
                _ => flush(&mut run, start, encoding)?,
            }
        }
        flush(&mut run, start, encoding)?;
    } else {
        let mut offset = 0;
        let mut sequence = Vec::with_capacity(4);
        let mut sequence_start = 0;
        while let Some(byte) = bytes.next() {
            let byte = byte?;
            if sequence.is_empty() {
                sequence_start = offset;
            }
            sequence.push(byte);
            offset += 1;
            loop {
                match std::str::from_utf8(&sequence) {
                    Ok(text) => {
                        for c in text.chars() {
                            if c.is_control() {
                                flush(&mut run, start, "UTF-8")?;
                            } else {
                                if run.is_empty() {
                                    start = sequence_start;
                                }
                                run.push(c, limits.max_string_bytes);
                            }
                        }
                        sequence.clear();
                        break;
                    }
                    Err(e) if e.error_len().is_none() => break,
                    Err(e) => {
                        flush(&mut run, start, "UTF-8")?;
                        let skip = e.error_len().unwrap();
                        sequence.drain(..skip);
                        sequence_start += skip;
                        if sequence.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
        flush(&mut run, start, "UTF-8")?;
    }
    Ok(())
}

/// Scan conservative ASCII-range UTF-16 candidates at either byte alignment.
/// Both byte orders are candidates; overlapping interpretations may be emitted.
pub fn scan_embedded_utf16(
    reader: impl std::io::Read,
    patterns: &[(String, Regex)],
    decode: bool,
    only_matches: bool,
    limits: Limits,
    mut emit: impl FnMut(StringFinding) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::{BufReader, Read};
    let mut runs: [Run; 4] = std::array::from_fn(|_| Run::default());
    let mut starts = [0usize; 4];
    let mut previous = None;
    for (position, byte) in BufReader::with_capacity(65536, reader).bytes().enumerate() {
        let byte = byte?;
        if let Some(first) = previous {
            let start = position - 1;
            for (order, little) in [true, false].into_iter().enumerate() {
                let index = order * 2 + start % 2;
                let unit = if little {
                    u16::from_le_bytes([first, byte])
                } else {
                    u16::from_be_bytes([first, byte])
                };
                if (32..=126).contains(&unit) {
                    if runs[index].is_empty() {
                        starts[index] = start;
                    }
                    runs[index].push(
                        char::from_u32(unit as u32).unwrap(),
                        limits.max_string_bytes,
                    );
                } else if let Some(mut finding) = finish_run(
                    &mut runs[index],
                    starts[index],
                    if little { "UTF-16LE" } else { "UTF-16BE" },
                    patterns,
                    decode,
                    only_matches,
                    limits,
                ) {
                    finding.extraction = "embedded_utf16_candidate";
                    emit(finding)?;
                }
            }
        }
        previous = Some(byte);
    }
    for index in 0..4 {
        if let Some(mut finding) = finish_run(
            &mut runs[index],
            starts[index],
            if index < 2 { "UTF-16LE" } else { "UTF-16BE" },
            patterns,
            decode,
            only_matches,
            limits,
        ) {
            finding.extraction = "embedded_utf16_candidate";
            emit(finding)?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn analyze_reader(
    reader: impl std::io::Read,
    patterns: &[(String, Regex)],
    decode: bool,
    only_matches: bool,
    limits: Limits,
    emit: impl FnMut(StringFinding) -> std::io::Result<()>,
) -> std::io::Result<()> {
    analyze_reader_with_encoding(
        reader,
        patterns,
        decode,
        only_matches,
        limits,
        Encoding::Auto,
        emit,
    )
}

#[cfg(test)]
fn analyze(
    content: &[u8],
    patterns: &[(String, Regex)],
    decode: bool,
    only_matches: bool,
) -> Vec<StringFinding> {
    let mut findings = Vec::new();
    analyze_reader(
        content,
        patterns,
        decode,
        only_matches,
        Limits::default(),
        |f| {
            findings.push(f);
            Ok(())
        },
    )
    .unwrap();
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Short<'a> {
        bytes: &'a [u8],
        max: usize,
    }
    impl std::io::Read for Short<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = buffer.len().min(self.max).min(self.bytes.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }
    #[test]
    fn explicit_bomless_utf16_preserves_unicode_and_offsets() {
        for (little, selected) in [(true, Encoding::Utf16le), (false, Encoding::Utf16be)] {
            let mut bytes = Vec::new();
            for unit in "abc😀 café\0tail".encode_utf16() {
                bytes.extend_from_slice(&if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let patterns = vec![("word".into(), Regex::new("café").unwrap())];
            let mut found = Vec::new();
            analyze_reader_with_encoding(
                Short {
                    bytes: &bytes,
                    max: 1,
                },
                &patterns,
                false,
                false,
                Limits::default(),
                selected,
                |f| {
                    found.push(f);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(found[0].offset, 0);
            assert_eq!(found[0].value, "abc😀 café");
            assert_eq!(found[0].match_details[0].offset, 12);
            assert_eq!(found[0].match_details[0].end_offset, 20);
            assert_eq!(found[1].offset, 22);
        }
    }

    #[test]
    fn selected_encoding_handles_matching_and_conflicting_boms() {
        let bytes = [255, 254, b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0];
        let mut found = Vec::new();
        analyze_reader_with_encoding(
            &bytes[..],
            &[],
            false,
            false,
            Limits::default(),
            Encoding::Utf16le,
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(found[0].value, "hello");
        assert_eq!(found[0].offset, 2);
        let error = analyze_reader_with_encoding(
            &bytes[..],
            &[],
            false,
            false,
            Limits::default(),
            Encoding::Utf16be,
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let mut found = Vec::new();
        analyze_reader_with_encoding(
            &b"\xff\xfehello"[..],
            &[],
            false,
            false,
            Limits::default(),
            Encoding::Utf8,
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(found[0].value, "hello");
        assert_eq!(found[0].offset, 2);
    }

    #[test]
    fn embedded_scan_checks_both_alignments_and_byte_orders() {
        for little in [true, false] {
            for prefix_length in [2, 3, 65535] {
                let mut bytes = vec![0xff; prefix_length];
                for unit in "https://example.com".encode_utf16() {
                    bytes.extend_from_slice(&if little {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    });
                }
                bytes.extend_from_slice(&[0, 0, 255]);
                let patterns = load_patterns(None).unwrap();
                let mut found = Vec::new();
                scan_embedded_utf16(
                    Short {
                        bytes: &bytes,
                        max: 3,
                    },
                    &patterns,
                    false,
                    false,
                    Limits::default(),
                    |f| {
                        found.push(f);
                        Ok(())
                    },
                )
                .unwrap();
                let encoding = if little { "UTF-16LE" } else { "UTF-16BE" };
                let hit = found
                    .iter()
                    .find(|f| f.encoding == encoding && f.offset == prefix_length)
                    .unwrap();
                assert_eq!(hit.value, "https://example.com");
                assert_eq!(hit.extraction, "embedded_utf16_candidate");
                let detail = hit
                    .match_details
                    .iter()
                    .find(|m| m.pattern == "URL")
                    .unwrap();
                assert_eq!(detail.offset, prefix_length);
                assert_eq!(detail.end_offset, prefix_length + 38);
            }
        }
    }

    #[test]
    fn embedded_scan_rejects_short_runs_and_respects_limits() {
        let mut found = Vec::new();
        scan_embedded_utf16(
            &b"\xffa\0b\0c\0\0\0"[..],
            &[],
            false,
            false,
            Limits::default(),
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        assert!(found.is_empty());
        scan_embedded_utf16(
            &b"\xffa\0b\0c\0d\0e\0f\0"[..],
            &[],
            true,
            true,
            Limits {
                max_string_bytes: 4,
                max_decode_bytes: 2,
                ..Limits::default()
            },
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        let hit = found
            .iter()
            .find(|f| f.offset == 1 && f.encoding == "UTF-16LE")
            .unwrap();
        assert_eq!(hit.value, "abcd");
        assert_eq!(hit.length, 6);
        assert!(hit.truncated);
        assert!(hit.match_details.is_empty());
    }

    #[test]
    fn embedded_scan_propagates_output_errors() {
        let error = scan_embedded_utf16(
            &b"a\0b\0c\0d\0\0\0"[..],
            &[],
            false,
            false,
            Limits::default(),
            |_| Err(std::io::Error::other("output failed")),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "output failed");
    }

    #[test]
    fn match_spans_preserve_repeated_utf8_occurrences_and_categories() {
        let patterns = vec![
            ("word".into(), Regex::new("café").unwrap()),
            ("suffix".into(), Regex::new("fé").unwrap()),
        ];
        let bytes = "\0😀 café café\0".as_bytes();
        let found = analyze(bytes, &patterns, false, false);
        assert_eq!(found[0].matches, ["word", "suffix"]);
        let details = &found[0].match_details;
        assert_eq!(details.len(), 4);
        assert_eq!((details[0].offset, details[0].end_offset), (6, 11));
        assert_eq!((details[1].offset, details[1].end_offset), (12, 17));
        for detail in details {
            assert_eq!(
                &bytes[detail.offset..detail.end_offset],
                detail.text.as_bytes()
            );
        }
    }

    #[test]
    fn utf16_spans_map_surrogates_and_short_reads_to_source_bytes() {
        let patterns = vec![("hit".into(), Regex::new("😀 café").unwrap())];
        for little in [true, false] {
            let mut bytes = if little {
                vec![255, 254]
            } else {
                vec![254, 255]
            };
            for unit in "abc😀 café tail".encode_utf16() {
                bytes.extend_from_slice(&if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let mut found = Vec::new();
            analyze_reader(
                Short {
                    bytes: &bytes,
                    max: 1,
                },
                &patterns,
                false,
                false,
                Limits::default(),
                |f| {
                    found.push(f);
                    Ok(())
                },
            )
            .unwrap();
            let detail = &found[0].match_details[0];
            assert_eq!((detail.offset, detail.end_offset), (8, 22));
            let units: Vec<_> = bytes[detail.offset..detail.end_offset]
                .chunks_exact(2)
                .map(|c| {
                    if little {
                        u16::from_le_bytes([c[0], c[1]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]])
                    }
                })
                .collect();
            assert_eq!(String::from_utf16(&units).unwrap(), detail.text);
        }
    }

    #[test]
    fn detail_limits_preserve_category_list_and_signal_omissions() {
        let patterns = vec![
            ("many".into(), Regex::new("a").unwrap()),
            ("whole".into(), Regex::new("^a+$").unwrap()),
        ];
        let found = analyze(&vec![b'a'; MAX_MATCH_DETAILS + 1], &patterns, false, false);
        assert_eq!(found[0].match_details.len(), MAX_MATCH_DETAILS);
        assert!(found[0].match_details_truncated);
        assert_eq!(found[0].matches, ["many", "whole"]);
        let text = "a".repeat(MAX_MATCH_TEXT_BYTES / 2 + 1);
        let patterns = vec![
            ("first".into(), Regex::new("^a+$").unwrap()),
            ("second".into(), Regex::new("^a+$").unwrap()),
        ];
        let (_, details, omitted, _) = locate_matches(&text, 0, "UTF-8", &patterns);
        assert_eq!(details.len(), 1);
        assert!(omitted);
    }

    #[test]
    fn zero_width_and_exact_cap_are_unambiguous() {
        let patterns = vec![("start".into(), Regex::new("^").unwrap())];
        let found = analyze(b"\0abcd", &patterns, false, false);
        assert_eq!(found[0].match_details[0].text, "");
        assert_eq!(
            (
                found[0].match_details[0].offset,
                found[0].match_details[0].end_offset
            ),
            (1, 1)
        );
        let patterns = vec![("many".into(), Regex::new("a").unwrap())];
        let found = analyze(&vec![b'a'; MAX_MATCH_DETAILS], &patterns, false, false);
        assert!(!found[0].match_details_truncated);
    }

    #[test]
    fn bundled_pattern_fixture_coverage() {
        let patterns = load_patterns(None).unwrap();
        let fixtures: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/patterns.json")).unwrap();
        let names: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), patterns.len());
        for (name, regex) in patterns {
            let fixture = fixtures
                .iter()
                .find(|f| f["name"] == name)
                .expect("fixture for every pattern");
            assert!(
                regex.is_match(fixture["positive"].as_str().unwrap()),
                "positive: {name}"
            );
            assert!(
                !regex.is_match(fixture["negative"].as_str().unwrap()),
                "negative: {name}"
            );
        }
    }

    #[test]
    fn limits_preserve_offsets_counts_and_do_not_classify_prefixes() {
        let patterns = vec![("prefix".into(), Regex::new("^aaaa$").unwrap())];
        let mut found = Vec::new();
        analyze_reader(
            &b"aaaaaaaaaa\0done"[..],
            &patterns,
            true,
            true,
            Limits {
                max_string_bytes: 4,
                max_decode_bytes: 2,
                ..Limits::default()
            },
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].value, "done");
        assert_eq!(found[1].decode_status, "limit");
        assert_eq!(found[0].value, "aaaa");
        assert_eq!(found[0].length, 10);
        assert!(found[0].truncated);
        assert!(found[0].matches.is_empty());
        assert!(found[0].match_details.is_empty());
        assert_eq!(found[0].decode_status, "truncated");
        for little in [true, false] {
            let mut bytes = if little {
                vec![255, 254]
            } else {
                vec![254, 255]
            };
            for unit in "abc😀def\0tail".encode_utf16() {
                bytes.extend_from_slice(&if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let mut found = Vec::new();
            analyze_reader(
                &bytes[..],
                &[],
                false,
                false,
                Limits {
                    max_string_bytes: 4,
                    max_decode_bytes: 2,
                    ..Limits::default()
                },
                |f| {
                    found.push(f);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(found[0].value, "abc");
            assert_eq!(found[0].length, 7);
            assert!(found[0].truncated);
            assert_eq!(found[1].offset, 20);
            assert!(!found[1].truncated);
        }
    }

    #[test]
    fn decode_limit_includes_exact_padded_boundary() {
        for (limit, expected) in [(4, "limit"), (5, "decoded")] {
            let mut found = Vec::new();
            analyze_reader(
                &b"aGVsbG8="[..],
                &[],
                true,
                false,
                Limits {
                    max_string_bytes: 32,
                    max_decode_bytes: limit,
                    ..Limits::default()
                },
                |f| {
                    found.push(f);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(found[0].decode_status, expected);
            assert_eq!(found[0].decoded.is_some(), limit == 5);
        }
    }

    #[test]
    fn large_run_retention_is_bounded_and_next_offset_is_correct() {
        use std::io::Read;
        let bytes = std::io::repeat(b'a')
            .take(8 * 1024 * 1024)
            .chain(&b"\0done"[..]);
        let mut found = Vec::new();
        analyze_reader(
            bytes,
            &[],
            false,
            false,
            Limits {
                max_string_bytes: 64,
                max_decode_bytes: 32,
                ..Limits::default()
            },
            |f| {
                found.push(f);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(found[0].value.len(), 64);
        assert_eq!(found[0].length, 8 * 1024 * 1024);
        assert_eq!(found[1].offset, 8 * 1024 * 1024 + 1);
    }

    #[test]
    fn short_reads_utf8_and_utf16_surrogates() {
        let utf8 = b"\xffhello caf\xc3\xa9\0world\xe2!abcd\0tail\xe2";
        for max in 1..=7 {
            let mut found = Vec::new();
            analyze_reader(
                Short { bytes: utf8, max },
                &[],
                false,
                false,
                Limits::default(),
                |f| {
                    found.push(f);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                found.iter().map(|f| f.value.as_str()).collect::<Vec<_>>(),
                ["hello café", "world", "!abcd", "tail"]
            );
            assert_eq!(
                found.iter().map(|f| f.offset).collect::<Vec<_>>(),
                [1, 13, 19, 25]
            );
            for little in [true, false] {
                let mut bytes = if little {
                    vec![255, 254]
                } else {
                    vec![254, 255]
                };
                for unit in "abc😀def\0tail".encode_utf16() {
                    bytes.extend_from_slice(&if little {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    });
                }
                let mut found = Vec::new();
                analyze_reader(
                    Short { bytes: &bytes, max },
                    &[],
                    false,
                    false,
                    Limits::default(),
                    |f| {
                        found.push(f);
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(found[0].value, "abc😀def");
                assert_eq!(found[0].length, 7);
                assert_eq!(found[1].value, "tail");
                assert_eq!(found[1].offset, 20);
            }
        }
    }
    #[test]
    fn long_run_crosses_buffer_boundary() {
        let mut bytes = vec![b'a'; 65535];
        bytes.extend_from_slice("éworld\0done".as_bytes());
        let found = analyze(&bytes, &[], false, false);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].length, 65541);
        assert!(found[0].value.ends_with("éworld"));
        assert_eq!(found[1].offset, 65543);
    }
    #[test]
    fn emits_before_eof_and_propagates_failures() {
        struct FailAfterRun(bool);
        impl std::io::Read for FailAfterRun {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("read failed"));
                }
                self.0 = true;
                buffer[..6].copy_from_slice(b"hello\0");
                Ok(6)
            }
        }
        let mut count = 0;
        let result = analyze_reader(
            FailAfterRun(false),
            &[],
            false,
            false,
            Limits::default(),
            |_| {
                count += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(count, 1);
        let result = analyze_reader(
            &b"hello\0world"[..],
            &[],
            false,
            false,
            Limits::default(),
            |_| Err(std::io::Error::other("write failed")),
        );
        assert_eq!(result.unwrap_err().to_string(), "write failed");
    }
    #[test]
    fn unicode_offsets_and_multiple_matches() {
        let patterns = vec![
            ("one".into(), Regex::new("hello").unwrap()),
            ("two".into(), Regex::new("world").unwrap()),
        ];
        let f = analyze("\0hello world\0café\0".as_bytes(), &patterns, false, false);
        assert_eq!(f[0].offset, 1);
        assert_eq!(f[0].matches, ["one", "two"]);
        assert_eq!(f[1].encoding, "UTF-8");
        let f = analyze(
            &[255, 254, 104, 0, 101, 0, 108, 0, 108, 0, 111, 0],
            &patterns,
            false,
            false,
        );
        assert_eq!(f[0].value, "hello");
        assert_eq!(f[0].offset, 2);
    }
    #[test]
    fn bundled_patterns_and_decode() {
        assert!(!load_patterns(None).unwrap().is_empty());
        let f = analyze(b"aGVsbG8=", &[], true, false);
        assert_eq!(f[0].decoded.as_deref(), Some("hello"));
        assert!(analyze(b"aGVsbG8=", &[], false, false)[0].decoded.is_none());
    }
}

#[cfg(test)]
#[path = "robustness_tests.rs"]
mod robustness_tests;
