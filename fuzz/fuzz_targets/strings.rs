//
// VULNEX -BinSith-
//
// File: strings.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

#![no_main]

// Compile production sources directly; avoid copying parser implementations or
// exposing a public library API solely for the fuzz harness.
#[path = "../../src/string_analysis.rs"]
mod string_analysis;
#[path = "../../src/validation.rs"]
mod validation;

use libfuzzer_sys::fuzz_target;
use regex::Regex;
use std::{io, sync::OnceLock};
use string_analysis::{Encoding, Limits, StringFinding};

struct Chunks<'a> {
    input: &'a [u8],
    size: usize,
}
impl io::Read for Chunks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.size).min(self.input.len());
        out[..n].copy_from_slice(&self.input[..n]);
        self.input = &self.input[n..];
        Ok(n)
    }
}
fn inspect(f: &StringFinding, input: &[u8], limits: Limits) {
    assert!(f.offset <= input.len());
    assert!(f.value.len() <= limits.max_string_bytes);
    assert!(f.match_details.len() <= 1000);
    if f.truncated {
        assert!(f.matches.is_empty());
        assert!(f.decoded_layers.is_empty());
    }
    for detail in &f.match_details {
        assert!(detail.offset <= detail.end_offset && detail.end_offset <= input.len());
        let text: Vec<u8> = match f.encoding {
            "UTF-16LE" => detail
                .text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
            "UTF-16BE" => detail
                .text
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect(),
            _ => detail.text.as_bytes().to_vec(),
        };
        assert_eq!(&input[detail.offset..detail.end_offset], text);
    }
    assert!(f.decoded_layers.len() <= 128 * limits.decode_depth);
    assert!(
        f.decoded_layers.iter().map(|l| l.text.len()).sum::<usize>() <= limits.max_decode_bytes
    );
    for layer in &f.decoded_layers {
        assert!(layer.depth > 0 && layer.depth <= limits.decode_depth);
        assert!(
            layer.source_offset <= layer.source_end_offset
                && layer.source_end_offset <= input.len()
        );
        assert!(layer.match_details.len() <= 1000);
        for detail in &layer.match_details {
            assert_eq!(
                layer.text.get(detail.offset..detail.end_offset),
                Some(detail.text.as_str())
            );
        }
    }
}
fn scan(
    data: &[u8],
    size: usize,
    patterns: &[(String, Regex)],
) -> Result<serde_json::Value, String> {
    let limits = Limits {
        max_string_bytes: 4 + data[2] as usize * 4,
        max_decode_bytes: data[3] as usize * 4,
        decode_depth: data[4] as usize % 9,
        min_length: 1 + data[5] as usize % 8,
    };
    let input = &data[6..];
    let reader = Chunks { input, size };
    let mut findings = Vec::new();
    let emit = |finding| {
        inspect(&finding, input, limits);
        findings.push(finding);
        Ok(())
    };
    let decode = data[1] & 1 != 0;
    let matching_only = data[1] & 2 != 0;
    let mode = data[0] % 5;
    let result = if mode == 4 {
        string_analysis::scan_embedded_utf16(reader, patterns, decode, matching_only, limits, emit)
    } else {
        let encoding = [
            Encoding::Auto,
            Encoding::Utf8,
            Encoding::Utf16le,
            Encoding::Utf16be,
        ][mode as usize];
        string_analysis::analyze_reader_with_encoding(
            reader,
            patterns,
            decode,
            matching_only,
            limits,
            encoding,
            emit,
        )
    };
    result.map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(findings).unwrap())
}

fuzz_target!(|data: &[u8]| {
    if !(6..=8192).contains(&data.len()) {
        return;
    }
    static PATTERNS: OnceLock<Vec<(String, Regex)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        let mut patterns = string_analysis::load_patterns(None).unwrap();
        for (name, regex) in [
            ("zero_width", ""),
            ("overlap", "a+"),
            ("letters", r"\p{L}+"),
        ] {
            patterns.push((name.into(), Regex::new(regex).unwrap()));
        }
        patterns
    });
    assert_eq!(scan(data, 1, patterns), scan(data, 65536, patterns));
});
