//! Deterministic mutation/property tests, run by the normal test suite.
use super::*;
use std::io::{self, Read};

struct Chunks<'a> {
    bytes: &'a [u8],
    size: usize,
}
impl Read for Chunks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.size).min(self.bytes.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}
fn check(f: &StringFinding, input: &[u8], limits: Limits) {
    assert!(f.offset <= input.len());
    assert!(f.value.len() <= limits.max_string_bytes);
    assert!(f.match_details.len() <= MAX_MATCH_DETAILS);
    assert!(f.decoded_layers.len() <= 128 * limits.decode_depth);
    assert!(
        f.decoded_layers.iter().map(|l| l.text.len()).sum::<usize>() <= limits.max_decode_bytes
    );
    if f.truncated {
        assert!(f.matches.is_empty());
        assert!(f.decoded_layers.is_empty());
    }
    for d in &f.match_details {
        assert!(d.offset <= d.end_offset && d.end_offset <= input.len());
        let expected: Vec<u8> = match f.encoding {
            "UTF-16LE" => d.text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            "UTF-16BE" => d.text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            _ => d.text.as_bytes().to_vec(),
        };
        assert_eq!(&input[d.offset..d.end_offset], expected);
    }
    for layer in &f.decoded_layers {
        assert!(
            layer.source_offset <= layer.source_end_offset
                && layer.source_end_offset <= input.len()
        );
        assert!(layer.depth > 0 && layer.depth <= limits.decode_depth);
        assert!(layer.match_details.len() <= MAX_MATCH_DETAILS);
        for d in &layer.match_details {
            assert_eq!(
                layer.text.get(d.offset..d.end_offset),
                Some(d.text.as_str())
            );
        }
    }
}
fn scan(
    input: &[u8],
    size: usize,
    encoding: Encoding,
    embedded: bool,
    patterns: &[(String, Regex)],
) -> Result<serde_json::Value, String> {
    let limits = Limits {
        max_string_bytes: 64,
        max_decode_bytes: 48,
        min_length: 1,
        decode_depth: 3,
    };
    let mut findings = Vec::new();
    let emit = |f| {
        check(&f, input, limits);
        findings.push(f);
        Ok(())
    };
    let reader = Chunks { bytes: input, size };
    let result = if embedded {
        scan_embedded_utf16(reader, patterns, true, false, limits, emit)
    } else {
        analyze_reader_with_encoding(reader, patterns, true, false, limits, encoding, emit)
    };
    result.map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(findings).unwrap())
}
#[test]
fn mutated_inputs_preserve_bounds_offsets_and_chunk_independence() {
    let mut patterns = load_patterns(None).unwrap();
    for (name, expression) in [("zero", ""), ("overlap", "a+"), ("unicode", r"\p{L}+")] {
        patterns.push((name.into(), Regex::new(expression).unwrap()));
    }
    let seeds: Vec<Vec<u8>> = vec![
        vec![],
        b"https://example.com:443/a?x=1&y=2\0".to_vec(),
        b"config=aHR0cHM6Ly9leGFtcGxlLmNvbQ==;".to_vec(),
        b"\xff\xfe\x00\xd8x\0\x00\xdc\xff".to_vec(),
        b"\xfe\xff\xd8\0\0x\xdc\0\xff".to_vec(),
        b"a\xf0\x9f\x98\x80\xed\xa0\x80\xc0\xaf\xf4\x90\x80\x80z".to_vec(),
        "a😀é\0https://example.com"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
        vec![b'a'; 1025],
    ];
    let mut state = 0x6a09e667f3bcc909u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for case in 0..256 {
        let mut input = seeds[case % seeds.len()].clone();
        if case >= seeds.len() {
            for _ in 0..1 + next() % 12 {
                match next() % 3 {
                    0 if !input.is_empty() => {
                        let at = next() as usize % input.len();
                        input[at] ^= next() as u8;
                    }
                    1 => {
                        let at = next() as usize % (input.len() + 1);
                        input.insert(at, next() as u8);
                    }
                    _ if !input.is_empty() => {
                        input.truncate(next() as usize % (input.len() + 1));
                    }
                    _ => {}
                }
            }
        }
        for encoding in [
            Encoding::Auto,
            Encoding::Utf8,
            Encoding::Utf16le,
            Encoding::Utf16be,
        ] {
            assert_eq!(
                scan(&input, 1, encoding, false, &patterns),
                scan(&input, 65536, encoding, false, &patterns),
                "case {case}: {encoding:?}"
            );
        }
        assert_eq!(
            scan(&input, 1, Encoding::Auto, true, &patterns),
            scan(&input, 65536, Encoding::Auto, true, &patterns),
            "embedded case {case}"
        );
    }
}

#[test]
fn large_runs_nested_decoding_and_output_failures_stay_bounded() {
    let patterns = vec![("any".into(), Regex::new(".").unwrap())];
    let mut nested = "https://example.com".to_owned();
    for _ in 0..8 {
        nested = STANDARD.encode(nested);
    }
    for input in [
        vec![b'a'; 1024 * 1024],
        nested.into_bytes(),
        b"aGVsbG8=;".repeat(10000),
    ] {
        scan(&input, 4096, Encoding::Utf8, false, &patterns).unwrap();
    }
    let mut nested = "https://example.com".to_owned();
    for _ in 0..8 {
        nested = STANDARD.encode(nested);
    }
    for depth in [0, 1, 3, 8] {
        for budget in [0, 1, 32, 4096] {
            let limits = Limits {
                max_string_bytes: 4096,
                max_decode_bytes: budget,
                min_length: 1,
                decode_depth: depth,
            };
            analyze_reader_with_encoding(
                nested.as_bytes(),
                &patterns,
                true,
                false,
                limits,
                Encoding::Utf8,
                |f| {
                    check(&f, nested.as_bytes(), limits);
                    Ok(())
                },
            )
            .unwrap();
        }
    }
    let error = analyze_reader_with_encoding(
        &b"hello\0world\0"[..],
        &patterns,
        true,
        false,
        Limits::default(),
        Encoding::Auto,
        |_| Err(io::Error::other("injected output failure")),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "injected output failure");
}
