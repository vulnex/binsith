//
// VULNEX -BinSith-
//
// File: validation.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Candidate,
    Validated,
    Invalid,
}

#[derive(Debug, Serialize)]
pub struct Validation {
    pub status: Status,
    pub reason: &'static str,
}

/// Bounded neighboring text in the same extracted/decoded run. Raw values and
/// offsets remain unchanged; warnings are interpretations, never corrections.
#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct Evidence {
    pub before: String,
    pub after: String,
    pub boundary_warning: Option<&'static str>,
}

fn is_builtin(name: &str, regex: &Regex) -> bool {
    static PATTERNS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| toml::from_str(include_str!("regex_patterns.toml")).unwrap())
        .get(name)
        .map(String::as_str)
        == Some(regex.as_str())
}

fn url_warning(text: &str) -> Option<&'static str> {
    static NESTED: OnceLock<Regex> = OnceLock::new();
    static TRAILER: OnceLock<Regex> = OnceLock::new();
    if NESTED
        .get_or_init(|| Regex::new(r"(?i)https?://").unwrap())
        .find_iter(text)
        .nth(1)
        .is_some()
    {
        Some("Multiple URL schemes in one match; boundary is ambiguous")
    } else if TRAILER
        .get_or_init(|| Regex::new(r"(?i)(?:\.(?:crt|crl|cer|p7c)0|/ocsp0)[^/]*$").unwrap())
        .is_match(text)
    {
        Some("Possible printable ASN.1 trailer after certificate URI; inspect source bytes")
    } else if url::Url::parse(text).ok().is_some_and(|url| {
        // A numeric suffix on an alphabetic TLD often comes from an adjacent
        // binary field. IPv4/IPv6 and IDNA A-labels do not use this heuristic.
        matches!(url.host(), Some(url::Host::Domain(host)) if host.trim_end_matches('.').rsplit('.').next().is_some_and(|label| !label.starts_with("xn--") && label.starts_with(|c: char| c.is_ascii_alphabetic()) && label.bytes().any(|b| b.is_ascii_digit())))
    }) {
        Some("Numeric suffix in alphabetic hostname final label; possible adjacent binary data")
    } else {
        None
    }
}

pub fn evidence(name: &str, regex: &Regex, value: &str, start: usize, end: usize) -> Evidence {
    let before: String = value[..start]
        .chars()
        .rev()
        .take(48)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Evidence {
        before,
        after: value[end..].chars().take(48).collect(),
        boundary_warning: if name == "URL" && is_builtin(name, regex) {
            url_warning(&value[start..end])
        } else {
            None
        },
    }
}

// Small bounded Base58 decoder for legacy Base58Check address formats only.
fn base58check(text: &str, payload_len: usize) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if text.len() > 64 {
        return false;
    }
    let mut bytes = vec![0u8];
    for c in text.bytes() {
        let Some(mut carry) = ALPHABET.iter().position(|&b| b == c).map(|n| n as u32) else {
            return false;
        };
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let leading = text.bytes().take_while(|&b| b == b'1').count();
    let nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let mut decoded = vec![0; leading];
    decoded.extend_from_slice(&bytes[nonzero..]);
    if decoded.len() != payload_len + 4 {
        return false;
    }
    let checksum = Sha256::digest(Sha256::digest(&decoded[..payload_len]));
    decoded[payload_len..] == checksum[..4]
}

/// None suppresses a generic API-key false positive. Custom rules stay candidates.
pub fn validate(
    name: &str,
    regex: &Regex,
    value: &str,
    start: usize,
    end: usize,
) -> Option<Validation> {
    static BUILT_INS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    let built_ins = BUILT_INS.get_or_init(|| {
        toml::from_str(include_str!("regex_patterns.toml")).expect("bundled patterns are tested")
    });
    let result = |status, reason| Some(Validation { status, reason });
    if built_ins.get(name).map(String::as_str) != Some(regex.as_str()) {
        return result(
            Status::Candidate,
            "Custom regex match; no built-in validation applied",
        );
    }
    let text = &value[start..end];
    match name {
        "litecoin" | "zcash" => {
            if base58check(text, if name == "zcash" { 22 } else { 21 }) {
                result(
                    Status::Validated,
                    "Base58Check length and checksum passed; ownership and activity unknown",
                )
            } else {
                result(
                    Status::Invalid,
                    "Base58Check length, alphabet, or checksum failed",
                )
            }
        }
        "file_path" => {
            // A slash inside a URL is not independent evidence of a local file.
            let mut context_start = start.saturating_sub(192);
            while !value.is_char_boundary(context_start) {
                context_start += 1;
            }
            let context = &value[context_start..start];
            // Match the built-in URL delimiters so neighboring quoted fields
            // cannot make an independent path look like part of a URL.
            let prefix = context
                .rsplit(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`'))
                .next()
                .unwrap_or("");
            if prefix.contains(":/") || prefix.ends_with(':') && text.starts_with("//") {
                return result(
                    Status::Invalid,
                    "Path-shaped fragment inside a URL; not evidence of a local file",
                );
            }
            result(
                Status::Candidate,
                "Path shape matched; local-file existence and provenance not checked",
            )
        }
        "credit_card" => {
            let digits: Vec<_> = text
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .map(|b| b - b'0')
                .collect();
            if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
                return result(Status::Invalid, "Implausible payment-card number");
            }
            let sum: u32 = digits
                .iter()
                .rev()
                .enumerate()
                .map(|(i, &digit)| {
                    let n = if i % 2 == 1 { digit * 2 } else { digit };
                    u32::from(if n > 9 { n - 9 } else { n })
                })
                .sum();
            if sum.is_multiple_of(10) {
                result(
                    Status::Validated,
                    "13–19 digits and Luhn checksum passed; issuance and account status unknown",
                )
            } else {
                result(Status::Invalid, "Luhn checksum failed")
            }
        }
        "URL" => {
            // Preserve evidence verbatim; parser normalization is never substituted.
            let parsed = url::Url::parse(text);
            if text.contains('\\')
                || text.chars().any(char::is_control)
                || text.as_bytes().iter().enumerate().any(|(i, b)| {
                    *b == b'%'
                        && (i + 2 >= text.len()
                            || !text.as_bytes()[i + 1].is_ascii_hexdigit()
                            || !text.as_bytes()[i + 2].is_ascii_hexdigit())
                })
            {
                return result(Status::Invalid, "Invalid URL escape or separator");
            }
            match parsed {
                Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
                    if let Some(reason) = url_warning(text) {
                        return result(Status::Candidate, reason);
                    }
                    if let Some(url::Host::Domain(host)) = url.host() {
                        if !host.contains('.')
                            || host.trim_end_matches('.').split('.').any(|label| {
                                label.is_empty()
                                    || label.starts_with('-')
                                    || label.ends_with('-')
                                    || !label
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            })
                        {
                            return result(
                                Status::Candidate,
                                "Nonstandard or single-label hostname; inspect context before use",
                            );
                        }
                    }
                    result(
                        Status::Validated,
                        "HTTP(S) URL syntax passed; destination and reachability not checked",
                    )
                }
                _ => result(Status::Invalid, "Invalid HTTP(S) URL syntax"),
            }
        }
        "ip_address" => {
            let token_char = |c: char| c.is_alphanumeric() || c == '_' || c == '.';
            if value[..start].chars().next_back().is_some_and(token_char)
                || value[end..].chars().next().is_some_and(token_char)
            {
                return None;
            }
            if text.parse::<std::net::Ipv4Addr>().is_ok() {
                result(
                    Status::Validated,
                    "IPv4 syntax passed; reachability not checked",
                )
            } else {
                result(Status::Invalid, "Invalid IPv4 syntax")
            }
        }
        "guid" => result(
            Status::Validated,
            "UUID hexadecimal grouping passed; version and provenance not checked",
        ),
        "mac" => {
            let separator = text.as_bytes()[2];
            if [5, 8, 11, 14]
                .iter()
                .all(|&i| text.as_bytes()[i] == separator)
            {
                result(
                    Status::Validated,
                    "48-bit MAC syntax passed; assignment not checked",
                )
            } else {
                result(Status::Invalid, "Mixed MAC address separators")
            }
        }
        "api_key" => {
            static CONTEXT: OnceLock<Regex> = OnceLock::new();
            let context = CONTEXT.get_or_init(|| Regex::new(r#"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret)["']?\s*[:=]\s*["']?$"#).unwrap());
            let mut prefix_start = start.saturating_sub(96);
            while !value.is_char_boundary(prefix_start) {
                prefix_start += 1;
            }
            if !context.is_match(&value[prefix_start..start]) {
                return None;
            }
            result(
                Status::Candidate,
                "32–64 character token in a key/secret assignment; authenticity not checked",
            )
        }
        _ => result(
            Status::Candidate,
            "Regex shape matched; no semantic validation implemented",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realistic_validation_fixtures() {
        let patterns: BTreeMap<String, String> =
            toml::from_str(include_str!("regex_patterns.toml")).unwrap();
        let fixtures: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/validation.json")).unwrap();
        for fixture in fixtures {
            let name = fixture["pattern"].as_str().unwrap();
            let input = fixture["input"].as_str().unwrap();
            let expected = fixture["status"].as_str().unwrap();
            let regex = Regex::new(&patterns[name]).unwrap();
            let found: Vec<_> = regex
                .find_iter(input)
                .filter_map(|m| validate(name, &regex, input, m.start(), m.end()))
                .collect();
            if expected == "suppressed" {
                assert!(found.is_empty(), "{input}");
            } else {
                assert!(!found.is_empty(), "no match: {input}");
                for result in found {
                    assert_eq!(
                        serde_json::to_value(&result.status).unwrap(),
                        expected,
                        "{input}"
                    );
                    assert!(!result.reason.is_empty());
                }
            }
        }
    }

    #[test]
    fn custom_patterns_are_not_reinterpreted_by_name() {
        let regex = Regex::new("custom-value").unwrap();
        for name in ["api_key", "credit_card", "mac", "ip_address"] {
            let validation = validate(name, &regex, "custom-value", 0, 12).unwrap();
            assert_eq!(validation.status, Status::Candidate);
            assert!(validation.reason.contains("Custom"));
        }
    }
}

/// Trim prose delimiters only for the bundled URL rule.
pub fn match_end(name: &str, regex: &Regex, value: &str, start: usize, end: usize) -> usize {
    if name != "URL" {
        return end;
    }
    static URL_PATTERN: OnceLock<String> = OnceLock::new();
    let builtin = URL_PATTERN.get_or_init(|| {
        let patterns: BTreeMap<String, String> =
            toml::from_str(include_str!("regex_patterns.toml")).unwrap();
        patterns["URL"].clone()
    });
    if regex.as_str() != builtin {
        return end;
    }
    let mut text = &value[start..end];
    // Count once so adversarial runs of closing brackets stay linear.
    let mut excess = [
        text.matches(')')
            .count()
            .saturating_sub(text.matches('(').count()),
        text.matches(']')
            .count()
            .saturating_sub(text.matches('[').count()),
        text.matches('}')
            .count()
            .saturating_sub(text.matches('{').count()),
    ];
    while let Some(last) = text.chars().next_back() {
        let bracket = match last {
            ')' => Some(0),
            ']' => Some(1),
            '}' => Some(2),
            _ => None,
        };
        let unmatched = bracket.is_some_and(|i| excess[i] > 0);
        if matches!(last, '.' | ',' | ';' | '!') || unmatched {
            if let Some(i) = bracket {
                excess[i] -= 1;
            }
            text = &text[..text.len() - last.len_utf8()];
        } else {
            break;
        }
    }
    start + text.len()
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    fn check(name: &str, text: &str) -> Validation {
        let p: BTreeMap<String, String> =
            toml::from_str(include_str!("regex_patterns.toml")).unwrap();
        let r = Regex::new(&p[name]).unwrap();
        let m = r.find(text).unwrap();
        validate(name, &r, text, m.start(), m.end()).unwrap()
    }
    #[test]
    fn observed_wallet_false_positives_fail_checksums() {
        assert_eq!(
            check("litecoin", "MaxReceiveBufferPerConnection").status,
            Status::Invalid
        );
        assert_eq!(
            check("zcash", "t16int32int64uint8arraysliceGreekSHabc").status,
            Status::Invalid
        );
    }
    #[test]
    fn base58check_known_vector_and_mutation() {
        assert_eq!(
            check("litecoin", "LKDxGDJq5fF4FohAB8zJH24mDDNHDNtqsE").status,
            Status::Validated
        );
        assert_eq!(
            check("zcash", "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs").status,
            Status::Validated
        );
        assert!(base58check("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", 21));
        assert!(!base58check("1BoatSLRHtKNngkdXEeobR76b53LETtpyU", 21));
        assert!(!base58check("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", 22));
        assert!(!base58check("0000", 21));
    }
    #[test]
    fn ambiguous_urls_are_not_validated_and_invalid_stays_invalid() {
        for text in [
            "https://example.com/a.crt0E",
            "https://example.com/ahttps://example.org/",
            "http://Descriptionrelatively",
            "http://.css",
            "http://ocsp.example.com0A",
            "http://example.com/ocsp0f",
            "http://example.com/root.p7c0#",
        ] {
            assert_eq!(check("URL", text).status, Status::Candidate, "{text}");
        }
        assert_eq!(
            check("URL", "https://example.com/%zzhttps://example.org").status,
            Status::Invalid
        );
        assert_eq!(
            check("URL", "http://192.0.2.1/path").status,
            Status::Validated
        );
        assert_eq!(
            check("URL", "http://example.xn--p1ai/path").status,
            Status::Validated
        );
        assert_eq!(
            check("URL", "https://example.com/a.crt").status,
            Status::Validated
        );
    }
    #[test]
    fn url_path_fragments_are_not_local_file_evidence() {
        assert_eq!(
            check("file_path", "http://31.77.227.121/bins/parm").status,
            Status::Invalid
        );
        assert_eq!(
            check("file_path", "/tmp/notes.txt").status,
            Status::Candidate
        );
    }
    #[test]
    fn unicode_whitespace_before_path_does_not_split_a_codepoint() {
        for separator in ['\u{2001}', '\u{00a0}', '\u{3000}'] {
            let input = format!("prefix{separator}/tmp/file.txt");
            assert_eq!(check("file_path", &input).status, Status::Candidate);
            let input = format!("prefix{separator}https://example.org/file.txt");
            assert_eq!(check("file_path", &input).status, Status::Invalid);
        }
    }
    #[test]
    fn context_is_bounded_unicode_safe_and_custom_rules_uninterpreted() {
        let value = format!("{}TOKEN{}", "😀".repeat(100), "é".repeat(100));
        let r = Regex::new("TOKEN").unwrap();
        let e = evidence("URL", &r, &value, 400, 405);
        assert_eq!(e.before.chars().count(), 48);
        assert_eq!(e.after.chars().count(), 48);
        assert!(e.boundary_warning.is_none());
        let r = Regex::new(".*").unwrap();
        assert_eq!(
            validate("litecoin", &r, "MaxReceiveBufferPerConnection", 0, 28)
                .unwrap()
                .status,
            Status::Candidate
        );
    }
}
