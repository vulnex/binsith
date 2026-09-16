use regex::Regex;
use serde::Serialize;
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
            if sum % 10 == 0 {
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
