//! Bounded, case-sensitive matching over native filename units. No filesystem I/O.
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeEncoding {
    #[serde(rename = "unix-bytes")]
    Unix,
    #[serde(rename = "windows-utf16")]
    Windows,
}
impl NativeEncoding {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionConfiguration {
    pub grammar: String,
    pub native_encoding: NativeEncoding,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub max_depth: Option<u64>,
    #[serde(deserialize_with = "super::records::required_nullable")]
    pub max_file_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Literal(u16),
    Any,
    Star,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    GlobStar,
    Pattern(Vec<Token>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    parts: Vec<Part>,
    directory: bool,
}

impl Rule {
    fn compile(source: &str, exclude: bool, encoding: NativeEncoding) -> Result<Self, String> {
        let invalid = || "invalid native_glob_v1 selection pattern".to_string();
        let directory = source.ends_with('/');
        if directory && !exclude {
            return Err("directory patterns are only allowed with --exclude".into());
        }
        let source = if directory {
            &source[..source.len() - 1]
        } else {
            source
        };
        if source.is_empty() || source.as_bytes().get(1) == Some(&b':') {
            return Err(invalid());
        }
        let mut parts = Vec::new();
        for component in source.split('/') {
            if parts.len() == 256 || component.is_empty() {
                return Err(invalid());
            }
            if component == "**" {
                parts.push(Part::GlobStar);
                continue;
            }
            let mut tokens = Vec::new();
            let mut chars = component.chars();
            while let Some(c) = chars.next() {
                let literal = match c {
                    '*' => {
                        if tokens.last() == Some(&Token::Star) {
                            return Err(invalid());
                        }
                        tokens.push(Token::Star);
                        continue;
                    }
                    '?' => {
                        tokens.push(Token::Any);
                        continue;
                    }
                    '\\' => match chars.next().ok_or_else(invalid)? {
                        c @ ('*' | '?' | '\\' | '[' | ']' | '{' | '}' | '!') => Some(c as u16),
                        kind @ ('x' | 'u') => {
                            if (kind == 'x') != (encoding == NativeEncoding::Unix) {
                                return Err(invalid());
                            }
                            let mut unit = 0_u16;
                            for _ in 0..if kind == 'x' { 2 } else { 4 } {
                                unit = unit * 16
                                    + chars
                                        .next()
                                        .and_then(|c| c.to_digit(16))
                                        .ok_or_else(invalid)?
                                        as u16;
                            }
                            Some(unit)
                        }
                        _ => return Err(invalid()),
                    },
                    '[' | ']' | '{' | '}' | '!' => return Err(invalid()),
                    _ => {
                        match encoding {
                            NativeEncoding::Unix => {
                                let mut bytes = [0; 4];
                                tokens.extend(
                                    c.encode_utf8(&mut bytes)
                                        .bytes()
                                        .map(|b| Token::Literal(u16::from(b))),
                                );
                            }
                            NativeEncoding::Windows => {
                                let mut units = [0; 2];
                                tokens.extend(
                                    c.encode_utf16(&mut units)
                                        .iter()
                                        .copied()
                                        .map(Token::Literal),
                                );
                            }
                        }
                        None
                    }
                };
                if let Some(unit) = literal {
                    tokens.push(Token::Literal(unit));
                }
            }
            if tokens.iter().any(|t| matches!(t, Token::Literal(0 | 47)))
                || (encoding == NativeEncoding::Windows
                    && tokens.iter().any(|t| matches!(t, Token::Literal(58 | 92))))
                || tokens == [Token::Literal(46)]
                || tokens == [Token::Literal(46), Token::Literal(46)]
            {
                return Err(invalid());
            }
            parts.push(Part::Pattern(tokens));
        }
        Ok(Self { parts, directory })
    }

    fn matches(&self, components: &[Vec<u16>]) -> bool {
        // Two bounded NFA state vectors; ** consumes components, never recurses.
        let mut states = vec![false; self.parts.len() + 1];
        states[0] = true;
        for i in 0..self.parts.len() {
            if self.parts[i] == Part::GlobStar && states[i] {
                states[i + 1] = true;
            }
        }
        for component in components {
            let mut next = vec![false; states.len()];
            for (i, part) in self.parts.iter().enumerate() {
                if states[i] {
                    match part {
                        Part::GlobStar => next[i] = true,
                        Part::Pattern(tokens) => {
                            next[i + 1] |= component_matches(tokens, component)
                        }
                    }
                }
            }
            for i in 0..self.parts.len() {
                if self.parts[i] == Part::GlobStar && next[i] {
                    next[i + 1] = true;
                }
            }
            states = next;
        }
        states[self.parts.len()]
    }
}

fn component_matches(tokens: &[Token], units: &[u16]) -> bool {
    let mut states = vec![false; tokens.len() + 1];
    let mut next = states.clone();
    states[0] = true;
    for i in 0..tokens.len() {
        if tokens[i] == Token::Star && states[i] {
            states[i + 1] = true;
        }
    }
    for unit in units {
        next.fill(false);
        for (i, token) in tokens.iter().enumerate() {
            if states[i] {
                match token {
                    Token::Star => next[i] = true,
                    Token::Any => next[i + 1] = true,
                    Token::Literal(c) if c == unit => next[i + 1] = true,
                    _ => (),
                }
            }
        }
        for i in 0..tokens.len() {
            if tokens[i] == Token::Star && next[i] {
                next[i + 1] = true;
            }
        }
        std::mem::swap(&mut states, &mut next);
    }
    states[tokens.len()]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionReason {
    Excluded,
    Depth,
    NotIncluded,
    Size,
}
impl SelectionReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::Excluded => "selection_excluded",
            Self::Depth => "selection_depth",
            Self::NotIncluded => "selection_not_included",
            Self::Size => "selection_size",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    configuration: SelectionConfiguration,
    includes: Vec<Rule>,
    excludes: Vec<Rule>,
}
impl Selection {
    pub fn compile(configuration: SelectionConfiguration, recursive: bool) -> Result<Self, String> {
        if configuration.grammar != "native_glob_v1" {
            return Err("unsupported selection grammar".into());
        }
        if configuration.max_depth.is_some() && !recursive {
            return Err("--max-depth requires --recursive".into());
        }
        let rules = configuration.includes.iter().chain(&configuration.excludes);
        if configuration
            .includes
            .len()
            .saturating_add(configuration.excludes.len())
            > 128
            || rules.clone().any(|r| r.len() > 4096)
            || rules.map(String::len).sum::<usize>() > 65536
        {
            return Err(
                "selection patterns exceed 128 rules, 4096 bytes per rule or 65536 total bytes"
                    .into(),
            );
        }
        let compile = |sources: &[String], exclude| {
            sources
                .iter()
                .map(|s| Rule::compile(s, exclude, configuration.native_encoding))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            includes: compile(&configuration.includes, false)?,
            excludes: compile(&configuration.excludes, true)?,
            configuration,
        })
    }
    pub fn configuration(&self) -> &SelectionConfiguration {
        &self.configuration
    }
    pub fn size_excluded(&self, size: u64) -> bool {
        self.configuration
            .max_file_bytes
            .is_some_and(|max| size > max)
    }
    pub fn path_reason(&self, path: &Path, directory: bool) -> Option<SelectionReason> {
        let components: Vec<Vec<u16>> = path
            .components()
            .filter_map(|part| {
                let Component::Normal(name) = part else {
                    return None;
                };
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    Some(name.as_bytes().iter().map(|b| u16::from(*b)).collect())
                }
                #[cfg(windows)]
                {
                    use std::os::windows::ffi::OsStrExt;
                    Some(name.encode_wide().collect())
                }
            })
            .collect();
        if self
            .excludes
            .iter()
            .any(|r| r.directory == directory && r.matches(&components))
        {
            return Some(SelectionReason::Excluded);
        }
        if directory {
            // Entering a directory at depth d would expose files at d + 1.
            if self
                .configuration
                .max_depth
                .is_some_and(|max| components.len().saturating_sub(1) as u64 >= max)
            {
                return Some(SelectionReason::Depth);
            }
        } else if !self.includes.is_empty() && !self.includes.iter().any(|r| r.matches(&components))
        {
            return Some(SelectionReason::NotIncluded);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_matches(pattern: &str, path: &str, encoding: NativeEncoding) -> bool {
        let parts: Vec<Vec<u16>> = path
            .split('/')
            .map(|p| match encoding {
                NativeEncoding::Unix => p.bytes().map(u16::from).collect(),
                NativeEncoding::Windows => p.encode_utf16().collect(),
            })
            .collect();
        Rule::compile(pattern, false, encoding)
            .unwrap()
            .matches(&parts)
    }

    #[test]
    fn anchored_globstar_case_and_native_units() {
        for encoding in [NativeEncoding::Unix, NativeEncoding::Windows] {
            for (pattern, path, expected) in [
                ("**/*.exe", "a.exe", true),
                ("**/*.exe", "a/b/c.exe", true),
                ("*.exe", "sub/a.exe", false),
                ("*.exe", "a.EXE", false),
                ("a/**/b", "a/b", true),
                ("a/**/b", "a/x/y/b", true),
                ("a/**/b", "a/b/c", false),
                ("**/**/a", "a", true),
                ("a*b?c", "aXXbYc", true),
                ("a*b?c", "aXXbc", false),
                ("**", "a/b", true),
                (r"a\*b", "a*b", true),
                (r"a\?b", "a?b", true),
                ("é", "é", true),
                ("é", "e\u{301}", false),
                ("*", ".hidden", true),
            ] {
                assert_eq!(
                    rule_matches(pattern, path, encoding),
                    expected,
                    "{pattern:?} {path:?} {encoding:?}"
                );
            }
        }
        assert!(rule_matches("????", "😀", NativeEncoding::Unix));
        assert!(!rule_matches("?", "é", NativeEncoding::Unix));
        assert!(rule_matches("?", "é", NativeEncoding::Windows));
        assert!(rule_matches("??", "😀", NativeEncoding::Windows));
        assert!(Rule::compile(r"bad-\xFF", false, NativeEncoding::Unix)
            .unwrap()
            .matches(&[vec![98, 97, 100, 45, 255]]));
        assert!(Rule::compile(r"bad-\uD800", false, NativeEncoding::Windows)
            .unwrap()
            .matches(&[vec![98, 97, 100, 45, 0xd800]]));
    }

    #[test]
    fn malformed_and_unsupported_patterns_fail() {
        for encoding in [NativeEncoding::Unix, NativeEncoding::Windows] {
            for pattern in [
                "", "/", "/root", "a//b", "a/./b", "a/../b", "C:/x", "a**b", "***", "a/[xy]",
                "{a,b}", "!a", "a\\", r"a\q", "a\0b",
            ] {
                assert!(
                    Rule::compile(pattern, true, encoding).is_err(),
                    "{pattern:?} {encoding:?}"
                );
            }
            assert!(Rule::compile("cache/", false, encoding).is_err());
            assert!(Rule::compile("cache/", true, encoding).unwrap().directory);
        }
        for pattern in [r"\x00", r"\x2f", r"\x2e\x2e", r"\xGG", r"\x1", r"\u0041"] {
            assert!(
                Rule::compile(pattern, false, NativeEncoding::Unix).is_err(),
                "{pattern}"
            );
        }
        for pattern in [
            r"\u0000", r"\u002f", r"\u005c", r"\u003a", r"\u002e", r"\u00GG", r"\u1", r"\x41",
            r"a\\b",
        ] {
            assert!(
                Rule::compile(pattern, false, NativeEncoding::Windows).is_err(),
                "{pattern}"
            );
        }
    }

    fn config() -> SelectionConfiguration {
        SelectionConfiguration {
            grammar: "native_glob_v1".into(),
            native_encoding: NativeEncoding::current(),
            includes: vec![],
            excludes: vec![],
            max_depth: None,
            max_file_bytes: None,
        }
    }
    #[test]
    fn configuration_budgets_and_exact_boundaries() {
        let mut c = config();
        c.includes = vec!["a".into(); 128];
        Selection::compile(c.clone(), true).unwrap();
        c.excludes.push("b".into());
        assert!(Selection::compile(c, true).is_err());
        let mut c = config();
        c.includes = vec!["a".repeat(4096)];
        Selection::compile(c.clone(), true).unwrap();
        c.includes[0].push('a');
        assert!(Selection::compile(c, true).is_err());
        let mut c = config();
        c.includes = vec!["a".repeat(4096); 16];
        Selection::compile(c.clone(), true).unwrap();
        c.includes.push("a".into());
        assert!(Selection::compile(c, true).is_err());
        assert!(Rule::compile(&vec!["a"; 256].join("/"), false, NativeEncoding::Unix).is_ok());
        assert!(Rule::compile(&vec!["a"; 257].join("/"), false, NativeEncoding::Unix).is_err());
        let mut c = config();
        c.max_depth = Some(0);
        c.max_file_bytes = Some(4);
        assert!(Selection::compile(c.clone(), false).is_err());
        let s = Selection::compile(c, true).unwrap();
        assert!(!s.size_excluded(4));
        assert!(s.size_excluded(5));
        assert_eq!(
            s.path_reason(Path::new("a"), true),
            Some(SelectionReason::Depth)
        );
        assert_eq!(s.path_reason(Path::new("a"), false), None);
    }

    #[test]
    fn includes_never_prune_and_excludes_take_precedence() {
        let mut c = config();
        c.includes = vec!["**/*.bin".into(), "**/*.txt".into()];
        c.excludes = vec!["cache/".into(), "**/bad.bin".into()];
        let s = Selection::compile(c, true).unwrap();
        for (path, directory, expected) in [
            ("cache", true, Some(SelectionReason::Excluded)),
            ("nested/cache", true, None),
            ("nested", true, None),
            ("nested/bad.bin", false, Some(SelectionReason::Excluded)),
            ("cache", false, Some(SelectionReason::NotIncluded)),
            ("nested/a.bin", false, None),
            ("a.txt", false, None),
            ("a.dat", false, Some(SelectionReason::NotIncluded)),
        ] {
            assert_eq!(s.path_reason(Path::new(path), directory), expected);
        }
    }
}
