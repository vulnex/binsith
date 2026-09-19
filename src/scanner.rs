//
// VULNEX -BinSith-
//
// File: scanner.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

//! Reusable per-file JSON scanning. No global streams, destination publication,
//! filesystem discovery, or exit policy. The caller supplies the selected range.
use crate::{
    batch::AnalysisConfiguration,
    coverage::Coverage,
    entropy, file_summary,
    json_output::JsonWriter,
    string_analysis::{self, Encoding, Limits, StringFinding},
};
use std::{
    error::Error,
    fmt,
    io::{self, Read, Seek, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    fn check(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(tag(
                ScanErrorKind::Cancelled,
                io::Error::other("scan cancelled"),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanErrorKind {
    InvalidConfiguration,
    Cancelled,
    Read,
    TemporaryStorage,
    Analysis,
    Report,
}
#[derive(Debug)]
pub struct ScanError {
    pub kind: ScanErrorKind,
    source: io::Error,
}
impl ScanError {
    fn at(kind: ScanErrorKind, source: io::Error) -> Self {
        let kind = source
            .get_ref()
            .and_then(|e| e.downcast_ref::<TaggedError>())
            .map(|e| e.kind)
            .unwrap_or(kind);
        Self { kind, source }
    }
    pub fn into_io_error(self) -> io::Error {
        self.source
    }
}
impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}
impl Error for ScanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
#[derive(Debug)]
struct TaggedError {
    kind: ScanErrorKind,
    source: io::Error,
}
impl fmt::Display for TaggedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}
impl Error for TaggedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
fn tag(kind: ScanErrorKind, source: io::Error) -> io::Error {
    if source.get_ref().is_some_and(|e| e.is::<TaggedError>()) {
        return source;
    }
    io::Error::new(source.kind(), TaggedError { kind, source })
}

pub struct ScanRequest<'a> {
    pub display_path: &'a str,
    pub configuration: &'a AnalysisConfiguration,
    pub patterns: &'a [(String, regex::Regex)],
    pub metadata: &'a serde_json::Value,
}
pub struct ScanOutcome {
    pub summary: file_summary::FileSummary,
    pub coverage: Coverage,
    /// None when string analysis was not requested.
    pub has_actionable_indicators: Option<bool>,
}

struct CheckedReader<'a, R, P> {
    input: R,
    cancellation: &'a CancellationToken,
    progress: P,
    consumed: u64,
    kind: ScanErrorKind,
}
impl<R: Read, P: FnMut(u64)> Read for CheckedReader<'_, R, P> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cancellation.check()?;
        let count = self.input.read(bytes).map_err(|e| tag(self.kind, e))?;
        self.consumed = self
            .consumed
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("input byte count overflow"))?;
        if count != 0 {
            (self.progress)(self.consumed);
        }
        self.cancellation.check()?;
        Ok(count)
    }
}
struct CheckedWriter<'a, W> {
    output: W,
    cancellation: &'a CancellationToken,
    kind: ScanErrorKind,
}
impl<W: Write> Write for CheckedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation.check()?;
        self.output.write(bytes).map_err(|e| tag(self.kind, e))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.cancellation.check()?;
        self.output.flush().map_err(|e| tag(self.kind, e))
    }
}

/// Input must already be positioned and limited to the configured range. Offset
/// shifts evidence coordinates; this function never seeks/reopens the source.
/// Progress is cumulative selected-input bytes, reported once across all passes.
/// A failure may leave partial bytes in the supplied sink: the caller must publish
/// its temporary report only on success (and after its own file-identity checks).
pub fn scan_selected(
    input: impl Read,
    output: impl Write,
    request: &ScanRequest<'_>,
    cancellation: &CancellationToken,
    progress: impl FnMut(u64),
) -> Result<ScanOutcome, ScanError> {
    let config = request.configuration;
    config.validate().map_err(|e| {
        ScanError::at(
            ScanErrorKind::InvalidConfiguration,
            io::Error::new(io::ErrorKind::InvalidInput, e),
        )
    })?;
    cancellation
        .check()
        .map_err(|e| ScanError::at(ScanErrorKind::Cancelled, e))?;
    let mut input = CheckedReader {
        input,
        cancellation,
        progress,
        consumed: 0,
        kind: ScanErrorKind::Read,
    };
    // Preserve the established summary-first pipeline. One-pass optimization is FS-07.
    let mut snapshot = if config.strings || config.entropy {
        let mut file =
            tempfile::tempfile().map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
        io::copy(
            &mut input,
            &mut CheckedWriter {
                output: &mut file,
                cancellation,
                kind: ScanErrorKind::TemporaryStorage,
            },
        )
        .map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
        file.rewind()
            .map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
        Some(file)
    } else {
        None
    };
    let summary = if let Some(file) = snapshot.as_mut() {
        file_summary::summarize_reader(
            request.display_path,
            CheckedReader {
                input: file,
                cancellation,
                progress: |_| {},
                consumed: 0,
                kind: ScanErrorKind::TemporaryStorage,
            },
        )
    } else {
        file_summary::summarize_reader(request.display_path, &mut input)
    }
    .map_err(|e| ScanError::at(ScanErrorKind::Analysis, e))?;
    // Check at buffered I/O boundaries and finding/region checkpoints rather than
    // performing an atomic load for every small JSON serialization fragment.
    let writer = io::BufWriter::new(CheckedWriter {
        output,
        cancellation,
        kind: ScanErrorKind::Report,
    });
    let mut json = JsonWriter::report(
        writer,
        &summary,
        config.strings,
        false,
        config.offset,
        config.length,
    )
    .map_err(|e| ScanError::at(ScanErrorKind::Report, e))?;
    let mut coverage = Coverage::default();
    let mut matched = false;
    if config.strings {
        let mut emit = |finding: StringFinding| {
            cancellation.check()?;
            coverage.observe(&finding);
            matched |= finding.has_actionable_match
                || finding
                    .decoded_layers
                    .iter()
                    .any(|l| l.has_actionable_match);
            json.finding(&finding)
        };
        for embedded in [false, true] {
            if embedded && !config.scan_utf16 {
                continue;
            }
            let file = snapshot.as_mut().expect("string analysis owns a snapshot");
            file.rewind()
                .map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
            let reader = CheckedReader {
                input: file,
                cancellation,
                progress: |_| {},
                consumed: 0,
                kind: ScanErrorKind::TemporaryStorage,
            };
            string_pass(reader, config, request.patterns, embedded, &mut emit)
                .map_err(|e| ScanError::at(ScanErrorKind::Analysis, e))?;
        }
    }
    if config.entropy {
        json.start_entropy()
            .map_err(|e| ScanError::at(ScanErrorKind::Report, e))?;
        let file = snapshot.as_mut().expect("entropy analysis owns a snapshot");
        file.rewind()
            .map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
        let reader = CheckedReader {
            input: file,
            cancellation,
            progress: |_| {},
            consumed: 0,
            kind: ScanErrorKind::TemporaryStorage,
        };
        entropy::scan(
            reader,
            config.entropy_window,
            config.offset,
            config.entropy_threshold,
            |region| json.region(&region),
        )
        .map_err(|e| ScanError::at(ScanErrorKind::Analysis, e))?;
    }
    cancellation
        .check()
        .map_err(|e| ScanError::at(ScanErrorKind::Cancelled, e))?;
    json.finish_report(request.metadata, &coverage.report())
        .map_err(|e| ScanError::at(ScanErrorKind::Report, e))?;
    Ok(ScanOutcome {
        summary,
        coverage,
        has_actionable_indicators: config.strings.then_some(matched),
    })
}

/// Shared extraction pass for ordinary, live, comparison, and folder reports.
pub fn string_pass(
    reader: impl Read,
    config: &AnalysisConfiguration,
    patterns: &[(String, regex::Regex)],
    embedded: bool,
    mut emit: impl FnMut(StringFinding) -> io::Result<()>,
) -> io::Result<()> {
    let base = usize::try_from(config.offset)
        .map_err(|_| io::Error::other("offset exceeds platform address range"))?;
    let mut adjust = |mut finding: StringFinding| {
        let shift = |n: usize| {
            n.checked_add(base)
                .ok_or_else(|| io::Error::other("offset overflow"))
        };
        finding.offset = shift(finding.offset)?;
        for detail in &mut finding.match_details {
            detail.offset = shift(detail.offset)?;
            detail.end_offset = shift(detail.end_offset)?;
        }
        for layer in &mut finding.decoded_layers {
            layer.source_offset = shift(layer.source_offset)?;
            layer.source_end_offset = shift(layer.source_end_offset)?;
        }
        emit(finding)
    };
    let limits = Limits {
        max_string_bytes: config.max_string_bytes,
        max_decode_bytes: config.max_decode_bytes,
        min_length: config.min_length,
        decode_depth: config.decode_depth as usize,
    };
    let decode = !config.no_decode && config.max_decode_bytes > 0;
    if embedded {
        string_analysis::scan_embedded_utf16(
            reader,
            patterns,
            decode,
            config.matches_only,
            limits,
            &mut adjust,
        )
    } else {
        let encoding = match config.encoding.as_str() {
            "auto" => Encoding::Auto,
            "utf8" => Encoding::Utf8,
            "utf16le" => Encoding::Utf16le,
            "utf16be" => Encoding::Utf16be,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown encoding",
                ))
            }
        };
        string_analysis::analyze_reader_with_encoding(
            reader,
            patterns,
            decode,
            config.matches_only,
            limits,
            encoding,
            &mut adjust,
        )
    }
}
