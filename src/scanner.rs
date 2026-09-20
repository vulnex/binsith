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

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    parent: Option<Arc<CancellationState>>,
}
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<CancellationState>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        let mut state = self.0.as_ref();
        loop {
            if state.cancelled.load(Ordering::Relaxed) {
                return true;
            }
            match state.parent.as_deref() {
                Some(parent) => state = parent,
                None => return false,
            }
        }
    }
    /// Cancelling a child stops its workers without labelling the caller interrupted.
    pub(crate) fn child(&self) -> Self {
        Self(Arc::new(CancellationState {
            cancelled: AtomicBool::new(false),
            parent: Some(self.0.clone()),
        }))
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
        #[cfg(test)]
        if self.kind == ScanErrorKind::TemporaryStorage {
            crate::batch::faults::hit(crate::batch::faults::Point::SnapshotWrite)
                .map_err(|e| tag(self.kind, e))?;
        }
        let count = self.output.write(bytes).map_err(|e| tag(self.kind, e))?;
        self.cancellation.check()?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.cancellation.check()?;
        self.output.flush().map_err(|e| tag(self.kind, e))?;
        self.cancellation.check()
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
    scan_with_snapshot(
        input,
        output,
        request,
        cancellation,
        progress,
        || {
            #[cfg(test)]
            crate::batch::faults::hit(crate::batch::faults::Point::SnapshotCreate)?;
            tempfile::tempfile()
        },
        &|_| cancellation.check(),
    )
}

// Injection seam keeps filesystem failures and cleanup tests deterministic without
// process-global temporary-directory changes or timing-dependent cancellation.
fn scan_with_snapshot<S: Read + Write + Seek>(
    input: impl Read,
    output: impl Write,
    request: &ScanRequest<'_>,
    cancellation: &CancellationToken,
    progress: impl FnMut(u64),
    snapshot_factory: impl FnOnce() -> io::Result<S>,
    checkpoint: &impl Fn(string_analysis::Checkpoint) -> io::Result<()>,
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
    if config.strings && !config.scan_utf16 && !config.entropy {
        return scan_one_pass(input, output, request, cancellation, checkpoint);
    }
    // Extra analysis passes retain a private snapshot of the selected range.
    let mut snapshot = if config.strings || config.entropy {
        let mut file =
            snapshot_factory().map_err(|e| ScanError::at(ScanErrorKind::TemporaryStorage, e))?;
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
            string_pass_checked(
                reader,
                config,
                request.patterns,
                embedded,
                &mut emit,
                checkpoint,
            )
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
            |region| {
                cancellation.check()?;
                json.region(&region)
            },
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

/// Basic strings and summary share the selected-input read. No snapshot or
/// retained findings collection is needed; only JSON field order changes.
fn scan_one_pass(
    input: impl Read,
    output: impl Write,
    request: &ScanRequest<'_>,
    cancellation: &CancellationToken,
    checkpoint: &impl Fn(string_analysis::Checkpoint) -> io::Result<()>,
) -> Result<ScanOutcome, ScanError> {
    let config = request.configuration;
    let mut observed = file_summary::SummaryReader::new(input, None);
    let writer = io::BufWriter::new(CheckedWriter {
        output,
        cancellation,
        kind: ScanErrorKind::Report,
    });
    let mut json =
        JsonWriter::strings_first(writer).map_err(|e| ScanError::at(ScanErrorKind::Report, e))?;
    let mut coverage = Coverage::default();
    let mut matched = false;
    string_pass_checked(
        &mut observed,
        config,
        request.patterns,
        false,
        |finding| {
            cancellation.check()?;
            coverage.observe(&finding);
            matched |= finding.has_actionable_match
                || finding
                    .decoded_layers
                    .iter()
                    .any(|layer| layer.has_actionable_match);
            json.finding(&finding)
        },
        checkpoint,
    )
    .map_err(|e| ScanError::at(ScanErrorKind::Analysis, e))?;
    cancellation
        .check()
        .map_err(|e| ScanError::at(ScanErrorKind::Cancelled, e))?;
    let (summary, _) = observed.finish(request.display_path);
    json.finish_with_summary(
        &summary,
        config.offset,
        config.length,
        request.metadata,
        &coverage.report(),
    )
    .map_err(|e| ScanError::at(ScanErrorKind::Report, e))?;
    Ok(ScanOutcome {
        summary,
        coverage,
        has_actionable_indicators: Some(matched),
    })
}

/// Shared extraction pass for ordinary, live, comparison, and folder reports.
pub fn string_pass(
    reader: impl Read,
    config: &AnalysisConfiguration,
    patterns: &[(String, regex::Regex)],
    embedded: bool,
    emit: impl FnMut(StringFinding) -> io::Result<()>,
) -> io::Result<()> {
    string_pass_checked(reader, config, patterns, embedded, emit, &|_| Ok(()))
}

fn string_pass_checked(
    reader: impl Read,
    config: &AnalysisConfiguration,
    patterns: &[(String, regex::Regex)],
    embedded: bool,
    mut emit: impl FnMut(StringFinding) -> io::Result<()>,
    checkpoint: &impl Fn(string_analysis::Checkpoint) -> io::Result<()>,
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
        string_analysis::scan_embedded_utf16_checked(
            reader,
            patterns,
            decode,
            config.matches_only,
            limits,
            &mut adjust,
            checkpoint,
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
        string_analysis::analyze_reader_with_encoding_checked(
            reader,
            patterns,
            decode,
            config.matches_only,
            limits,
            encoding,
            &mut adjust,
            checkpoint,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{batch::Manifest, string_analysis::Checkpoint};
    use std::{cell::Cell, io::SeekFrom};

    fn configuration() -> AnalysisConfiguration {
        let manifest: Manifest = serde_json::from_str(include_str!(
            "../tests/fixtures/batch/manifest-interrupted.json"
        ))
        .unwrap();
        manifest.configuration.analysis
    }

    fn request(config: &AnalysisConfiguration) -> ScanRequest<'_> {
        ScanRequest {
            display_path: "test",
            configuration: config,
            patterns: &[],
            metadata: &serde_json::Value::Null,
        }
    }

    // A real owned temporary file with deterministic failures at the snapshot
    // boundaries. Closing this wrapper must also unlink the file on every exit.
    struct Snapshot<'a> {
        file: tempfile::NamedTempFile,
        operation: &'a str,
        target_pass: usize,
        pass: usize,
        cancellation: &'a CancellationToken,
    }
    impl Read for Snapshot<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.pass == self.target_pass {
                if self.operation == "read" {
                    return Err(io::Error::other("snapshot read failed"));
                }
                if self.operation == "cancel" {
                    self.cancellation.cancel();
                }
            }
            self.file.read(bytes)
        }
    }
    impl Write for Snapshot<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.operation == "write" {
                return Err(io::Error::other("snapshot write failed"));
            }
            self.file.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    impl Seek for Snapshot<'_> {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.pass += 1;
            if self.operation == "seek" && self.pass == self.target_pass {
                return Err(io::Error::other("snapshot seek failed"));
            }
            self.file.seek(position)
        }
    }

    #[test]
    fn snapshot_cleanup_on_success_and_failures_in_every_pass() {
        let mut config = configuration();
        config.scan_utf16 = true;
        config.entropy = true;
        config.entropy_window = 4;
        let request = request(&config);
        for operation in [
            "success",
            "write",
            "read",
            "seek",
            "cancel",
            "source_cancel",
        ] {
            // Summary, primary strings, embedded UTF-16, entropy.
            for target_pass in 1..=4 {
                let token = CancellationToken::default();
                let file = tempfile::NamedTempFile::new().unwrap();
                let path = file.path().to_owned();
                let snapshot = Snapshot {
                    file,
                    operation,
                    target_pass,
                    pass: 0,
                    cancellation: &token,
                };
                let result = scan_with_snapshot(
                    &b"hello world\0"[..],
                    io::sink(),
                    &request,
                    &token,
                    |_| {
                        if operation == "source_cancel" {
                            token.cancel();
                        }
                    },
                    || Ok(snapshot),
                    &|_| token.check(),
                );
                assert!(
                    !path.exists(),
                    "{operation} pass {target_pass} leaked snapshot"
                );
                if operation == "success" {
                    assert!(result.is_ok());
                } else {
                    let error = result.err().unwrap();
                    assert_eq!(
                        error.kind,
                        if operation.contains("cancel") {
                            ScanErrorKind::Cancelled
                        } else {
                            ScanErrorKind::TemporaryStorage
                        }
                    );
                }
            }
        }
        let error = scan_with_snapshot(
            io::empty(),
            io::sink(),
            &request,
            &CancellationToken::default(),
            |_| {},
            || {
                Err::<std::fs::File, _>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "create failed",
                ))
            },
            &|_| Ok(()),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ScanErrorKind::TemporaryStorage);
        assert_eq!(
            error.into_io_error().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn analysis_and_nested_decode_cancel_before_emission_and_remove_snapshot() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(base64::engine::general_purpose::STANDARD.encode(b"https://example.com"));
        let patterns = vec![("custom".into(), regex::Regex::new("never-matches").unwrap())];
        for stage in [
            Checkpoint::Extraction,
            Checkpoint::Matching,
            Checkpoint::Decode,
        ] {
            for (stop_at, scan_utf16) in [1, 4]
                .into_iter()
                .flat_map(|n| [false, true].map(|extra| (n, extra)))
            {
                let mut config = configuration();
                config.decode_depth = 3;
                config.scan_utf16 = scan_utf16;
                config.matches_only = true;
                let mut request = request(&config);
                request.patterns = &patterns;
                let token = CancellationToken::default();
                let count = Cell::new(0);
                let file = tempfile::NamedTempFile::new().unwrap();
                let path = file.path().to_owned();
                let data = format!("{encoded}\0{encoded}\0{encoded}\0");
                let mut output = Vec::new();
                let error = scan_with_snapshot(
                    data.as_bytes(),
                    &mut output,
                    &request,
                    &token,
                    |_| {},
                    || Ok(file),
                    &|current| {
                        if current == stage {
                            count.set(count.get() + 1);
                            if count.get() == stop_at {
                                token.cancel();
                            }
                        }
                        token.check()
                    },
                )
                .err()
                .unwrap();
                assert_eq!(error.kind, ScanErrorKind::Cancelled, "{stage:?}");
                assert_eq!(count.get(), stop_at);
                assert!(!path.exists());
                assert!(serde_json::from_slice::<serde_json::Value>(&output).is_err());
            }
        }
    }

    #[test]
    fn buffered_extraction_and_embedded_pass_honor_checkpoints() {
        for embedded in [false, true] {
            for encoding in ["utf8", "utf16le", "utf16be"] {
                let mut config = configuration();
                config.encoding = encoding.into();
                let token = CancellationToken::default();
                let calls = Cell::new(0);
                let data = if embedded || encoding != "utf8" {
                    b"x\0".repeat(20_000)
                } else {
                    vec![b'x'; 40_000]
                };
                let error = string_pass_checked(
                    &data[..],
                    &config,
                    &[],
                    embedded,
                    |_| panic!("cancel before a retained run is emitted"),
                    &|stage| {
                        if stage == Checkpoint::Extraction {
                            calls.set(calls.get() + 1);
                            if calls.get() == 2 {
                                token.cancel();
                            }
                        }
                        token.check()
                    },
                )
                .unwrap_err();
                assert_eq!(
                    ScanError::at(ScanErrorKind::Analysis, error).kind,
                    ScanErrorKind::Cancelled
                );
                assert_eq!(calls.get(), 2);
            }
        }
    }

    struct ReportSink<'a> {
        token: &'a CancellationToken,
        operation: &'a str,
    }
    impl Write for ReportSink<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.operation == "write_error" {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if self.operation == "write_cancel" {
                self.token.cancel();
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.operation == "flush_error" {
                return Err(io::Error::other("flush failed"));
            }
            if self.operation == "flush_cancel" {
                self.token.cancel();
            }
            Ok(())
        }
    }

    #[test]
    fn report_failure_or_late_cancellation_never_returns_success_and_cleans_snapshot() {
        let mut config = configuration();
        config.scan_utf16 = true;
        for (operation, size) in ["write_error", "flush_error", "write_cancel", "flush_cancel"]
            .into_iter()
            .flat_map(|operation| [12, 20_000].map(|size| (operation, size)))
        {
            let token = CancellationToken::default();
            let file = tempfile::NamedTempFile::new().unwrap();
            let path = file.path().to_owned();
            let error = scan_with_snapshot(
                &vec![b'x'; size][..],
                ReportSink {
                    token: &token,
                    operation,
                },
                &request(&config),
                &token,
                |_| {},
                || Ok(file),
                &|_| token.check(),
            )
            .err()
            .unwrap();
            assert_eq!(
                error.kind,
                if operation.ends_with("cancel") {
                    ScanErrorKind::Cancelled
                } else {
                    ScanErrorKind::Report
                }
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn analysis_failure_removes_snapshot_and_does_not_become_cancellation() {
        let mut config = configuration();
        config.encoding = "utf16be".into();
        config.scan_utf16 = true;
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        let error = scan_with_snapshot(
            &b"\xff\xfeh\0i\0"[..],
            io::sink(),
            &request(&config),
            &CancellationToken::default(),
            |_| {},
            || Ok(file),
            &|_| Ok(()),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ScanErrorKind::Analysis);
        assert_eq!(error.into_io_error().kind(), io::ErrorKind::InvalidData);
        assert!(!path.exists());
    }

    #[test]
    fn one_pass_never_creates_snapshot_and_hashes_every_selected_byte() {
        struct Short<'a> {
            bytes: &'a [u8],
            chunk: usize,
        }
        impl Read for Short<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let count = self.chunk.min(output.len()).min(self.bytes.len());
                output[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes = &self.bytes[count..];
                Ok(count)
            }
        }
        let cases = [
            ("auto", Vec::new()),
            ("auto", b"prefix\0https://example.com\0\xfftail".to_vec()),
            ("auto", vec![b'x'; 131_075]),
            ("utf16le", b"h\0e\0l\0l\0o\0x".to_vec()),
            ("utf16be", b"\0h\0e\0l\0l\0o\xd8\x3d\xde\x00".to_vec()),
        ];
        for (encoding, data) in cases {
            for chunk in [1, 7, 65_536] {
                let mut config = configuration();
                config.encoding = encoding.into();
                config.offset = 47;
                config.length = Some(data.len() as u64);
                config.max_string_bytes = 4096;
                let token = CancellationToken::default();
                let mut output = Vec::new();
                let mut progress = Vec::new();
                let outcome = scan_with_snapshot(
                    Short {
                        bytes: &data,
                        chunk,
                    },
                    &mut output,
                    &request(&config),
                    &token,
                    |n| progress.push(n),
                    || -> io::Result<std::fs::File> {
                        panic!("basic scan must not create scratch")
                    },
                    &|_| token.check(),
                )
                .unwrap();
                let expected = file_summary::summarize_reader("test", &data[..]).unwrap();
                assert_eq!(
                    serde_json::to_value(&outcome.summary).unwrap(),
                    serde_json::to_value(&expected).unwrap()
                );
                assert_eq!(progress.last().copied().unwrap_or(0), data.len() as u64);
                assert!(progress.windows(2).all(|pair| pair[0] < pair[1]));
                let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
                assert_eq!(report["complete"], true);
                assert_eq!(report["scan_range"]["offset"], 47);
                assert_eq!(report["scan_range"]["length"], data.len());
                assert_eq!(
                    report["file_summary"],
                    serde_json::to_value(expected).unwrap()
                );
            }
        }
    }

    #[test]
    fn one_pass_report_errors_and_late_cancellation_do_not_return_success() {
        let config = configuration();
        for operation in ["write_error", "flush_error", "write_cancel", "flush_cancel"] {
            let token = CancellationToken::default();
            let error = scan_with_snapshot(
                &vec![b'x'; 20_000][..],
                ReportSink {
                    token: &token,
                    operation,
                },
                &request(&config),
                &token,
                |_| {},
                || -> io::Result<std::fs::File> { panic!("no scratch") },
                &|_| token.check(),
            )
            .err()
            .unwrap();
            assert_eq!(
                error.kind,
                if operation.ends_with("cancel") {
                    ScanErrorKind::Cancelled
                } else {
                    ScanErrorKind::Report
                }
            );
        }
    }
}
