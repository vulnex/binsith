//
// VULNEX -BinSith-
//
// File: file_summary.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct FileSummary {
    pub file_path: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub md5: String,
    pub sha256: String,
    pub entropy: f64,
}

#[cfg(test)]
pub fn summarize(file_path: &str, content: &[u8]) -> FileSummary {
    summarize_reader(file_path, std::io::Cursor::new(content)).expect("reading an in-memory buffer")
}

pub fn summarize_reader(
    file_path: &str,
    reader: impl std::io::Read,
) -> std::io::Result<FileSummary> {
    let mut observed = SummaryReader::new(reader, None);
    std::io::copy(&mut observed, &mut std::io::sink())?;
    Ok(observed.finish(file_path).0)
}

/// Accumulates the summary during analysis; optional snapshot supports later passes.
pub struct SummaryReader<R> {
    reader: R,
    snapshot: Option<std::fs::File>,
    frequencies: [u64; 256],
    md5: md5::Context,
    sha256: Sha256,
    size: u64,
    prefix: Vec<u8>,
}
impl<R> SummaryReader<R> {
    pub fn new(reader: R, snapshot: Option<std::fs::File>) -> Self {
        Self {
            reader,
            snapshot,
            frequencies: [0; 256],
            md5: md5::Context::new(),
            sha256: Sha256::new(),
            size: 0,
            prefix: Vec::new(),
        }
    }
    pub fn finish(self, file_path: &str) -> (FileSummary, Option<std::fs::File>) {
        let entropy = self
            .frequencies
            .iter()
            .filter(|&&n| n > 0)
            .map(|&n| {
                let p = n as f64 / self.size as f64;
                -p * p.log2()
            })
            .sum();
        (
            FileSummary {
                file_path: file_path.into(),
                size_bytes: self.size,
                mime_type: infer::get(&self.prefix)
                    .map(|t| t.mime_type())
                    .unwrap_or("Unknown")
                    .into(),
                md5: format!("{:x}", self.md5.compute()),
                sha256: format!("{:x}", self.sha256.finalize()),
                entropy,
            },
            self.snapshot,
        )
    }
}
impl<R: std::io::Read> std::io::Read for SummaryReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Write;
        let count = self.reader.read(buffer)?;
        let bytes = &buffer[..count];
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.write_all(bytes)?;
        }
        self.size += count as u64;
        for &byte in bytes {
            self.frequencies[byte as usize] += 1;
        }
        self.prefix
            .extend_from_slice(&bytes[..count.min(8192 - self.prefix.len())]);
        self.md5.consume(bytes);
        self.sha256.update(bytes);
        Ok(count)
    }
}

impl std::fmt::Display for FileSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "File Summary:\n-------------\n- File Path: {}\n- File Size: {} ({} bytes)\n- File MIME: {}\n- MD5: {}\n- SHA256: {}\n- File Entropy: {:.2}", self.file_path, human_readable_size(self.size_bytes), self.size_bytes, self.mime_type, self.md5, self.sha256, self.entropy)
    }
}

fn human_readable_size(size: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", units[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_boundaries_and_read_errors() {
        for size in [65535, 65536, 65537, 8 * 1024 * 1024 + 1] {
            let bytes = vec![b'a'; size];
            let summary = summarize("fixture", &bytes);
            assert_eq!(summary.md5, format!("{:x}", md5::compute(&bytes)));
            assert_eq!(summary.sha256, format!("{:x}", Sha256::digest(&bytes)));
        }
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read failure"))
            }
        }
        assert!(summarize_reader("fixture", FailingReader).is_err());
    }
    #[test]
    fn known_hashes_and_empty_input() {
        let s = summarize("fixture", b"abc");
        assert_eq!(s.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            s.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let empty = summarize("empty", b"");
        assert_eq!(empty.entropy, 0.0);
        assert_eq!(empty.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(human_readable_size(1 << 40), "1.00 TiB");
    }
}
