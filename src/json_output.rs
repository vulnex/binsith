//
// VULNEX -BinSith-
//
// File: json_output.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use crate::{file_summary::FileSummary, string_analysis::StringFinding};
use std::io::{self, Write};

pub struct JsonWriter<W: Write> {
    out: W,
    first: bool,
    strings_open: bool,
    entropy_open: bool,
    jsonl: bool,
    live: bool,
}

impl<W: Write> JsonWriter<W> {
    #[cfg(test)]
    pub fn new(out: W, summary: &FileSummary, strings: bool) -> io::Result<Self> {
        Self::report(out, summary, strings, false, 0, None)
    }
    pub fn report(
        mut out: W,
        summary: &FileSummary,
        strings: bool,
        jsonl: bool,
        offset: u64,
        requested_length: Option<u64>,
    ) -> io::Result<Self> {
        let range = serde_json::json!({"offset": offset, "length": summary.size_bytes, "requested_length": requested_length});
        if jsonl {
            serde_json::to_writer(
                &mut out,
                &serde_json::json!({"type":"summary", "schema_version":1, "file_summary":summary, "scan_range":range}),
            )?;
            writeln!(out)?;
        } else {
            write!(out, "{{\"schema_version\":1,\"file_summary\":")?;
            serde_json::to_writer(&mut out, summary)?;
            write!(out, ",\"scan_range\":")?;
            serde_json::to_writer(&mut out, &range)?;
            write!(out, ",\"strings\":{}", if strings { "[" } else { "null" })?;
        }
        Ok(Self {
            out,
            first: true,
            strings_open: strings && !jsonl,
            entropy_open: false,
            jsonl,
            live: false,
        })
    }
    pub fn live(out: W) -> io::Result<Self> {
        let mut writer = Self {
            out,
            first: true,
            strings_open: false,
            entropy_open: false,
            jsonl: true,
            live: true,
        };
        writer.event(
            "start",
            &serde_json::json!({"schema_version":1,"mode":"live_jsonl","summary_position":"end"}),
        )?;
        Ok(writer)
    }
    pub fn summary(
        &mut self,
        summary: &FileSummary,
        offset: u64,
        requested_length: Option<u64>,
    ) -> io::Result<()> {
        serde_json::to_writer(
            &mut self.out,
            &serde_json::json!({"type":"summary", "schema_version":1, "file_summary":summary,
            "scan_range":{"offset":offset,"length":summary.size_bytes,"requested_length":requested_length}}),
        )?;
        writeln!(self.out)?;
        if self.live {
            self.out.flush()?;
        }
        Ok(())
    }
    fn event(&mut self, kind: &str, value: &impl serde::Serialize) -> io::Result<()> {
        serde_json::to_writer(
            &mut self.out,
            &serde_json::json!({"type":kind, "data":value}),
        )?;
        writeln!(self.out)?;
        if self.live {
            self.out.flush()?;
        }
        Ok(())
    }
    fn close_arrays(&mut self) -> io::Result<()> {
        if self.strings_open || self.entropy_open {
            write!(self.out, "]")?;
        }
        self.strings_open = false;
        self.entropy_open = false;
        Ok(())
    }
    pub fn finding(&mut self, finding: &StringFinding) -> io::Result<()> {
        if self.jsonl {
            return self.event("string", finding);
        }
        if !self.first {
            write!(self.out, ",")?;
        }
        self.first = false;
        serde_json::to_writer(&mut self.out, finding)?;
        Ok(())
    }
    pub fn start_entropy(&mut self) -> io::Result<()> {
        if !self.jsonl && !self.entropy_open {
            self.close_arrays()?;
            write!(self.out, ",\"entropy_regions\":[")?;
            self.entropy_open = true;
            self.first = true;
        }
        Ok(())
    }
    pub fn region(&mut self, region: &crate::entropy::Region) -> io::Result<()> {
        if self.jsonl {
            return self.event("entropy", region);
        }
        if !self.entropy_open {
            self.close_arrays()?;
            write!(self.out, ",\"entropy_regions\":[")?;
            self.entropy_open = true;
            self.first = true;
        }
        if !self.first {
            write!(self.out, ",")?;
        }
        self.first = false;
        serde_json::to_writer(&mut self.out, region)?;
        Ok(())
    }
    pub fn comparison(&mut self, comparison: &impl serde::Serialize) -> io::Result<()> {
        if self.jsonl {
            return self.event("comparison", comparison);
        }
        self.close_arrays()?;
        write!(self.out, ",\"comparison\":")?;
        serde_json::to_writer(&mut self.out, comparison)?;
        Ok(())
    }
    #[cfg(test)]
    pub fn finish(self) -> io::Result<()> {
        self.finish_report(&serde_json::Value::Null, &serde_json::Value::Null)
    }
    pub fn finish_report(
        mut self,
        metadata: &serde_json::Value,
        coverage: &serde_json::Value,
    ) -> io::Result<()> {
        if self.jsonl {
            self.event("complete", &serde_json::json!({"complete":true,"processing_complete":true,"metadata":metadata,"analysis_coverage":coverage}))?;
        } else {
            self.close_arrays()?;
            write!(self.out, ",\"metadata\":")?;
            serde_json::to_writer(&mut self.out, metadata)?;
            write!(self.out, ",\"analysis_coverage\":")?;
            serde_json::to_writer(&mut self.out, coverage)?;
            writeln!(
                self.out,
                ",\"complete\":true,\"processing_complete\":true}}"
            )?;
        }
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_write_and_flush_errors_are_propagated() {
        struct Fail {
            write: bool,
        }
        impl Write for Fail {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.write {
                    Err(io::Error::other("disk write failed"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("disk flush failed"))
            }
        }
        assert!(JsonWriter::live(Fail { write: true }).is_err());
        assert!(JsonWriter::live(Fail { write: false }).is_err());
        let summary = crate::file_summary::summarize("fixture", b"abc");
        assert!(JsonWriter::new(Fail { write: true }, &summary, false).is_err());
        let writer = JsonWriter::new(Fail { write: false }, &summary, false).unwrap();
        assert_eq!(
            writer.finish().unwrap_err().to_string(),
            "disk flush failed"
        );
    }
}
