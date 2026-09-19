//
// VULNEX -BinSith-
//
// File: hex_dump.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use std::io::{self, Read, Write};

#[cfg(test)]
pub fn write_hex_dump(reader: impl Read, out: &mut impl Write) -> io::Result<()> {
    write_hex_dump_at(reader, out, 0)
}
pub fn write_hex_dump_at(
    reader: impl Read,
    out: &mut impl Write,
    mut offset: u64,
) -> io::Result<()> {
    let mut reader = io::BufReader::with_capacity(65536, reader);
    loop {
        let mut buffer = [0u8; 16];
        let mut count = 0;
        while count < buffer.len() {
            match reader.read(&mut buffer[count..]) {
                Ok(0) => break,
                Ok(n) => count += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if count == 0 {
            break;
        }
        let chunk = &buffer[..count];
        write!(out, "{offset:08x}: ")?;
        offset += count as u64;
        for i in 0..16 {
            if i == 8 {
                write!(out, " ")?;
            }
            if let Some(byte) = chunk.get(i) {
                write!(out, "{byte:02x} ")?;
            } else {
                write!(out, "   ")?;
            }
        }
        write!(out, "|")?;
        for &byte in chunk {
            write!(
                out,
                "{}",
                if (32..=126).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            )?;
        }
        writeln!(out, "|")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_reads_preserve_rows_and_offsets() {
        struct Short<'a>(&'a [u8]);
        impl Read for Short<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = buffer.len().min(3).min(self.0.len());
                buffer[..count].copy_from_slice(&self.0[..count]);
                self.0 = &self.0[count..];
                Ok(count)
            }
        }
        let mut output = Vec::new();
        write_hex_dump(Short(b"abcdefghijklmnopq"), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        let rows: Vec<_> = text.lines().collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].starts_with("00000000: 61 62 63"));
        assert!(rows[0].ends_with("|abcdefghijklmnop|"));
        assert!(rows[1].starts_with("00000010: 71 "));
        assert!(rows[1].ends_with("|q|"));
    }
}

#[cfg(test)]
mod buffering_tests {
    use super::*;
    #[test]
    fn large_input_uses_block_reads() {
        struct Counting {
            remaining: usize,
            calls: usize,
        }
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                let n = self.remaining.min(buf.len());
                buf[..n].fill(0);
                self.remaining -= n;
                Ok(n)
            }
        }
        let mut input = Counting {
            remaining: 1024 * 1024,
            calls: 0,
        };
        write_hex_dump(&mut input, &mut io::sink()).unwrap();
        assert_eq!(input.remaining, 0);
        assert!(input.calls <= 18, "{} reads", input.calls);
    }
}
