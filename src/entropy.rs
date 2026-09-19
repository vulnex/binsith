//
// VULNEX -BinSith-
//
// File: entropy.rs
// Author: Simon Roses Femerling
// Created: 2026-09-16
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use serde::Serialize;
use std::io::{self, Read};

#[derive(Debug, Serialize)]
pub struct Region {
    pub offset: u64,
    pub length: usize,
    pub entropy: f64,
    pub high: bool,
}

pub fn next_region(
    reader: &mut impl Read,
    window: usize,
    offset: u64,
    threshold: f64,
) -> io::Result<Option<Region>> {
    let mut counts = [0u64; 256];
    let mut length = 0;
    let mut buffer = [0u8; 65536];
    while length < window {
        let take = buffer.len().min(window - length);
        let n = match reader.read(&mut buffer[..take]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => r?,
        };
        if n == 0 {
            break;
        }
        for &b in &buffer[..n] {
            counts[b as usize] += 1;
        }
        length += n;
    }
    if length == 0 {
        return Ok(None);
    }
    let entropy: f64 = counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / length as f64;
            -p * p.log2()
        })
        .sum();
    Ok(Some(Region {
        offset,
        length,
        entropy,
        high: entropy >= threshold,
    }))
}

pub fn scan(
    mut reader: impl Read,
    window: usize,
    mut offset: u64,
    threshold: f64,
    mut emit: impl FnMut(Region) -> io::Result<()>,
) -> io::Result<()> {
    if window == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entropy window must be positive",
        ));
    }
    while let Some(region) = next_region(&mut reader, window, offset, threshold)? {
        offset += region.length as u64;
        emit(region)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_reads_and_read_errors() {
        struct Short<'a>(&'a [u8]);
        impl Read for Short<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = 1.min(self.0.len()).min(b.len());
                b[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let mut regions = Vec::new();
        scan(Short(&[0, 1, 0, 1, 2]), 4, 10, 1.0, |r| {
            regions.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(regions[0].entropy, 1.0);
        assert_eq!(regions[1].offset, 14);
        assert_eq!(regions[1].length, 1);
        struct Fail;
        impl Read for Fail {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("failed"))
            }
        }
        assert!(scan(Fail, 4, 0, 1.0, |_| Ok(())).is_err());
    }
}
