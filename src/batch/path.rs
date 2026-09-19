//
// VULNEX -BinSith-
//
// File: batch/path.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-19
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Lossless relative identity; its display representation is never authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelativePath {
    encoding: Encoding,
    value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Encoding {
    #[serde(rename = "unix-bytes-base64")]
    Unix,
    #[serde(rename = "windows-utf16le-base64")]
    Windows,
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            encoding: Encoding,
            value: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(&wire.value)
            .map_err(serde::de::Error::custom)?;
        Self::new(wire.encoding, &bytes).map_err(serde::de::Error::custom)
    }
}

impl RelativePath {
    fn new(encoding: Encoding, bytes: &[u8]) -> Result<Self, &'static str> {
        let units: Vec<u16> = match encoding {
            Encoding::Unix => bytes.iter().map(|b| u16::from(*b)).collect(),
            Encoding::Windows => {
                if !bytes.len().is_multiple_of(2) {
                    return Err("Windows path must contain complete UTF-16LE code units");
                }
                bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect()
            }
        };
        let separator = |c: &u16| *c == 47 || (encoding == Encoding::Windows && *c == 92);
        if units.is_empty()
            || units.contains(&0)
            || (encoding == Encoding::Windows && units.contains(&58))
            || units
                .split(separator)
                .any(|part| part.is_empty() || part == [46] || part == [46, 46])
        {
            return Err("path must contain only nonempty relative normal components");
        }
        Ok(Self {
            encoding,
            value: STANDARD.encode(bytes),
        })
    }

    /// Capture the native path without lossy conversion or filesystem access.
    pub fn from_relative(path: &Path) -> Result<Self, &'static str> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::new(Encoding::Unix, path.as_os_str().as_bytes())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let bytes: Vec<u8> = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect();
            Self::new(Encoding::Windows, &bytes)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err("native path encoding is unsupported on this platform")
        }
    }

    /// SHA-256(domain || encoding tag || NUL || raw native relative path bytes).
    /// This identifies a path, not its contents, and provides no confidentiality.
    pub fn report_id(&self) -> String {
        let tag = match self.encoding {
            Encoding::Unix => "unix-bytes-base64",
            Encoding::Windows => "windows-utf16le-base64",
        };
        let mut digest = Sha256::new();
        digest.update(b"binsith:relative-path:v1\0");
        digest.update(tag.as_bytes());
        digest.update([0]);
        digest.update(
            STANDARD
                .decode(&self.value)
                .expect("validated path encoding"),
        );
        format!("{:x}", digest.finalize())
    }

    /// Generated ASCII-only destination relative to the claimed output root.
    pub fn report_location(&self) -> String {
        let id = self.report_id();
        format!("results/{}/{id}.json", &id[..2])
    }
}
