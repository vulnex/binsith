//
// VULNEX -BinSith-
//
// File: batch/mod.rs
// Author: Simon Roses Femerling
// Created: 2026-09-19
// Last Modified: 2026-09-20
// Version: 0.4.2
// License: Apache-2.0
// Copyright (c) 2026 VULNEX. All rights reserved.
// https://www.vulnex.com
//

//! Batch artifact contracts. Execution and CLI integration are not yet available.
pub mod cli;
pub mod discovery;
pub mod input;
mod manifest;
mod path;
pub mod preflight;
mod records;
pub mod roots;
pub use manifest::*;
pub use path::RelativePath;
pub use records::*;
