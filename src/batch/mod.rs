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

//! Native folder scanning and batch artifact contracts.
pub mod cli;
pub mod coordinator;
pub mod discovery;
pub mod execution;
#[cfg(test)]
pub(crate) mod faults;
pub mod input;
mod manifest;
pub mod output;
mod path;
pub mod preflight;
mod records;
pub mod roots;
pub use manifest::*;
pub use path::RelativePath;
pub use records::*;
