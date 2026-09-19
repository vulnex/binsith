mod comparison;
mod coverage;
mod entropy;
mod file_summary;
mod hex_dump;
mod indicator_export;
mod json_output;
mod string_analysis;
mod utils;
mod validation;

use clap::Parser;
use std::io::{self, Write};

#[derive(Parser, serde::Serialize)]
#[command(
    name = "binsith",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), "\nrevision: ", env!("BINSITH_REVISION"), "\nsource SHA256: ", env!("BINSITH_SOURCE_SHA256"), "\ntarget: ", env!("BINSITH_TARGET"), "\nprofile: ", env!("BINSITH_PROFILE")),
    about = "VULNEX BinSith, a binary analysis tool"
)]
struct Args {
    /// Input file, or - for standard input
    #[arg(required_unless_present = "list_categories")]
    file: Option<String>,
    /// List available bundled/custom pattern categories without reading a sample
    #[arg(long, conflicts_with_all = ["file", "summary", "strings", "matches_only", "hex", "no_decode", "output", "max_string_bytes", "max_decode_bytes", "encoding", "scan_utf16", "offset", "length", "min_length", "categories", "decode_depth", "entropy", "entropy_window", "entropy_threshold", "jsonl", "live_jsonl", "export_indicators", "export_format", "export_validation", "quiet", "match_exit_code", "no_match_exit_code", "inconclusive_exit_code", "compare"])]
    list_categories: bool,
    /// Print file summary (the default if no analysis mode is selected)
    #[arg(short = 'i', long = "summary")]
    summary: bool,
    /// Extract and classify strings
    #[arg(short = 's', long = "string-analysis")]
    strings: bool,
    /// Show only strings matching a pattern
    #[arg(short = 'S', long = "string-analysis-only")]
    matches_only: bool,
    /// Print a hex dump
    #[arg(short = 'x', long = "hexdump")]
    hex: bool,
    /// Disable Base64 decoding
    #[arg(short = 'D', long = "no-decode")]
    no_decode: bool,
    /// Save structured analysis as JSON
    #[arg(short = 'j', long = "json-output", value_name = "OUTPUT_JSON")]
    output: Option<String>,
    /// Override bundled regex patterns with a TOML file
    #[arg(long, value_name = "TOML")]
    patterns: Option<String>,
    /// Maximum retained UTF-8 bytes per string (minimum 4); longer runs are marked truncated
    #[arg(long, default_value_t = 1048576, value_parser = parse_string_limit)]
    max_string_bytes: usize,
    /// Maximum decoded Base64 bytes per string (0 disables decoding)
    #[arg(long, default_value_t = 262144)]
    max_decode_bytes: usize,
    /// Select string encoding; auto recognizes a leading UTF-16 BOM
    #[arg(long, value_enum)]
    encoding: Option<string_analysis::Encoding>,
    /// Also scan embedded ASCII-range UTF-16 candidates in both byte orders
    #[arg(long)]
    scan_utf16: bool,
    /// Start at this byte offset (decimal or 0x hexadecimal)
    #[arg(long, default_value = "0", value_parser = parse_offset)]
    offset: u64,
    /// Scan at most this many bytes
    #[arg(long, value_parser = parse_offset)]
    length: Option<u64>,
    /// Minimum characters in an extracted string
    #[arg(long, default_value_t = 4, value_parser = parse_positive)]
    min_length: usize,
    /// Only these pattern categories (repeat or comma separate)
    #[arg(long = "category", value_delimiter = ',')]
    categories: Vec<String>,
    /// Maximum nested Base64 layers (0 disables decoding; maximum 8)
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=8))]
    decode_depth: u8,
    /// Emit entropy for consecutive windows
    #[arg(long)]
    entropy: bool,
    /// Bytes per entropy window
    #[arg(long, default_value_t = 4096, value_parser = parse_positive)]
    entropy_window: usize,
    /// Mark entropy at or above this value as high (0–8 bits/byte)
    #[arg(long, default_value_t = 7.0)]
    entropy_threshold: f64,
    /// Emit JSON Lines to stdout, or to the -j destination
    #[arg(long)]
    jsonl: bool,
    /// Live JSON Lines: enable strings, emit findings before EOF, summarize last
    #[arg(long)]
    live_jsonl: bool,
    /// Export deduplicated primary-input indicators to PATH, or - for stdout
    #[arg(long, value_name = "PATH")]
    export_indicators: Option<String>,
    /// Indicator export format
    #[arg(
        long,
        value_enum,
        default_value = "json",
        requires = "export_indicators"
    )]
    export_format: indicator_export::Format,
    /// Export all matches, actionable candidates/validated matches, or validated only
    #[arg(
        long,
        value_enum,
        default_value = "all",
        requires = "export_indicators"
    )]
    export_validation: indicator_export::ValidationFilter,
    /// Suppress human-readable output
    #[arg(short, long)]
    quiet: bool,
    /// Exit code when a candidate/validated indicator is found
    #[arg(long, default_value_t = 0)]
    match_exit_code: u8,
    /// Exit code when no candidate/validated indicator is found
    #[arg(long, default_value_t = 0)]
    no_match_exit_code: u8,
    /// Exit code for a limited scan with no indicator (match takes precedence)
    #[arg(long)]
    inconclusive_exit_code: Option<u8>,
    /// Compare strings, indicators, hashes, and regional entropy with another file
    #[arg(long, value_name = "OTHER_FILE")]
    compare: Option<String>,
}

fn parse_string_limit(value: &str) -> Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "expected an integer".to_owned())?;
    if limit < 4 {
        Err("must be at least 4 bytes".into())
    } else {
        Ok(limit)
    }
}

fn parse_offset(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| "expected nonnegative byte count (decimal or 0x hex)".into())
}
fn parse_positive(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("must be a positive integer".into()),
    }
}
fn limits(args: &Args) -> string_analysis::Limits {
    string_analysis::Limits {
        max_string_bytes: args.max_string_bytes,
        max_decode_bytes: args.max_decode_bytes,
        min_length: args.min_length,
        decode_depth: args.decode_depth as usize,
    }
}
fn scan_pass(
    reader: impl io::Read,
    args: &Args,
    patterns: &[(String, regex::Regex)],
    embedded: bool,
    mut emit: impl FnMut(string_analysis::StringFinding) -> io::Result<()>,
) -> io::Result<()> {
    let base = usize::try_from(args.offset)
        .map_err(|_| io::Error::other("offset exceeds platform address range"))?;
    let mut adjust = |mut f: string_analysis::StringFinding| {
        let shift = |n: usize| {
            n.checked_add(base)
                .ok_or_else(|| io::Error::other("offset overflow"))
        };
        f.offset = shift(f.offset)?;
        for detail in &mut f.match_details {
            detail.offset = shift(detail.offset)?;
            detail.end_offset = shift(detail.end_offset)?;
        }
        for layer in &mut f.decoded_layers {
            layer.source_offset = shift(layer.source_offset)?;
            layer.source_end_offset = shift(layer.source_end_offset)?;
        }
        emit(f)
    };
    let matching_only = args.matches_only || !args.categories.is_empty();
    if embedded {
        string_analysis::scan_embedded_utf16(
            reader,
            patterns,
            !args.no_decode && args.max_decode_bytes > 0,
            matching_only,
            limits(args),
            &mut adjust,
        )
    } else {
        string_analysis::analyze_reader_with_encoding(
            reader,
            patterns,
            !args.no_decode && args.max_decode_bytes > 0,
            matching_only,
            limits(args),
            args.encoding.unwrap_or_default(),
            &mut adjust,
        )
    }
}
fn has_hit(f: &string_analysis::StringFinding) -> bool {
    f.has_actionable_match || f.decoded_layers.iter().any(|l| l.has_actionable_match)
}
fn run(mut args: Args) -> Result<u8, Box<dyn std::error::Error>> {
    use std::io::Seek;
    if args.list_categories {
        let patterns = string_analysis::load_patterns(args.patterns.as_deref())?;
        let mut stdout = io::BufWriter::new(io::stdout());
        for (name, _) in patterns {
            writeln!(stdout, "{}", utils::escape_string(&name))?;
        }
        stdout.flush()?;
        return Ok(0);
    }
    let input_path = args.file.as_deref().ok_or("input file is required")?;
    if args.live_jsonl {
        args.jsonl = true;
    }
    if !args.entropy_threshold.is_finite() || !(0.0..=8.0).contains(&args.entropy_threshold) {
        return Err("entropy threshold must be between 0 and 8".into());
    }
    if args
        .length
        .is_some_and(|n| args.offset.checked_add(n).is_none())
    {
        return Err("scan range overflows byte offsets".into());
    }
    if args.compare.as_deref() == Some("-") {
        return Err(
            "comparison file must be a path; stdin is supported only for the primary input".into(),
        );
    }
    let want_strings = args.export_indicators.is_some()
        || args.live_jsonl
        || args.strings
        || args.matches_only
        || args.encoding.is_some()
        || args.scan_utf16
        || !args.categories.is_empty()
        || args.compare.is_some()
        || args.match_exit_code != 0
        || args.no_match_exit_code != 0
        || args.inconclusive_exit_code.is_some();
    let report_requested = args.output.is_some() || args.jsonl;
    let report_stdout =
        args.output.as_deref() == Some("-") || (args.jsonl && args.output.is_none());
    let export_stdout = args.export_indicators.as_deref() == Some("-");
    if export_stdout && report_stdout {
        return Err("indicator export and analysis report cannot both use stdout".into());
    }
    if let (Some(export), Some(report)) = (&args.export_indicators, &args.output) {
        if export != "-"
            && report != "-"
            && indicator_export::destination_identity(export)?
                == indicator_export::destination_identity(report)?
        {
            return Err(
                "indicator export and analysis report require different destinations".into(),
            );
        }
    }
    let human = !args.quiet && !report_stdout && !export_stdout && !args.live_jsonl;
    let show_summary =
        args.summary || (!want_strings && !args.hex && !args.entropy && !report_requested);
    let want_summary = show_summary
        || report_requested
        || args.compare.is_some()
        || args.export_indicators.is_some();
    let mut patterns = if want_strings {
        string_analysis::load_patterns(args.patterns.as_deref())?
    } else {
        Vec::new()
    };
    for category in &args.categories {
        if !patterns.iter().any(|(name, _)| name == category) {
            return Err(format!("unknown category: {category}").into());
        }
    }
    if !args.categories.is_empty() {
        patterns.retain(|(name, _)| args.categories.contains(name));
    }
    let mut input = utils::ranged_input(input_path, args.offset, args.length)?;
    let terminal: Box<dyn Write> = if human {
        Box::new(io::stdout())
    } else {
        Box::new(io::sink())
    };
    let mut out = utils::Terminal::new(
        io::BufWriter::new(terminal),
        report_requested || args.export_indicators.is_some(),
    );
    let passes = usize::from(want_summary)
        + usize::from(want_strings)
        + usize::from(args.hex)
        + usize::from(args.scan_utf16)
        + usize::from(args.entropy)
        + usize::from(args.compare.is_some());
    let mut snapshot = if args.live_jsonl {
        if args.hex || args.scan_utf16 || args.entropy || args.compare.is_some() {
            Some(tempfile::tempfile()?)
        } else {
            None
        }
    } else if passes > 1 {
        let mut file = tempfile::tempfile()?;
        io::copy(&mut input, &mut file)?;
        file.rewind()?;
        Some(file)
    } else {
        None
    };
    let reader: &mut dyn io::Read = match snapshot.as_mut() {
        Some(file) => file,
        None => input.as_mut(),
    };
    let mut summary = if want_summary && !args.live_jsonl {
        Some(file_summary::summarize_reader(input_path, reader)?)
    } else {
        None
    };
    if show_summary && human {
        writeln!(out, "{}", summary.as_ref().unwrap())?;
        if args.offset != 0 || args.length.is_some() {
            writeln!(
                out,
                "Scan range: offset {}, {} bytes (hashes describe this range)",
                args.offset,
                summary.as_ref().unwrap().size_bytes
            )?;
        }
    }
    let mut json_file = if report_requested && !report_stdout {
        let path = args.output.as_ref().unwrap();
        let parent = std::path::Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        Some(tempfile::NamedTempFile::new_in(parent)?)
    } else {
        None
    };
    let mut json = if report_requested {
        let writer: Box<dyn Write + '_> = match json_file.as_mut() {
            Some(file) => Box::new(io::BufWriter::new(file.as_file_mut())),
            None => Box::new(io::BufWriter::new(io::stdout())),
        };
        Some(if args.live_jsonl {
            json_output::JsonWriter::live(writer)?
        } else {
            json_output::JsonWriter::report(
                writer,
                summary.as_ref().unwrap(),
                want_strings,
                args.jsonl,
                args.offset,
                args.length,
            )?
        })
    } else {
        None
    };
    use sha2::{Digest, Sha256};
    let effective_patterns: Vec<_> = patterns
        .iter()
        .map(|(name, regex)| (name, regex.as_str()))
        .collect();
    let metadata = serde_json::json!({
        "tool": "binsith", "version": env!("CARGO_PKG_VERSION"),
        "revision": env!("BINSITH_REVISION"), "source_sha256": env!("BINSITH_SOURCE_SHA256"),
        "target":env!("BINSITH_TARGET"), "profile":env!("BINSITH_PROFILE"), "rustc":env!("BINSITH_RUSTC"),
        "configuration": &args, "strings_enabled":want_strings,
        "effective_encoding":args.encoding.unwrap_or_default(),
        "decoding_enabled":want_strings && !args.no_decode && args.max_decode_bytes > 0 && args.decode_depth > 0,
        "patterns_sha256":format!("{:x}", Sha256::digest(serde_json::to_vec(&effective_patterns)?)),
        "patterns_hash_format":"SHA256 of compact JSON array of sorted [name, expression] pairs after category filtering"
    });
    let mut coverage = coverage::Coverage::default();
    let mut matched = false;
    let mut index = comparison::Index::default();
    let mut indicators = args
        .export_indicators
        .as_ref()
        .map(|_| indicator_export::Index::new(args.export_validation));
    if want_strings {
        if human {
            writeln!(out, "Offset\tEncoding\tLength\tAnalysis\tString")?;
        }
        let mut emit = |finding: string_analysis::StringFinding| {
            coverage.observe(&finding);
            if let Some(index) = indicators.as_mut() {
                index.observe(&finding);
            }
            matched |= has_hit(&finding);
            if args.compare.is_some() {
                index.add(&finding);
            }
            if human {
                print_string(&finding, &mut out)?;
            }
            if let Some(json) = json.as_mut() {
                json.finding(&finding)?;
            }
            Ok(())
        };
        if args.live_jsonl {
            let mut observed = file_summary::SummaryReader::new(input.as_mut(), snapshot.take());
            scan_pass(&mut observed, &args, &patterns, false, &mut emit)?;
            let (finished_summary, captured) = observed.finish(input_path);
            summary = Some(finished_summary);
            snapshot = captured;
        } else {
            let reader: &mut dyn io::Read = if let Some(file) = snapshot.as_mut() {
                file.rewind()?;
                file
            } else {
                input.as_mut()
            };
            scan_pass(reader, &args, &patterns, false, &mut emit)?;
        }
        if args.scan_utf16 {
            let file = snapshot.as_mut().unwrap();
            file.rewind()?;
            scan_pass(file, &args, &patterns, true, &mut emit)?;
        }
    }
    if args.hex {
        let reader: &mut dyn io::Read = if let Some(file) = snapshot.as_mut() {
            file.rewind()?;
            file
        } else {
            input.as_mut()
        };
        hex_dump::write_hex_dump_at(reader, &mut out, args.offset)?;
    }
    if args.entropy {
        if let Some(json) = json.as_mut() {
            json.start_entropy()?;
        }
        let reader: &mut dyn io::Read = if let Some(file) = snapshot.as_mut() {
            file.rewind()?;
            file
        } else {
            input.as_mut()
        };
        entropy::scan(
            reader,
            args.entropy_window,
            args.offset,
            args.entropy_threshold,
            |region| {
                if human {
                    writeln!(
                        out,
                        "Entropy {:08x} +{}: {:.4}{}",
                        region.offset,
                        region.length,
                        region.entropy,
                        if region.high { " HIGH" } else { "" }
                    )?;
                }
                if let Some(json) = json.as_mut() {
                    json.region(&region)?;
                }
                Ok(())
            },
        )?;
    }
    if let Some(other) = args.compare.as_deref() {
        let mut other_input = utils::ranged_input(other, args.offset, args.length)?;
        let mut other_file = tempfile::tempfile()?;
        io::copy(&mut other_input, &mut other_file)?;
        other_file.rewind()?;
        let other_summary = file_summary::summarize_reader(other, &mut other_file)?;
        let mut other_index = comparison::Index::default();
        other_file.rewind()?;
        scan_pass(&mut other_file, &args, &patterns, false, |f| {
            coverage.observe(&f);
            other_index.add(&f);
            Ok(())
        })?;
        if args.scan_utf16 {
            other_file.rewind()?;
            scan_pass(&mut other_file, &args, &patterns, true, |f| {
                coverage.observe(&f);
                other_index.add(&f);
                Ok(())
            })?;
        }
        let left = snapshot.as_mut().unwrap();
        left.rewind()?;
        other_file.rewind()?;
        let comparison = comparison::compare(
            summary.as_ref().unwrap(),
            other_summary,
            index,
            other_index,
            left,
            &mut other_file,
            args.offset,
            args.entropy_window,
            args.entropy_threshold,
        )?;
        coverage.comparison_limited =
            comparison.incomplete_index || comparison.entropy_changes_omitted > 0;
        if human {
            writeln!(
                out,
                "Comparison (primary → other):\n{}",
                serde_json::to_string_pretty(&comparison)?
            )?;
        }
        if let Some(json) = json.as_mut() {
            json.comparison(&comparison)?;
        }
    }
    // Analysis is complete. Close input handles before replacing destinations,
    // which may refer to the input file; Windows can reject an open destination.
    drop(input);
    drop(snapshot);
    if let Some(index) = indicators.as_ref() {
        coverage.indicator_export_limited = index.limited();
        indicator_export::save(
            index,
            args.export_indicators.as_deref().unwrap(),
            args.export_format,
            summary.as_ref().unwrap(),
            &metadata,
            &coverage.report(),
        )?;
    }
    if human && coverage.limited() {
        writeln!(out, "Analysis coverage limited: {}", coverage.report())?;
    }
    out.flush()?;
    if let Some(mut json) = json.take() {
        if args.live_jsonl {
            json.summary(summary.as_ref().unwrap(), args.offset, args.length)?;
        }
        json.finish_report(&metadata, &coverage.report())?;
    }
    drop(json);
    if let (Some(file), Some(path)) = (json_file, args.output.as_ref()) {
        file.persist(path)?;
    }
    out.finish()?;
    Ok(if matched {
        args.match_exit_code
    } else {
        if coverage.limited() {
            args.inconclusive_exit_code
                .unwrap_or(args.no_match_exit_code)
        } else {
            args.no_match_exit_code
        }
    })
}

fn print_string(f: &string_analysis::StringFinding, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{:08x}\t{}\t{}\t{}\t{}",
        f.offset,
        f.encoding,
        f.length,
        if f.truncated {
            "TRUNCATED (not classified)".into()
        } else if f.matches.is_empty() {
            ".".into()
        } else {
            f.matches.join(",")
        },
        utils::escape_string(&f.value)
    )?;
    if f.extraction == "embedded_utf16_candidate" {
        writeln!(out, "  Embedded UTF-16 candidate")?;
    }
    for detail in &f.match_details {
        writeln!(
            out,
            "    Context: {} | {} | {}",
            utils::escape_string(&detail.evidence.before),
            utils::escape_string(&detail.text),
            utils::escape_string(&detail.evidence.after)
        )?;
        writeln!(
            out,
            "  Match {} [{:08x}..{:08x}): {}",
            utils::escape_string(&detail.pattern),
            detail.offset,
            detail.end_offset,
            utils::escape_string(&detail.text)
        )?;
        writeln!(
            out,
            "    {:?}: {}",
            detail.validation.status, detail.validation.reason
        )?;
    }
    if f.match_details_truncated {
        writeln!(
            out,
            "  Additional match details omitted by category: {}",
            serde_json::to_string(&f.match_details_omitted)?
        )?;
    }
    if f.decode_status == "limit" {
        writeln!(out, "Base64 decoding skipped: byte limit")?;
    }
    for layer in &f.decoded_layers {
        writeln!(
            out,
            "Decoded (Base64 layer {}, source [{:08x}..{:08x})): {}",
            layer.depth,
            layer.source_offset,
            layer.source_end_offset,
            utils::escape_string(&layer.text)
        )?;
        for detail in &layer.match_details {
            writeln!(
                out,
                "    Context: {} | {} | {}",
                utils::escape_string(&detail.evidence.before),
                utils::escape_string(&detail.text),
                utils::escape_string(&detail.evidence.after)
            )?;
            writeln!(
                out,
                "  Decoded match {} [UTF-8 {}..{}): {} ({:?}: {})",
                utils::escape_string(&detail.pattern),
                detail.offset,
                detail.end_offset,
                utils::escape_string(&detail.text),
                detail.validation.status,
                detail.validation.reason
            )?;
        }
        if layer.match_details_truncated {
            writeln!(
                out,
                "  Decoded match details omitted by category: {}",
                serde_json::to_string(&layer.match_details_omitted)?
            )?;
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(Args::parse()) {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e)
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe) =>
        {
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("binsith: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
