# BinSith

<img src="assets/branding/binsith-logo.png" alt="BinSith Byte Monogram logo" width="420">

**BinSith is a fast, cross-platform static binary triage CLI built in Rust for
reliable, analyst-reviewed workflows on macOS, Linux, and Windows.**

Analyze hashes, MIME signatures, strings, indicators, encoded content, hex dumps,
regional entropy, and differences between files, with JSON/CSV exports.
It does not inspect executable headers, sections, imports, or entry points.

See the [release notes](CHANGELOG.md) and [release procedure](RELEASE.md)
for compatibility changes, packaging instructions, and promotion gates.

**0.5.0** adds native folder scanning with bounded parallel workers, per-file
reports, an outcome journal and a batch manifest.

## Performance and reliability

- **Fast:** streaming analysis and configurable string/decoding limits keep large
  inputs practical. In the local benchmark below, a 1 GiB summary took 4.20 seconds.
- **Cross-platform:** native release downloads for macOS ARM64, Linux x86-64, and
  Windows x86-64, with CI tests on all three operating systems.
- **Built for reliable workflows:** debug/release tests, strict Clippy checks,
  bounded sanitizer fuzzing, JSON/CSV compatibility checks, and extracted-binary
  package smoke tests. Reports expose completion and coverage limits; named reports
  replace their destination only after successful completion. Findings still require
  analyst review.

Measured with the published **0.4.2** binary on an **Apple M3 Pro, 36 GiB RAM**:

| Workload | Median time | Throughput | Peak process memory |
| --- | ---: | ---: | ---: |
| 256 MiB summary / hashes | 0.99 s | 259 MiB/s | 2.73 MiB |
| 256 MiB string analysis (`-s -q`) | 6.59 s | 39 MiB/s | 7.47 MiB |
| 256 MiB live JSONL | 13.52 s | 19 MiB/s | 7.58 MiB |
| 1 GiB summary / hashes | 4.20 s | 244 MiB/s | 2.75 MiB |

These are local synthetic-input measurements from 2026-09-19: three timed runs
following one warm-up, warm filesystem caches, and stdout discarded. They exclude
report storage and terminal rendering. Throughput and memory vary with hardware,
input content, enabled modes, custom patterns, and output destination; these are
observations, not guaranteed bounds or cross-platform benchmark results.

The development CLI also accepts a directory with `--output-dir`, using bounded
native scan workers. Recursive traversal, per-file JSON reports, outcome journals
and cooperative interruption are available.
Combined analysis modes can require temporary disk space proportional to the
selected input range. See [Resource limits](#resource-limits) and
[Robustness and performance checks](#robustness-and-performance-checks) for limits
and benchmark reproduction instructions.

## Download

[Download the latest release](https://github.com/vulnex/binsith/releases/latest).
The repository is currently private; sign in with a GitHub account that has access.
Download the archive for your platform and `SHA256SUMS` from the same release.

| Platform | 0.5.0 archive |
| --- | --- |
| macOS, Apple Silicon (ARM64) | `binsith-0.5.0-aarch64-apple-darwin.tar.gz` |
| Linux, x86-64 (built on Ubuntu 22.04) | `binsith-0.5.0-x86_64-unknown-linux-gnu.tar.gz` |
| Windows, x86-64 | `binsith-0.5.0-x86_64-pc-windows-msvc.zip` |

Run these commands in the folder containing your download. Compare the hash with
its filename's entry in `SHA256SUMS` before extracting. Archives are unsigned;
checksums detect corruption, not publisher authenticity.

**macOS (Apple Silicon)**

```sh
shasum -a 256 binsith-0.5.0-aarch64-apple-darwin.tar.gz
tar -xzf binsith-0.5.0-aarch64-apple-darwin.tar.gz
cd binsith-0.5.0-aarch64-apple-darwin
./binsith --version
```

**Linux (x86-64)**

```sh
sha256sum binsith-0.5.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf binsith-0.5.0-x86_64-unknown-linux-gnu.tar.gz
cd binsith-0.5.0-x86_64-unknown-linux-gnu
./binsith --version
```

**Windows (PowerShell, x86-64)**

```powershell
Get-FileHash .\binsith-0.5.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Expand-Archive .\binsith-0.5.0-x86_64-pc-windows-msvc.zip -DestinationPath .
Set-Location .\binsith-0.5.0-x86_64-pc-windows-msvc
.\binsith.exe --version
```

These examples use 0.5.0 filenames. For a newer release, substitute the filenames
shown on its release page. To build locally, see [Build and verify](#build-and-verify).

## Quickstart: analyze synthetic input

From the extracted package directory, create a small text file and export its
indicators. The input contains only example addresses; BinSith reads it as data
and does not contact the addresses.

**macOS / Linux**

```sh
printf 'https://example.org/download\n192.0.2.10\n' > sample.txt
./binsith sample.txt --category URL,ip_address --export-indicators indicators.json --quiet
cat indicators.json
```

**Windows (PowerShell)**

```powershell
Set-Content -Path sample.txt -Value @('https://example.org/download', '192.0.2.10') -Encoding ascii
.\binsith.exe sample.txt --category URL,ip_address --export-indicators indicators.json --quiet
Get-Content indicators.json
```

Expect two entries in `indicators`:

| Category | Value | Validation status |
| --- | --- | --- |
| `URL` | `https://example.org/download` | `validated` |
| `ip_address` | `192.0.2.10` | `validated` |

The report also includes `context.processing_complete: true`, source locations,
coverage information, and build metadata. Here, `validated` means the local
syntax check passed; it does not mean an address is reachable or malicious.

For CSV, replace `--export-indicators indicators.json` with
`--export-indicators indicators.csv --export-format csv`. CSV includes two
indicator rows followed by a context row; parse it with a CSV parser.
See [Indicator export](#indicator-export-040) for the full format.

## Build and verify

```sh
cargo build --locked --release
cargo test --locked
cargo fmt --check
```

Run `target/release/binsith`. Rebuild with `cargo build --locked --release` after
updates: ordinary `cargo test` updates the debug executable, not the release one.
On macOS, Apple development tools and their license must be configured.

## Usage

```sh
binsith sample.bin                              # Summary by default
binsith -i -x sample.bin                        # Summary and hex dump
binsith -s sample.bin                           # Strings and decoded indicators
binsith -S -D sample.bin                        # Matching strings, decoding disabled
binsith --category URL,ip_address sample.bin     # Filter indicator categories
binsith --encoding utf16le text.bin             # Explicit BOM-less UTF-16
binsith --scan-utf16 -S sample.bin               # Also find embedded UTF-16 candidates
binsith -s --offset 0x1000 --length 65536 --min-length 6 sample.bin
binsith -s --decode-depth 3 sample.bin
binsith --entropy --entropy-window 4096 --entropy-threshold 7 sample.bin
binsith -i -s --entropy -j report.json sample.bin
binsith -s --jsonl sample.bin                    # Machine output on stdout
binsith -s --jsonl -q -j findings.jsonl sample.bin
binsith --category URL -q --match-exit-code 3 --no-match-exit-code 4 sample.bin
binsith before.bin --compare after.bin -q -j comparison.json
cat sample.bin | binsith -s -
```

`--encoding`, `--scan-utf16`, `--category`, `--compare`, and nondefault match exit
codes enable string analysis. `-S` retains matching strings and truncation notices;
category selection also filters to matching strings. Category names are case
sensitive, repeatable or comma separated; unknown names are errors. Categories
match the embedded TOML keys, for example `URL`, `Email`, and `ip_address`.

`-j report.json` alone saves a summary without printing it. Combine it with `-s`
to include strings. `-q`/`--quiet` suppresses human-readable output. `-j -` writes
JSON to stdout. `--jsonl` selects JSON Lines and defaults to stdout unless `-j`
provides a destination. Machine stdout is never mixed with human output. Hex
dumps are human output only; a JSON report with `-x` includes the summary, not hex.

## Ranges and coordinates

`--offset` and `--length` accept decimal or `0x` hexadecimal byte counts and apply
to every selected analysis, including both files in a comparison. Offset zero
is the default; absent length means through EOF. An offset beyond EOF is an
error; a length past EOF scans the available bytes. Zero length is an empty scan.

Hashes, size, MIME detection, and entropy describe the selected range. JSON
`scan_range` records its absolute offset, actual byte length, and requested length.
MIME detection examines the first 8 KiB of that range, so an interior range may
have no recognizable signature. Hex, string, match, and entropy offsets stay
absolute in the original input. A range beginning inside a multibyte character
may discard that fragment; explicit UTF-16 decoding starts at the range boundary.

String `length` counts Unicode characters in the original run. Match ranges use
`[offset, end_offset)` with an exclusive end. UTF-16 spans map back to the original
bytes, including surrogate pairs. Match text is Unicode, not raw UTF-16 bytes.

## Patterns and validation

Patterns are embedded in the executable, independent of the working directory.
`--patterns custom.toml` replaces them with a TOML table of names and regex strings:

```toml
email = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
```

Each string retains category names in `matches`. `match_details` contains pattern,
exact text, source byte range, and a `validation` object with status and reason:

- `candidate`: a regex/context match without conclusive local validation.
- `validated`: the particular local check in the reason passed. This does not
  establish ownership, reachability, issuance, authenticity, or active status.
- `invalid`: the local check failed. These results remain visible, even with `-S`.

Built-in checks cover 13–19 digit payment-card candidates (Luhn and rejection of
all-identical digits), IPv4 parsing, UUID hexadecimal grouping, and consistent
48-bit MAC separators, plus Base58Check length/alphabet/checksum checks for
legacy Litecoin and transparent Zcash candidates. Other cryptocurrency formats
remain candidates. No credential or network verification is performed.

Generic `api_key` results require a bounded 32–64 character alphanumeric token
immediately after an assignment label such as `api_key`, `access_token`,
`auth_token`, `token`, or `secret`. Labels are case insensitive, allow optional
hyphens/underscores, and use `:` or `=` with optional whitespace/quotes. Context
must fit in the preceding 96 bytes. Unlabeled keys can be missed; labeled
placeholders can still match. Custom rules stay candidates unless their name and
expression exactly match a bundled rule, which inherits its validation.

Matches are grouped by category, then source order. Matches from different
patterns may overlap; occurrences within one regex do not overlap. Zero-width
matches have empty text and equal offsets. Each run retains at most 1000 details
and 1 MiB of matched text. Retention takes turns across categories, then displays
retained matches grouped by category and source order. A noisy category cannot
exhaust the detail count before later categories get a turn. These remain shared
limits, so a broad scan can still omit evidence; a focused category pass can help.
`match_details_truncated` indicates omissions, and `match_details_omitted` records
exact omitted counts by category. Category and actionable-match detection continue
beyond that detail cap.

Each detail also includes `evidence`: up to 48 Unicode characters before and after
the match in its extracted/decoded string, and an optional `boundary_warning`.
Human output escapes this text; JSON/CSV retain it as structured data. Multiple URL
schemes, possible printable certificate/OCSP URI trailers, or numeric suffixes
in alphabetic hostname final labels trigger heuristic boundary warnings. Private
numeric-suffix domains and legitimate similarly named paths can also be flagged. Their original text and offsets remain unchanged, and otherwise valid
ambiguous URLs remain candidates rather than validated results. These warnings do
not parse ASN.1 or establish the correct boundary. Nonstandard/single-label hosts
also remain candidates. Path-shaped fragments in URL context are marked invalid
as local-file evidence; they remain in unfiltered output.

## Encodings and decoded analysis

`--encoding auto` is the default: UTF-8/ASCII, or UTF-16 when a BOM starts the scan.
`utf8` forces UTF-8; `utf16le`/`utf16be` support BOM-less Unicode and surrogate
pairs. Matching BOMs are skipped; a conflicting UTF-16 BOM is an error. Malformed
sequences delimit runs; an incomplete trailing code unit is ignored.

`--scan-utf16` adds a pass at both byte alignments and byte orders. It finds
printable ASCII-range UTF-16 runs (U+0020–U+007E), not arbitrary Unicode text.
Use explicit encoding selection for broader Unicode. This heuristic can produce
overlapping interpretations or duplicate primary-pass results. These findings
have `extraction: "embedded_utf16_candidate"`; primary results use `"text"`.
Embedded candidates follow primary findings and are not globally offset-sorted.

Base64 decoding accepts whole extracted runs and embedded standard padded tokens
that produce UTF-8 text. Each decoded layer uses the same patterns and validation.
Embedded tokens require at least eight characters; up to 128 are considered per run.
`--decode-depth` defaults to 1, allows 0–8, and limits nested decoding. `-D`, depth
0, or decode byte limit 0 disables decoding. Category and `-S` filters consider
matches in decoded layers as well as original text.

`decoded` preserves the first decoded text for compatibility. `decoded_layers`
contains each layer's text, depth, category list, validation details, and decoding
stop state. Each chain carries its original encoded token's `source_offset` and
`source_end_offset`. Their match offsets are UTF-8 byte positions **inside that
layer**, explicitly labeled `offset_space: "decoded_layer_utf8"`; they are not
pretended to be direct file offsets. Depth resets to 1 for each new token; the
source envelope identifies its decoding chain.
`next_decode` is `decoded`, `not_utf8_base64`, `byte_limit`, or `depth_limit`.
A limit state means further decoding was not attempted.

## Resource limits

`--min-length` defaults to 4 characters. `--max-string-bytes` defaults to 1048576
(minimum 4), measured in retained UTF-8 bytes for all encodings. Oversized runs
retain a character-aligned prefix and count the rest without storing it. They are
marked `truncated` and are not classified or decoded, since prefix matching can
produce false results. They remain visible as incomplete-analysis notices under
filters; empty matches on these runs do not imply absence of indicators.

`--max-decode-bytes` defaults to 262144 and bounds cumulative decoded text across
all tokens and layers of one run. Decoded detail output has the same per-layer detail caps.
Original `decode_status` is `decoded`, `disabled`, `truncated`, `limit`, or
`not_utf8_base64`; size-limit states do not certify valid Base64.

Summaries and entropy use fixed-size read buffers. Hex uses 64 KiB reads with
16-byte rows. String memory scales with configured caps; embedded scanning holds
up to four limited prefixes. Basic quiet JSON string reports (`-q -s -j report.json`,
including reports to `-j -`) accumulate hashes and the summary during string
extraction, without an input snapshot. These reports write the `strings` field
before `file_summary`; consume JSON by field name, not property position. Named
reports still use a temporary output file for atomic publication.

Regional entropy or embedded UTF-16 adds passes that retain a private snapshot of
the selected range. Other non-live combined modes also use snapshots for
consistent passes and stdin support. Comparisons snapshot the selected range of
the other file. Allow temporary space for these input ranges and output reports.
Other single modes stream directly.
Regular files with a reported nonzero size seek directly to `--offset`, avoiding
reads of the discarded prefix. Stdin, pipes, devices, and zero-size virtual files
consume that prefix sequentially. An offset exactly at EOF selects an empty range;
an offset beyond EOF is an error, including with `--length 0`. Analyze stable files
for consistent results; concurrent file modification is not synchronized.

## Regional entropy

`--entropy` emits consecutive, nonoverlapping windows, default 4096 bytes. Each
record has absolute offset, actual length, entropy in bits/byte, and `high` based
on `--entropy-threshold` (default 7, allowed 0–8). The final short window is
included; an empty scan has no regions. High entropy alone does not prove
compression or encryption. Entropy is also compared region-by-region in file
comparison using the selected window size and threshold.

## File comparison

`--compare OTHER_FILE` treats the primary file as “before” and the other file as
“after”. It reports SHA256 content equality, the other summary, added/removed
strings and indicators, occurrence-count or sampled-offset changes, and regional
entropy differences. Decoded strings/indicators are included when decoding is on.
Encoding, range, limits, category filters, and minimum length apply to both inputs.
The primary input can be stdin; the comparison input must be a path.

Identity keys hash full retained text with SHA256. Previews are limited to 256
characters; strings also distinguish encoding/extraction and decoded depth.
Indicators distinguish category, validation status, and decoded depth. Decoded
indicator positions refer to their encoded source envelope in the comparison.

Indexes cap at 10000 unique strings and 10000 unique indicators per file. They
retain counts and the first 8 occurrence offsets. `incomplete_index` flags index
caps, truncated findings/details, or position sampling; do not interpret missing
differences as proof of equality when it is true. Entropy differences retain the
first 1000 records and count the rest in `entropy_changes_omitted`. Hash equality
still describes the full selected ranges. Sections/imports are not inspected.

## Automation and reports

JSON schema version 1 retains `file_summary` and `strings` (null when not selected)
and adds scan-range metadata, decoded layers, optional `entropy_regions` and
`comparison`, and a final `complete: true`. New fields are additive.

Standard `--jsonl` output starts with a `summary` event carrying `schema_version`, `file_summary`,
and `scan_range`, followed by `string`, `entropy`, and/or `comparison` events whose
payload is under `data`. A final `complete` event confirms successful completion.
An interrupted stdout stream may contain valid partial events; require that final
event before treating the report as complete. Named reports are written to a
temporary sibling file and replace their destination only after success.

`--match-exit-code` and `--no-match-exit-code` accept 0–255 and both default to 0.
They apply after successful processing based on candidate/validated indicators in
the **primary** scan, including decoded layers and active category filters. Invalid
matches alone do not trigger the match code. No-match means none was detected,
not proof of absence when limits or heuristics apply. Comparison differences and
high entropy do not trigger match codes. Processing errors use code 1; CLI parse
errors use code 2. Prefer other values for configured match codes.

Quiet mode suppresses human output, not reports or errors. Closed stdout pipes
are quiet early termination in terminal-only mode. With a named report, analysis
continues and publishes it despite a closed terminal pipe. Other terminal errors
are reported after saving the report; report failures remain fatal.

### Reliability and provenance (0.2.0)

`binsith --version` prints the version, Git revision, source SHA-256, target,
and build profile (`-V` prints the short version). The source fingerprint covers
`Cargo.toml`, `Cargo.lock`, `build.rs`, and files under `src/`; it identifies the
compiled inputs even when local source edits differ from the recorded revision.
It is an identity aid, not a signature or proof of reproducible compilation.

JSON reports add `metadata` with build identity, compiler version, effective
encoding and decoding state, parsed CLI configuration, and an SHA-256 fingerprint
of the effective patterns. Pattern hashing uses compact JSON serialization of
sorted `[name, expression]` pairs after category selection. JSONL puts these fields
in the final `complete` event's `data`. These are additive schema-version-1 fields.

`complete` and `processing_complete` mean the requested processing finished.
`analysis_coverage.status` separately reports `limited` or
`complete_within_configured_scope`. Limitation counts identify truncated strings,
strings and decoded layers with omitted match details, and strings with decoding
limits. Comparison limits are reported as a boolean. Counts cover both inputs
when comparing and all enabled extraction passes; they are not deduplicated counts
of physical byte ranges. The configured range, minimum length, encoding, categories,
and disabled decoding define the chosen scope. Complete coverage within that scope
is **not proof that a file is safe**.

Use an optional exit policy for automation:

```sh
binsith -s sample.bin --match-exit-code 7 --no-match-exit-code 8 --inconclusive-exit-code 9 -j report.json
```

Processing errors fail as before. Otherwise a primary-input indicator returns the
match code, even if coverage is limited. With no primary-input indicator, a limited
scan returns the inconclusive code when configured, falling back to the no-match
code otherwise. Comparison-input limitations also make coverage limited. The
inconclusive option enables string analysis. Matching-only/category output retains
limit notices so filtering cannot hide incomplete analysis.

HTTP(S) extraction now retains ports, query parameters, fragments, percent escapes,
and bracketed IPv6 hosts. A URL parser checks syntax; no network requests are made.
Original evidence and offsets are preserved. Trailing prose punctuation (`.,;!`)
and unmatched closing brackets are excluded by the bundled URL rule; when these
are intentional URL characters, use percent encoding or a custom pattern. Windows
drive paths support backslashes and spaces. IPv4 candidates embedded in larger
dotted or alphanumeric tokens are suppressed. Custom patterns retain their spans
and candidate classification.

Base64 decoding handles standard padded tokens inside assignments and quoted text,
as well as whole extracted strings. Embedded tokens must contain at least eight
characters. Each token's decoded layers carry its exact original byte envelope;
match offsets inside a decoded layer remain UTF-8 offsets relative to that layer.
Nested decoding treats each decoded layer as a whole Base64 value. URL-safe and
unpadded variants are not supported. A shared per-string decoded-byte budget and
128-candidate cap bound work across tokens. Depth limits are reported conservatively
when another syntactically plausible Base64 layer remains. `decoded` remains a
compatibility field containing the first successful decoded token.

The GitHub Actions workflow runs formatting and debug/release tests on Linux,
macOS, and Windows. Local verification does not imply these remote jobs have run.


### Live JSON Lines (0.3.0)

```sh
binsith --live-jsonl sample.bin
cat sample.bin | binsith --live-jsonl --category URL -
```

`--live-jsonl` enables string analysis and JSONL output. Its event order is
`start`, primary `string` findings, any additional analysis events, `summary`,
then `complete`. The start event has `data.schema_version: 1`,
`data.mode: "live_jsonl"`, and `data.summary_position: "end"`. The final summary
uses the same fields as the standard JSONL summary. Build/configuration metadata
and analysis coverage remain in the completion event. Existing `--jsonl` event
ordering is unchanged. Ordinary JSON reports preserve their fields and values;
property order can vary, including strings-first basic quiet reports.

Each live event is flushed immediately. A string finding is available when its
run ends (a delimiter or EOF), not while the string is still arriving. Filters
can suppress findings. Offsets are skipped before scanning starts. Hashes, MIME,
size, and overall entropy are accumulated during the first pass and emitted only
after all requested analysis succeeds. `--length` can end the selected range
without waiting for the source stream to close.

Basic live analysis needs no input snapshot. Embedded UTF-16 scanning, regional
entropy, comparison, and hex mode capture the selected range during the first
pass and perform additional passes after that range ends; their results are not
live during ingestion. These combinations require temporary disk space. Live
mode emits structured output only; human output, including hex display, is
suppressed. Avoid selecting hex mode when only the live report is needed.

With `-j PATH`, a named report remains atomic: events go to a temporary sibling
and the destination is replaced only after successful completion. Use stdout for
immediate consumption. On failure or interruption, partial stdout events are not
a completed report; always require the final `complete` event. Existing match and
inconclusive exit policies apply unchanged.

### Robustness and performance checks

`cargo test --locked` includes deterministic mutation/property tests with a fixed
seed: 256 cases across all four primary encoding selections and embedded UTF-16,
using both one-byte reads and buffered reads. They check chunk-independent output,
source-byte spans, decoded-text spans, retained-string/detail bounds, shared decode
budgets, malformed Unicode, truncation, zero-width/overlapping patterns, nested
Base64, and output-error propagation. The large-input checks include a 1 MiB run
under a 64-byte retention cap and decode-depth/budget combinations.

These are reproducible fuzz-style regression tests, not a coverage-guided fuzzing
campaign or proof that all malformed inputs are safe. Existing CLI tests also cover
range boundaries, failed reports, open-stdin streaming, and completion markers.

For process-level mutation checks and performance measurements, use Python 3.9+
with a release build (no third-party Python packages are needed):

```sh
cargo build --release --locked
python3 tools/quality_checks.py --output target/quality-baseline.json
python3 tools/quality_checks.py --baseline target/quality-baseline.json --output target/quality-current.json
```

The harness defaults to 128 deterministic CLI mutations, a 16 MiB generated corpus,
five timed runs after an excluded warm-up, and a 30-second timeout per process.
Use `--cases`, `--mib`, `--runs`, and `--timeout` to adjust those settings. Every
successful mutated scan must report the exact selected-range SHA-256 and length;
expected range/BOM errors must fail without a completion event.

Benchmarks cover summary, string analysis, and live JSONL throughput, plus latency
from writing a complete string to receiving its first finding with stdin still
open. Full-run timings include process startup and discard stdout to avoid disk
report costs. JSON results include samples, median wall time, MiB/s, executable
build identity, harness fingerprint, workload settings, platform, and peak RSS. RSS is measured per child
via `wait4` on macOS/Linux; it is `null` where unavailable. Retention assertions and
RSS measurements do not impose a hard operating-system memory limit.

An optional baseline comparison exits 1 when median time or peak RSS increases
more than `--max-regression-percent` (default 25). Other successful runs exit 0;
assertions, timeouts, and incompatible baselines fail. Comparisons require matching
platform, architecture, harness fingerprint, and workload settings. Run on the same otherwise-idle
machine: this check cannot detect different hardware with matching platform names,
and scheduler load, thermal state, and filesystem cache can affect results.

CI runs the Rust checks with a 15-minute job timeout. Linux additionally runs a
small process-level stress/benchmark smoke check; timing comparisons are kept local
to avoid treating noise from shared CI runners as performance regressions.

The robustness suite also injects `Interrupted` reads and hard failures at every
byte boundary of UTF-8/UTF-16 fixtures, including split surrogate pairs. Retried
reads must preserve findings, hashes, and captured snapshot bytes. Snapshot-write
failures must stop analysis. CLI cancellation checks terminate an active process
after a finding is written and verify that stdout has no completion marker and an
existing named report remains unchanged. A forceful kill can leave temporary files;
it does not publish the temporary report over the destination.

Normal EOF is a valid end of input, including when supplied by another program.
BinSith cannot infer whether that upstream program failed before closing its pipe;
consumers should check the upstream process status as well as report completion.

For coverage-guided exploration with AddressSanitizer, the separate
[fuzz workspace](fuzz/README.md) includes a bounded cargo-fuzz target and curated
seeds. It checks chunk-independent findings, exact offsets, and resource caps
while mutating encoding and decode settings. A separate Linux CI job runs a short
sanitizer campaign. This complements deterministic mutation and I/O-failure tests.

### Indicator export (0.4.0)

```sh
binsith sample.bin --export-indicators indicators.json --quiet
binsith sample.bin --export-indicators indicators.csv --export-format csv --quiet
binsith sample.bin --category URL,ip_address --export-indicators -
binsith --live-jsonl sample.bin --export-indicators indicators.json
```

`--export-indicators PATH` enables string analysis and writes a deduplicated export
after analysis finishes. `-` selects stdout; the default format is JSON regardless
of filename extension. Use `--export-format csv` for CSV. An export and the normal
analysis report may be requested together with distinct destinations; they cannot
both write to stdout. Named outputs are independently atomic, not a multi-file
transaction. If the second output fails to publish, the first may already exist.

Entries are sorted by category, exact value, and validation status. No URL, case,
or Unicode normalization is applied. Candidate, validated, and invalid matches are
all retained with their status and validation reason. Filter invalid entries when
your downstream workflow requires only actionable candidates. Export includes the
primary input only, even with `--compare`. Configured categories, extraction modes,
minimum length, ranges, and decoding limits apply.

Each entry carries `observed_occurrences` and a `locations` list. Raw locations have
absolute source byte offsets and an exclusive end. Decoded locations describe the
original encoded token's source envelope, `decode_encoding`, `decode_depth`, and
UTF-8 offsets relative to that decoded layer. Source encoding and extraction method
distinguish primary findings from embedded UTF-16 candidates. Repeated identical
locations are stored once; occurrence counts reflect observed retained match details
across all passes, including overlapping extraction interpretations. They do not
count upstream matches omitted by analysis limits.

JSON contains `context` and `indicators`. Context includes the selected-range file
summary and hashes, configuration/build metadata, analysis coverage, and export
limit counters, and `upstream_omitted_details_by_category`. Each location includes
its own evidence context, including for decoded findings. The index retains at most 10,000 unique indicators, 16 MiB of
category/value and retained context bytes (excluding storage overhead and duplicated index keys), and
64 locations per indicator. Beyond these limits, existing-entry occurrence counts
continue, omitted observations are counted, and `export_limited` is true. Upstream
truncation is reported separately through `analysis_coverage`. Export limits also
participate in the configured inconclusive-exit policy; positive matches still take
precedence. A limited export is not an exhaustive list of indicators.

CSV uses quoted fields and CRLF record endings. Read it with a CSV parser because
values can contain commas, quotes, or decoded newlines. Rows with
`record_type=indicator` carry indicator data, with locations encoded in the
`locations_json` cell. A final `record_type=context` row carries `context_json` and
confirms completion, including for empty exports. Require that final row when
consuming stdout; a truncated CSV may otherwise look valid. Values are preserved
exactly, including leading formula characters: import those columns as text when
using spreadsheet software. Named exports replace their destination only after a
successful write and flush.

### Export filters and category discovery (0.4.1)

```sh
binsith --list-categories
binsith --list-categories --patterns custom-patterns.toml
binsith sample.bin --export-indicators actionable.json --export-validation actionable --quiet
binsith sample.bin --export-indicators validated.csv --export-format csv --export-validation validated --quiet
```

`--list-categories` prints sorted category names, one per line, without a sample or
stdin read. With `--patterns`, it lists that custom file instead of the bundled
rules. Pattern files are compiled and validated before anything is printed. Listing
is a standalone operation: scan/output options and a sample argument are rejected.
Control characters in unusual custom names are escaped for terminal display.

`--export-validation` accepts `all` (the default), `actionable` (candidate and
validated matches), or `validated`. It requires `--export-indicators` and applies
to both raw and decoded matches in JSON and CSV. Filtering occurs before index
limits. Export context records `validation_filter` and `filtered_occurrences`,
counting observed match details excluded by this selection. Intentional filtering
does not mark coverage limited. Upstream analysis limits still apply and are
reported independently.

These filters affect only the indicator export. Normal analysis reports,
comparisons, and match/no-match exit policies keep their existing behavior. A
validated-only export can therefore be empty while a candidate match triggers the
configured match exit code. Validated means the implemented syntax/checksum checks
passed, not that an indicator is malicious, reachable, or authentic.

## License

Copyright 2026 VULNEX - Simon Roses Femerling.

BinSith is licensed under the [Apache License 2.0](LICENSE).


## Folder scanning

Directory scanning is included in 0.5.0 packages for macOS ARM64, Linux x86-64 and
Windows x86-64. Use the extracted binary or put it on your `PATH`. To build from
source, run `cargo build --locked --release` and use `target/release/binsith`.
See the filesystem and cancellation limitations below before scanning large trees.

### Try a small folder

Run these macOS/Linux examples in a directory where `folder-demo` does not exist.
The fixtures contain only synthetic text. Each scan uses a separate destination.

<!-- folder-example: setup -->
```sh
mkdir -p folder-demo/input/nested
printf 'https://example.org/download\n' > folder-demo/input/url.txt
printf 'hello\n' > folder-demo/input/plain.txt
printf '192.0.2.10\n' > folder-demo/input/nested/address.txt
```

Summarize the two top-level files. Subdirectories are excluded by default:

<!-- folder-example: summary -->
```sh
binsith folder-demo/input --output-dir folder-demo/summary -q
```

Scan all three files for strings and indicators with four workers:

<!-- folder-example: recursive -->
```sh
binsith folder-demo/input --output-dir folder-demo/recursive --recursive -s --jobs 4 -q
```

Both commands return 0. Summary-only indicator counters are `null`, meaning
analysis was not requested. The recursive scan has three complete reports and
two files with actionable indicators. Findings do not establish maliciousness.

To see how limited coverage is reported, deliberately lower the string limit:

<!-- folder-example: limited -->
```sh
binsith folder-demo/input --output-dir folder-demo/limited --recursive -s --max-string-bytes 8 -q
```

This command returns **1**. It still finishes orchestration and retains reports;
the URL and IP strings exceed the limit and are marked limited. An empty match
list in a limited report does not establish absence of indicators.

### Locate reports and interpret completion

| Artifact | Purpose |
| --- | --- |
| `manifest.json` | Batch configuration, build identity, counters, discovery state and stop reasons |
| `files.jsonl` | Admissions and terminal outcomes, with links to completed or limited reports |
| `errors.jsonl` | File, discovery and batch diagnostics |
| `results/<shard>/<id>.json` | Atomic per-file analysis reports |
| `.binsith.lock` | Exclusive ownership claim; normally removed after orderly shutdown |

Report IDs derive from lossless relative-path identities, not input contents.
Use the terminal record's `outcome.report.location` instead of guessing a filename.
Hard-linked files at distinct paths are separate entries. Display paths are for
humans; the structured path field preserves native identities. Treat sharding and
IDs as opaque when consuming reports. Batch artifacts have schema version 1.

After the recursive command completes, list its terminal results:

<!-- folder-example: inspect -->
```sh
python3 - <<'PY'
import json
from pathlib import Path
root = Path('folder-demo/recursive')
manifest = json.loads((root / 'manifest.json').read_text())
print(manifest['status'], manifest['counters']['complete'])
for line in (root / 'files.jsonl').read_text().splitlines():
    record = json.loads(line)
    if record['record_type'] == 'terminal':
        outcome = record['outcome']
        print(outcome['status'], record['display_path'],
              outcome.get('report', {}).get('location', 'no report'))
PY
```

The first line is `complete 3`; three terminal lines follow, in an unspecified
order. `status: complete` means orchestration finished, **not** that every file
succeeded. Check failed/limited/discovery-error counters and the process exit code.
`status: incomplete` means the inventory is unfinished. During execution, the
manifest is a checkpoint and can lag the journals. Per-file outcomes are
`complete`, `limited`, `failed`, `skipped` or `cancelled`.

| Exit code | Meaning |
| --- | --- |
| 0 | Completed without file/discovery failures, cancellations or limited coverage |
| 1 | Execution failure, limited coverage or unfinished orchestration |
| 2 | Invalid arguments or setup failure |
| 130 | Interrupted; takes precedence over other execution failures |

Indicator presence does not change folder exit codes. Zero eligible files is a
valid successful run; policy skips alone do not imply a failed scan. Counts cover
observed entries, not an atomic snapshot of a changing filesystem.

### Options and traversal

`--jobs` defaults to available CPUs capped at four. A positive explicit value
allows up to N active scans and 2N queued entries, subject to OS resources and
checked arithmetic. These are concurrency bounds, not memory or disk quotas.
Use fewer workers when storage or memory is constrained; more workers do not
always increase throughput.

The output directory must be new or empty. It cannot equal or contain the input
root. It may be inside the input tree, where it is excluded from traversal.
Input/output root components must not be symlinks or reparse points. Discovery
skips symlinks and special files; it includes hidden files and follows subdirectories
only with `--recursive`. Detectable input replacement or mutation fails the file
and prevents publication of its report; this is not a filesystem snapshot.

BinSith supports folder output on the tested macOS FAT32 USB.
It retains file handles for ownership checks and synchronizes FAT writes before
recording metadata; this can add substantial write latency. FAT32 uses the volume's
permission semantics. Existing output and preexisting AppleDouble metadata remain
protected from reuse.

Reading FAT32 inputs while placing reports and `TMPDIR` on APFS remains a tested
alternative. Hidden AppleDouble `._*` input files are scanned as ordinary files.
For outputs, macOS may create `._*` metadata companions; use the report locations
in `files.jsonl` to identify analysis reports.

Analysis flags apply independently to each file: summary, strings/matching strings,
category/custom-pattern selection, decoding and string limits, encoding, ranges,
embedded UTF-16 and entropy. For example, `--offset 4096` fails on files shorter
than that offset. Custom patterns are validated before output is claimed.

Folder mode rejects single-file destinations (`-j`), JSONL/live output, indicator
export options, comparison, hex dumps, category listing and custom match/no-match/
inconclusive exit codes. Folder-only options also require directory input.
There is no resume, archive extraction, watch mode or cross-file deduplication.

### Progress, interruption and recovery

File failures continue by default. `--fail-fast` stops admission after the first
file or discovery error, cancels queued work and lets active scans settle. Limited
coverage alone does not trigger fail-fast; it still makes the final exit code 1.

Human summaries and progress use stderr; stdout stays empty. `-q` suppresses the
summary and automatic progress. `--progress` explicitly enables progress even with
`-q` or redirected stderr. Progress uses periodic plain lines with processed,
active, queued, failed and limited counts plus selected bytes read. Totals remain
unknown until discovery finishes; file-rate/ETA estimates appear only when enough
stable observations exist. Extra passes and report writing can continue after
selected-byte counts stop increasing. Failed optional progress output does not
invalidate successfully written reports.

The first Ctrl+C requests cooperative shutdown. Published reports are preserved;
blocked OS calls can delay shutdown. A second interrupt requests process termination
without orderly cleanup, but a kernel-blocked filesystem operation can still delay
process exit until the operation is released. It may leave a stale claim, temporary
reports or a torn final journal line. A report can
also have been published before its terminal journal record was committed. Do not
infer batch success from report files alone.

Keep an interrupted batch for inspection and rerun into a **fresh destination**.
Do not remove the claim and reuse that directory as a resume mechanism. Journals
and atomic report/manifest replacement support inspection after process failure;
ordinary flushes are not a guarantee of survival through power loss (`fsync`
durability is not promised).

### Network output compatibility

Some macOS SMB mounts do not support the atomic no-replace publication needed
for folder output. BinSith refuses those output destinations rather than risking
replacement of an existing file or exposing partial reports. Use a supported local
output directory, or run BinSith on the file server with a local output path inside
the shared directory, then read the completed reports over SMB. The latter workflow
was verified on the Linux test server at one and four workers; it does not establish
network-output performance from macOS. Newly written network inputs must be stable;
concurrent or delayed metadata changes can result in `file_changed`.

### Storage, privacy and measured performance

Basic summary/string scanning streams input. Embedded UTF-16 and entropy may
require a temporary snapshot of each active file's selected range. Allow space
for concurrent snapshots, reports and journals. Large/deep directory traversal
also uses a private spool; report and journal growth are not capped by `--jobs`.
Unix output permissions are restricted, but access controls and storage protection
remain the operator's responsibility.

Reports and journals can contain local paths, extracted secrets, decoded text and
surrounding evidence. Keep input, output and temporary storage in an appropriate
location. BinSith does not execute scanned files or contact extracted addresses.

Local synthetic benchmarks covered 28 warm workload/worker combinations and 28
controlled write-latency combinations. Results are host-specific and do not
establish physical-storage performance. Native macOS, Windows and Linux runtime
checks pass; physical FAT32 performance remains unqualified.

On the tested FAT32 USB, the 128-file strings workload exceeded the 120-second
native benchmark timeout during warmup; no timed comparison completed.
For this drive, prefer local APFS output and temporary storage when scanning USB
inputs.

Follow-up diagnostics found variable delays in filesystem synchronization and metadata operations on
this USB. An experimental synchronization change did not reliably eliminate the
timeouts and was not adopted.
