# BinSith

BinSith analyzes binary data: hashes, MIME signatures, strings, indicators,
encoded content, hex dumps, regional entropy, and differences between files.
It does not inspect executable headers, sections, imports, or entry points.

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
48-bit MAC separators. Other categories, including cryptocurrency addresses,
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
and 1 MiB of matched text; `match_details_truncated` indicates omissions. Category
and actionable-match detection continue beyond that detail cap.

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
up to four limited prefixes. Combined modes and embedded scanning snapshot the
selected input range to private temporary disk storage for consistent passes and
stdin support. Comparisons also snapshot the selected range of the other file.
Allow temporary space for those ranges. Other single modes stream directly.
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

JSON Lines starts with a `summary` event carrying `schema_version`, `file_summary`,
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
