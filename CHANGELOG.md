# Changelog

## 0.4.2-rc.1 — 2026-09-16

Release candidate for analyst-reviewed static triage. This is not a declaration of
cross-platform production readiness.

### Evidence quality

- Retain match details across categories fairly within existing bounds; report
  omitted counts per category instead of allowing path matches to hide IP evidence.
- Add bounded surrounding text and URL-boundary warnings to raw/decoded findings
  and exported locations. Preserve original values and source offsets.
- Flag concatenated URL schemes, possible certificate/OCSP trailers, and unusual
  numeric hostname suffixes. Syntax-invalid URLs remain invalid.
- Validate legacy Litecoin and transparent Zcash Base58Check checksums; mark
  path-shaped URL fragments invalid as evidence of local files.
- Stop polling exhausted regex iterators during fair retention.
- Fix a fuzz-discovered panic when multibyte Unicode whitespace precedes a path.
- Preserve independent path candidates in quoted fields following a URL.
- Close analyzed inputs before replacing report destinations on Windows.

### Compatibility

- JSON schema remains version 1: existing fields and CSV columns remain present.
  New `evidence`, `match_details_omitted`, and export-context fields are additive.
  Consumers must tolerate unknown fields in version-1 objects.
- Validation classifications intentionally change. `actionable` excludes invalid
  wallet/path matches but still includes ambiguous URL candidates. `validated`
  excludes those candidates. Match exit codes can change for checksum-invalid
  inputs; candidate presence is never a maliciousness verdict.
- Under detail limits the selected subset changes; display grouping is preserved.
  Export's 16 MiB text budget now also accounts for retained surrounding context.
- Human output adds escaped context and per-category omission counts. Parse JSON
  or CSV rather than relying on the presentation format.

### Release engineering

- Strict Clippy checks in CI; one documented internal argument-count exception.
- Restore fuzz harness dependency alignment for the new checksum validator.
- Exclude local malware-derived evaluations from Git and source/binary packages.
- Provide an allowlisted macOS release package with SHA-256 checksum and build
  identity. Artifacts are unsigned; a checksum is not publisher authentication.

### Evaluation and accepted tradeoffs

The preceding evidence-quality build completed 82 static scans of 41 samples,
recovered 817 previously omitted URL/IP reference locations, and flagged all 122
known overcaptured URL occurrences. No sample was executed. This is extraction
verification, not a labelled malware precision/recall benchmark.

That measured build used about 18–20% more corpus scan time and roughly 15 MiB
peak process RSS versus 13 MiB previously. This overhead is accepted for the RC
because it retains more evidence and context. Measurements are observational,
not a controlled benchmark or a guarantee for other machines.

URL boundary warnings remain heuristic. Container unpacking and binary structure
analysis remain external. Linux/Windows CI and hosted sanitizer results are
required before promotion to a final release.
