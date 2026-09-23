# Changelog

## 0.5.0 — Unreleased

Release preparation for native folder scanning. The implementation has passed hosted
checks on macOS, Linux and Windows; this versioned release still requires its
own final-commit verification and packages before publication.

- Scan directories with bounded parallel workers, optional recursion, per-file JSON
  reports, an outcome journal and a batch manifest. Use a new or empty output
  directory for each run; published 0.4.2 packages do not include this mode.
- Add periodic stderr progress, fail-fast admission, cooperative interruption and
  a second-interrupt forced-exit request. A kernel-blocked filesystem operation
  may delay process exit even after the second interrupt. Folder exit codes
  distinguish complete success
  (0), execution/coverage failure (1), setup failure (2) and interruption (130).
- Preserve completed reports on partial failure; check input identity before
  publication and refuse report collisions. Process-crash recovery evidence does
  not establish power-loss durability or automatic resume.
- Retain existing single-file behavior and schema compatibility. Folder artifacts
  use version 1 schemas and lossless relative-path identities; consumers should
  follow journal report locations instead of deriving filenames.
- Reduce startup and regex-engine memory costs. macOS, Linux and Windows
  runtime checks pass on the preceding development candidate. All 28 local warm
  cases and 28 controlled write-latency
  combinations pass unchanged limits across retained observations. These are
  host-specific results, not a general speedup or physical-storage guarantee.
- Support folder output on the tested macOS FAT32 USB while retaining ownership
  and overwrite checks. Physical FAT32 performance remains unqualified: many-file
  tests timed out. Prefer local APFS output and temporary storage for this drive.
- Explain unsupported atomic publication on filesystems such as the tested macOS
  SMB mount. Direct output to that mount is unsupported; use local output or run
  Binsith on the file server using its local path.
- Verify Windows ACL, junction, long-path and console behavior in hosted CI. Keep
  console-test fixtures sparse without allocating their multi-gigabyte logical
  size, and stop CI immediately when a capability probe fails.
- Provide unsigned native candidate packages with build identity and checksum
  verification. Existing 0.4.2 release assets remain unchanged.

## 0.4.2 — 2026-09-19

- Promote RC1 analysis behavior to the final release for analyst-reviewed static triage.
- Provide native macOS ARM64, Linux x86-64, and Windows x86-64 packages with
  embedded build identity, extracted-binary smoke checks, and SHA-256 checksums.
- Build release packages from the workflow commit so their revision matches the
  versioned source, including the Windows source-fingerprint ordering fix.
- No downstream application is currently in scope; standard JSON/CSV parser
  compatibility is verified, while future integrations must qualify their importers.
- Evidence/context overhead documented below remains an accepted tradeoff.
  Artifacts remain unsigned; URL findings still require analyst review.

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

- Adopt the Byte Monogram logo; preserve alternative branding concepts in source.
- Check JSON/CSV parity with independent standard-library parsers in CI.
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
