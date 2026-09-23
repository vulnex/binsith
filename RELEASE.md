# Release procedure

The published version remains `0.4.2`. This checkout prepares **`0.5.0`**,
an unpublished release adding native folder scanning. Do not replace the published
0.4.2 assets. Publish 0.5.0 only after its final committed inputs and packages pass
the gates below.
The supported role remains static triage with analyst review. See CHANGELOG.md
for consumer-visible behavior changes.

## 0.5.0 scope and qualification

The preceding development candidate `195b803` passed all six hosted runtime,
sanitizer and package jobs. Those results establish the implementation checkpoint;
the version bump changes build metadata and the source fingerprint, so the 0.5.0
commit must receive fresh CI and native packages. Do not relabel older archives.

Retain these limitations in the release notes:

- Physical FAT32 performance is unqualified. The tested USB encountered substantial
  metadata latency and many-file timeouts. Prefer local APFS output and scratch.
- Direct output on the tested macOS SMB mount is unsupported because safe atomic
  no-replace publication is unavailable. Use local output or server-side scanning.
- A second interrupt may wait for kernel-blocked filesystem I/O; immediate process
  disappearance is not guaranteed. Completed reports remain useful, but interruption
  can leave an incomplete batch and a stale output claim.
- Packages are unsigned; checksums detect corruption, not publisher authenticity.

Confirm the remaining storage scope at promotion. Preparing these notes does not
mark incomplete physical-storage measurements as passing or authorize publication.

## Local verification

From a clean committed checkout:

```sh
cargo fmt --check
cargo fmt --manifest-path fuzz/Cargo.toml --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python3 tools/check_fuzz_alignment.py
python3 tools/check_export_compatibility.py
python3 tools/quality_checks.py --cases 64 --mib 1 --runs 2 --output target/quality-rc.json
```

Run the bounded AddressSanitizer campaign documented in fuzz/README.md using only
curated synthetic seeds. Never run malware samples as executables, scripts, or
loaded libraries. Static corpus evaluation is separate and remains local.

The export check compares JSON with CSV parsed by Python's standard libraries,
including quoted Unicode values, empty exports, validation filters, and limited
analysis. It does not replace testing your downstream application's importer.

## Folder-scanning candidate checks

After building the candidate, run the POSIX documentation examples on macOS/Linux:

```sh
python3 tools/check_folder_examples.py --output target/folder-examples.json
python3 tools/check_folder_filesystems.py --output target/folder-filesystems.json
python3 tools/check_folder_progress.py --binary target/debug/binsith
python3 tools/check_folder_progress.py --binary target/release/binsith
python3 -m unittest discover -s tools -p 'test_folder*.py'
```

Evidence paths must be new. Run the prepared Windows-specific filesystem and
console checks in a native Windows environment before qualifying that platform.
A cross-compile is insufficient. Retain build/source identity and log hashes for
each platform; the final candidate must include the tested scanner source.

Keep the folder performance thresholds frozen. Retain the warm and controlled
write-latency matrices, and run the physical-storage procedure in
[the storage runbook](devnotes/benchmarks/folder-storage-validation.md) on an
appropriate data volume. Synthetic sleeps do not close physical-storage coverage.
Do not promote an inconclusive noisy case as a pass; preserve original and repeated
observations. If physical coverage cannot be completed, explicitly accept and
document that release scope before promotion. Hosted Windows checks now pass on
the development candidate; rerun them on the versioned 0.5.0 commit.

The [folder readiness review](devnotes/folder-release-readiness.md) records current
local evidence and outstanding work. It is a development checkpoint, not permission
to publish or a replacement for final-commit CI, fuzzing and package verification.

## Package

```sh
python3 tools/package_release.py
```

The packager supports native macOS ARM64 (`aarch64-apple-darwin`), Linux x86-64
(`x86_64-unknown-linux-gnu`), and Windows x86-64 (`x86_64-pc-windows-msvc`).
Windows packages use ZIP; macOS and Linux packages use tar.gz. Each package is
read back and its extracted binary is smoke-tested before checksums are written.
macOS/Linux packages also execute the folder examples from the archived README
against the extracted binary. Their build and content hashes and check results
are saved as `dist/folder-examples-<target>.json` and retained with CI artifacts.

The `Release packages` workflow builds Linux and Windows artifacts from the
immutable workflow commit (`github.sha`), using the packaging script from that
same commit. It uploads CI artifacts only; publishing
them to GitHub Releases is a separate step. Linux is built on Ubuntu 22.04.
For publication, use the successful post-merge run whose commit matches the
release tag; PR runs package their temporary merge commit and must not be published.

The packager requires a clean checkout and a binary whose reported version,
revision, and source fingerprint match it. It includes only the trusted binary,
README.md, CHANGELOG.md, RELEASE.md, LICENSE, the selected README logo, and generated
BUILD-INFO.json. Alternative branding concepts are excluded. It validates
archive membership and binary digest before producing SHA256SUMS in `dist/`.
No recursive workspace archive is used. Local `evaluations/` content must never
be added to a release, source package, or public issue.

The archive is unsigned. SHA256SUMS detects corruption but is not proof of
publisher authenticity. This procedure does not claim reproducible compilation.

## Promotion gates

1. Run the configured Linux, macOS, and Windows CI matrix on the final candidate
   commit, including strict Clippy, debug/release tests, release builds and the
   folder-specific filesystem/console checks. Close or explicitly accept any
   remaining platform/storage scope limitations before qualification.
2. Pass the Linux sanitizer fuzz job and bounded stress job on that commit.
3. Exercise downstream JSON/CSV consumers when an application is in scope.
   For 0.4.2, the project owner confirmed no downstream application is in scope;
   application-specific testing is not applicable. Standard-parser checks remain
   required. Future integrations must qualify their importers. Additive fields
   retain schema version 1, but stricter validation can alter filtered results and
   match exit codes. Review omissions when analysis or export is limited.
4. Accept the documented evidence/context overhead, or benchmark representative
   workloads before establishing an operational latency requirement.
5. Build and checksum artifacts for each platform being distributed, then publish
   the candidate with its release notes. Do not describe untested platforms as
   verified or promote to a final version before the above gates pass.

A Git remote is required to run hosted CI and publish a release. Local successful
checks do not substitute for the other operating systems.
