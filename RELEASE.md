# Release procedure

The current version is `0.4.2`. Its supported role is static triage with
analyst review. See CHANGELOG.md for consumer-visible behavior changes.

## Local verification

From a clean committed checkout:

```sh
cargo fmt --check
cargo fmt --manifest-path fuzz/Cargo.toml --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python3 tools/check_export_compatibility.py
python3 tools/quality_checks.py --cases 64 --mib 1 --runs 2 --output target/quality-rc.json
```

Run the bounded AddressSanitizer campaign documented in fuzz/README.md using only
curated synthetic seeds. Never run malware samples as executables, scripts, or
loaded libraries. Static corpus evaluation is separate and remains local.

The export check compares JSON with CSV parsed by Python's standard libraries,
including quoted Unicode values, empty exports, validation filters, and limited
analysis. It does not replace testing your downstream application's importer.

## Package

```sh
python3 tools/package_release.py
```

The packager supports native macOS ARM64 (`aarch64-apple-darwin`), Linux x86-64
(`x86_64-unknown-linux-gnu`), and Windows x86-64 (`x86_64-pc-windows-msvc`).
Windows packages use ZIP; macOS and Linux packages use tar.gz. Each package is
read back and its extracted binary is smoke-tested before checksums are written.

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
   commit, including strict Clippy, debug/release tests, and release builds.
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
