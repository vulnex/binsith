# Coverage-guided string analysis fuzzing

This separate Cargo workspace compiles the production string-analysis and validation
sources directly. It does not change the CLI or require a new public library API.
Its lockfile starts from the CLI's resolved dependencies, adding only the fuzzing
runtime and build dependencies. Shared direct dependency requirements, feature
flags and locked packages are checked by `python3 tools/check_fuzz_alignment.py`
and the fuzz CI job. Run that check after dependency changes: matching version
numbers alone does not establish the same enabled regex engines.

The `strings` target varies encoding, embedded UTF-16 extraction, matching-only
mode, decoding, minimum length, string retention, decode budget, and nesting depth.
It checks:

- No panic or sanitizer failure.
- Findings agree between one-byte and buffered reads, including expected BOM errors.
- Raw match spans reproduce their exact original bytes.
- Decoded spans reproduce their layer text, and source envelopes remain in range.
- Retained strings, decoded bytes, layer counts, and match-detail counts respect caps.

The first six input bytes select mode, flags, retained-byte budget, decode-byte
budget, decode depth, and minimum length. Remaining bytes are the sample. Inputs
longer than 8192 bytes are rejected by the harness; longer-run limits are covered
by the deterministic Rust tests. Seeds include malformed UTF-8/UTF-16, URLs,
Base64, nesting, empty payloads, and oversized runs in each extraction mode.

## Run a bounded campaign

Following the [Rust Fuzz Book setup](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html),
install nightly alongside stable (do not change the default toolchain), and install
cargo-fuzz locally inside the ignored build directory:

```sh
python3 tools/check_fuzz_alignment.py
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked --root target/fuzz-tools
mkdir -p fuzz/corpus/strings
cp fuzz/seeds/strings/* fuzz/corpus/strings/
RUSTUP_TOOLCHAIN=nightly target/fuzz-tools/bin/cargo-fuzz run strings fuzz/corpus/strings -- -max_total_time=30 -max_len=8192 -timeout=5 -rss_limit_mb=1024 -seed=45335
```

Commands run from the repository root. AddressSanitizer is enabled by cargo-fuzz's
default configuration. The campaign runs for approximately 30 seconds after
compilation, with a five-second per-input timeout and a 1024 MiB libFuzzer RSS limit.
These controls are fuzzer checks, not an OS sandbox. CPU speed, toolchain, and
runtime scheduling affect the number of explored inputs even with a fixed seed.
Use `-runs=N` as an additional execution bound if desired.

Generated corpus files and crash artifacts are ignored by Git. Keep the curated
seeds unchanged; copy a confirmed reproducer to the curated corpus and add a
focused Rust regression test after investigating it. Reproduce a saved artifact:

```sh
RUSTUP_TOOLCHAIN=nightly target/fuzz-tools/bin/cargo-fuzz run strings fuzz/artifacts/strings/CRASH_FILE
```

The process exits unsuccessfully on a panic, sanitizer error, timeout, or RSS-limit
violation. A successful short campaign only means no failure was found among the
executions performed; it does not establish exhaustive coverage or correctness.
Record toolchain versions, build identity, campaign arguments, and the final fuzzer
statistics when comparing runs. The target tests parser logic; process cancellation,
I/O failures, and report publication are covered by the ordinary test suite.
