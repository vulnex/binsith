#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: check_scanner_compatibility.py
# Author: Simon Roses Femerling
# Created: 2026-09-19
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Compare ordinary JSON, streams and exit codes between two scanner builds."""
import argparse
import base64
import hashlib
import json
import math
from pathlib import Path
import subprocess
import tempfile


def identity(binary):
    return {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "build": subprocess.check_output([str(binary), "--version"], text=True, timeout=30).strip()}


def normalize(report):
    # Build provenance differs deliberately; analysis configuration is retained.
    for key in ("revision", "source_sha256", "rustc"):
        report["metadata"].pop(key, None)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    destination = Path(args.output)
    if destination.exists():
        parser.error("output already exists; choose a new evidence path")
    baseline, candidate = Path(args.baseline).resolve(), Path(args.candidate).resolve()
    mixed = (b"prefix\0https://example.com/a\0" +
             base64.b64encode(base64.b64encode(b"https://example.net/nested")) +
             b"\0\xfftail\0" + b"x" * 128 + b"\0")
    wide = "hello https://example.com/\U0001f600\0tail"
    cases = [
        ("summary", mixed, []),
        ("basic", mixed, ["-s"]),
        ("matching_only", mixed, ["-S"]),
        ("nested_decode", mixed, ["-s", "--decode-depth", "3"]),
        ("no_decode", mixed, ["-s", "--no-decode"]),
        ("decode_limit", mixed, ["-s", "--max-decode-bytes", "8"]),
        ("range", mixed, ["-s", "--offset", "7", "--length", "80"]),
        ("empty_range", mixed, ["-s", "--offset", str(len(mixed)), "--length", "0"]),
        ("empty", b"", ["-s"]),
        ("filtered", b"plain words\0", ["-S", "--no-match-exit-code", "8"]),
        ("long_limited", b"x" * 131075, ["-S", "--max-string-bytes", "4096", "--inconclusive-exit-code", "9"]),
        ("category_match", mixed, ["--category", "URL", "--match-exit-code", "7"]),
        ("utf16_bom", b"\xff\xfe" + wide.encode("utf-16-le"), ["-s"]),
        ("utf16le", wide.encode("utf-16-le") + b"x", ["--encoding", "utf16le"]),
        ("utf16be", wide.encode("utf-16-be"), ["--encoding", "utf16be"]),
        ("entropy_extra_pass", mixed, ["-s", "--entropy", "--entropy-window", "8"]),
        ("utf16_extra_pass", wide.encode("utf-16-le"), ["-s", "--scan-utf16"]),
    ]
    evidence = {"schema_version": 1, "baseline": identity(baseline), "candidate": identity(candidate),
                "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "comparison": "Parsed JSON equality excluding build revision/source/compiler; summary entropy absolute tolerance 1e-12; exact stdout/stderr/exit parity",
                "cases": [], "passed": True}
    with tempfile.TemporaryDirectory(prefix="binsith-scanner-compat-") as temporary:
        root = Path(temporary)
        sample, report_path = root / "input.bin", root / "report.json"
        for name, data, flags in cases:
            sample.write_bytes(data)
            for source in ("file", "stdin"):
                results = []
                for binary in (baseline, candidate):
                    report_path.unlink(missing_ok=True)
                    invocation = [str(binary), str(sample) if source == "file" else "-",
                                  "-q", "-j", str(report_path), *flags]
                    process = subprocess.run(invocation, input=data if source == "stdin" else None,
                                             capture_output=True, timeout=30)
                    report = normalize(json.loads(report_path.read_text()))
                    entropy = report["file_summary"].pop("entropy")
                    results.append((process, report, entropy))
                before, after = results
                parity = {
                    "report_equal": before[1] == after[1],
                    "entropy_equal": math.isclose(before[2], after[2], rel_tol=0, abs_tol=1e-12),
                    "stdout_equal": before[0].stdout == after[0].stdout,
                    "stderr_equal": before[0].stderr == after[0].stderr,
                    "exit_equal": before[0].returncode == after[0].returncode,
                }
                passed = all(parity.values())
                evidence["passed"] &= passed
                evidence["cases"].append({"name": name, "source": source, "flags": flags,
                                          "input_sha256": hashlib.sha256(data).hexdigest(),
                                          "input_bytes": len(data), "passed": passed,
                                          "baseline_exit": before[0].returncode,
                                          "candidate_exit": after[0].returncode, **parity})
    with destination.open("x", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, allow_nan=False)
        output.write("\n")
    print(f"{sum(case['passed'] for case in evidence['cases'])}/{len(evidence['cases'])} cases passed")
    raise SystemExit(0 if evidence["passed"] else 1)


if __name__ == "__main__":
    main()
