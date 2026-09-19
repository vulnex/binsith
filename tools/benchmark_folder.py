#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: benchmark_folder.py
# Author: Simon Roses Femerling
# Created: 2026-09-19
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Measure existing per-file JSON scans before implementing native folder execution.

Uses synthetic, distinct files and fresh report destinations for every run. Cache
state is warm/uncontrolled; this is not a cold-storage benchmark. Child RSS is
reported separately from aggregate memory, which this harness does not measure.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from quality_checks import timed_process


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def write_sample(path, size, index):
    header = f"sample-{index:08d}: https://example.com/{index}\0".encode()
    block = header + bytes(4096 - len(header))
    digest = hashlib.sha256()
    with path.open("wb") as output:
        remaining = size
        while remaining:
            part = block[:remaining]
            output.write(part)
            digest.update(part)
            remaining -= len(part)
    return {"path": path, "size": size, "sha256": digest.hexdigest()}


def measure(binary, samples, destination, workers, timeout, flags):
    destination.mkdir()
    start = time.perf_counter()

    def scan(item):
        index, sample = item
        report = destination / f"{index:08d}.json"
        elapsed, rss = timed_process(
            [binary, str(sample["path"]), *flags, "-q", "-j", str(report)], timeout)
        # Child exit follows atomic publication. This is a conservative observable
        # first-report latency, not instrumentation of the internal commit instant.
        return report, elapsed, rss, time.perf_counter() - start

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(scan, enumerate(samples)))
    elapsed = time.perf_counter() - start
    # Validate every artifact outside the timed interval; failed runs are never data.
    output_bytes = 0
    for sample, (report, _, _, _) in zip(samples, results):
        data = json.loads(report.read_bytes())
        summary = data["file_summary"]
        if summary["size_bytes"] != sample["size"] or summary["sha256"] != sample["sha256"]:
            raise RuntimeError(f"report summary mismatch: {report.name}")
        output_bytes += report.stat().st_size
    peaks = [result[2] for result in results if result[2] is not None]
    return {"elapsed_seconds": elapsed,
            "first_report_observed_seconds": min(result[3] for result in results),
            "max_single_child_rss_bytes": max(peaks) if peaks else None,
            "report_bytes": output_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/binsith")
    parser.add_argument("--output", required=True)
    parser.add_argument("--files", type=positive, default=128)
    parser.add_argument("--kib", type=positive, default=64)
    parser.add_argument("--large-mib", type=positive, default=8)
    parser.add_argument("--runs", type=positive, default=3)
    parser.add_argument("--workers", type=positive, nargs="+", default=[1, 4])
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be finite and positive")
    binary = str(Path(args.binary).resolve())
    result = {
        "schema_version": 1,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "timing_helper_sha256": hashlib.sha256(Path(__file__).with_name("quality_checks.py").read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "build": subprocess.check_output([binary, "--version"], text=True, timeout=args.timeout).strip(),
        "platform": platform.platform(), "machine": platform.machine(),
        "settings": {"corpus_version": 1, "files": args.files, "kib": args.kib,
                     "large_mib": args.large_mib, "runs": args.runs,
                     "workers": args.workers, "warmup_runs": 1},
        "cache_policy": "warm/uncontrolled; one excluded warmup per scenario",
        "limitations": ["synthetic low-density indicators; no cold-cache claim",
                        "aggregate live RSS and temporary disk peak are not measured",
                        "first report observed at successful child exit",
                        "no native worker implementation or release gates measured yet"],
        "scenarios": {},
    }
    with tempfile.TemporaryDirectory(prefix="binsith-report-baseline-") as temporary:
        root = Path(temporary)
        tiny = [write_sample(root / f"tiny-{i}.bin", args.kib * 1024, i) for i in range(args.files)]
        large = [write_sample(root / "large.bin", args.large_mib * 1024 * 1024, args.files)]
        corpora = {"tiny_strings": (tiny, ["-s"]), "large_summary": (large, ["-i"]),
                   "mixed_strings": (tiny + large, ["-s"])}
        for name, (samples, flags) in corpora.items():
            for workers in dict.fromkeys(args.workers):
                key = f"{name}_{workers}_workers"
                runs = []
                for run in range(args.runs + 1):
                    # Delete reports between runs to avoid accumulation changing disk pressure.
                    with tempfile.TemporaryDirectory(prefix="reports-", dir=root) as folder:
                        measured = measure(binary, samples, Path(folder) / "output", workers, args.timeout, flags)
                    if run:
                        runs.append(measured)
                times = [run["elapsed_seconds"] for run in runs]
                median = statistics.median(times)
                result["scenarios"][key] = {
                    "flags": flags, "files": len(samples), "input_bytes": sum(s["size"] for s in samples),
                    "samples": runs, "median_seconds": median,
                    "spread_percent_of_median": 100 * (max(times) - min(times)) / median,
                    "files_per_second": len(samples) / median,
                }
                print(f"{key}: {median:.3f}s", flush=True)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # A baseline is evidence; never silently replace an earlier run.
    with destination.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")


if __name__ == "__main__":
    main()
