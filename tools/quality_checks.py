#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: quality_checks.py
# Author: Simon Roses Femerling
# Created: 2026-09-16
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Dependency-free CLI stress checks and repeatable local benchmarks.
Run against a release build. Reports include build identity and workload settings.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import random
import statistics
import subprocess
import tempfile
import threading
import time


def stress(binary, cases, timeout):
    rng = random.Random(0xB17517)
    seeds = [b"", b"https://example.com\0", b"config=aHR0cHM6Ly9leGFtcGxlLmNvbQ==\0",
             b"\xff\xfe\x00\xd8x\x00\x00\xdc\xff", b"\xfe\xff\xd8\x00\x00x\xff",
             b"\xf0\x9f\x98\x80\xc0\xaf\xed\xa0\x80", b"a" * 8192]
    for case in range(cases):
        data = bytearray(seeds[case % len(seeds)])
        for _ in range(rng.randrange(16)):
            if data and rng.randrange(2):
                data[rng.randrange(len(data))] = rng.randrange(256)
            else:
                data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
        offset = rng.randrange(len(data) + 2)
        length = rng.randrange(len(data) + 2)
        encoding = ["auto", "utf8", "utf16le", "utf16be"][case % 4]
        args = [binary, "--live-jsonl", "--encoding", encoding, "--offset", str(offset),
                "--length", str(length), "--max-string-bytes", "64", "--max-decode-bytes", "48",
                "--decode-depth", "3", "--scan-utf16", "-"]
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        complete = [e for e in events if e["type"] == "complete"]
        selected = data[offset:offset + length]
        bom = bytes(selected[:2])
        conflict = (encoding == "utf16le" and bom == b"\xfe\xff") or (encoding == "utf16be" and bom == b"\xff\xfe")
        expected_error = offset > len(data) or conflict
        if expected_error:
            assert result.returncode == 1 and not complete, (case, result.returncode, result.stderr)
        else:
            assert result.returncode == 0 and len(complete) == 1, (case, result.returncode, result.stderr)
            summary = next(e["file_summary"] for e in events if e["type"] == "summary")
            assert summary["size_bytes"] == len(selected), case
            assert summary["sha256"] == hashlib.sha256(selected).hexdigest(), case
            for event in events:
                if event["type"] != "string":
                    continue
                f = event["data"]
                assert len(f["value"].encode()) <= 64, case
                assert sum(len(layer["text"].encode()) for layer in f["decoded_layers"]) <= 48, case
                for d in f["match_details"]:
                    assert offset <= d["offset"] <= d["end_offset"] <= offset + len(selected), case
    return {"cases": cases, "seed": "0xB17517", "timeout_seconds_per_case": timeout, "passed": True}


def timed_process(args, timeout, *, env=None):
    # wait4 measures this child only; RUSAGE_CHILDREN would accumulate previous runs.
    with tempfile.TemporaryFile() as errors:
        start = time.perf_counter()
        child = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors, env=env)
        peak = None
        try:
            if hasattr(os, "wait4"):
                while True:
                    pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                    if pid:
                        child.returncode = os.waitstatus_to_exitcode(status)
                        peak = usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)
                        break
                    if time.perf_counter() - start > timeout:
                        raise subprocess.TimeoutExpired(args, timeout)
                    time.sleep(0.001)
            else:
                child.wait(timeout=timeout)
        finally:
            if child.returncode is None:
                child.kill()
                child.wait()
        elapsed = time.perf_counter() - start
        errors.seek(0)
        assert child.returncode == 0, errors.read().decode(errors="replace")
        return elapsed, peak


def first_finding(binary, timeout):
    child = subprocess.Popen([binary, "--live-jsonl", "-"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    events = queue.Queue()
    def read_events():
        try:
            for line in child.stdout:
                events.put(json.loads(line))
        except Exception as error:
            events.put(error)
    thread = threading.Thread(target=read_events, daemon=True)
    thread.start()
    start = time.perf_counter()
    try:
        child.stdin.write(b"https://example.com\0")
        child.stdin.flush()
        while True:
            event = events.get(timeout=max(0.001, timeout - (time.perf_counter() - start)))
            if isinstance(event, Exception):
                raise event
            if event["type"] == "string":
                elapsed = time.perf_counter() - start
                assert child.poll() is None, "process ended before stdin closed"
                break
        child.stdin.close()
        child.wait(timeout=timeout)
        thread.join(timeout=timeout)
        assert not thread.is_alive() and child.returncode == 0
        return elapsed
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdin.close()
        thread.join(timeout=timeout)
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/binsith")
    parser.add_argument("--output", required=True, help="JSON results destination")
    parser.add_argument("--cases", type=int, default=128)
    parser.add_argument("--mib", type=int, default=16)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--baseline", help="Compare with a previous JSON result on the same machine")
    parser.add_argument("--max-regression-percent", type=float, default=25)
    args = parser.parse_args()
    if (not math.isfinite(args.timeout) or not math.isfinite(args.max_regression_percent)
            or min(args.cases, args.mib, args.runs, args.timeout) <= 0 or args.max_regression_percent < 0):
        parser.error("counts, size and timeout must be positive; regression allowance must be nonnegative")
    binary = str(Path(args.binary).resolve())
    settings = {"mib": args.mib, "runs": args.runs, "corpus_version": 1}
    result = {"schema_version": 1, "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "platform": platform.platform(), "machine": platform.machine(),
              "build": subprocess.check_output([binary, "--version"], text=True, timeout=args.timeout).strip(),
              "settings": settings, "stress": stress(binary, args.cases, args.timeout), "benchmarks": {}}
    with tempfile.TemporaryDirectory(prefix="binsith-quality-") as folder:
        sample = Path(folder) / "sample.bin"
        block = (b"https://example.com:8443/a?x=1&y=2\0" + bytes(range(256))) * 256
        remaining = args.mib * 1024 * 1024
        with sample.open("wb") as out:
            while remaining:
                part = block[:remaining]
                out.write(part)
                remaining -= len(part)
        scenarios = {"summary": [binary, str(sample), "-i", "-q"],
                     "strings": [binary, str(sample), "-s", "-q"],
                     "live_jsonl": [binary, str(sample), "--live-jsonl"]}
        for name, command in scenarios.items():
            timed_process(command, args.timeout)  # excluded warm-up
            samples = [timed_process(command, args.timeout) for _ in range(args.runs)]
            median = statistics.median(s[0] for s in samples)
            peaks = [s[1] for s in samples if s[1] is not None]
            result["benchmarks"][name] = {"median_seconds": median, "mib_per_second": args.mib / median,
                                          "peak_rss_bytes": max(peaks) if peaks else None,
                                          "samples_seconds": [s[0] for s in samples]}
        first_finding(binary, args.timeout)
        samples = [first_finding(binary, args.timeout) for _ in range(args.runs)]
        result["benchmarks"]["first_finding"] = {"median_seconds": statistics.median(samples), "samples_seconds": samples}
    regressions = []
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())
        for key in ["schema_version", "harness_sha256", "platform", "machine", "settings"]:
            if baseline[key] != result[key]:
                raise ValueError(f"baseline {key} differs; use the same environment and settings")
        for name, measurement in result["benchmarks"].items():
            for metric in ["median_seconds", "peak_rss_bytes"]:
                before = baseline["benchmarks"][name].get(metric)
                after = measurement.get(metric)
                if before and after is not None and after > before * (1 + args.max_regression_percent / 100):
                    regressions.append({"scenario": name, "metric": metric, "before": before, "after": after})
    result["regressions"] = regressions
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
