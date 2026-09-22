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
state is warm/uncontrolled; this is not a cold-storage benchmark. Optional resource
profiling is separate from timing and samples only benchmark child processes.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import threading
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


def write_sample(path, size, index, kind="sparse_findings"):
    header = f"sample-{index:08d}: https://example.com/{index}\0".encode()
    if kind == "dense":
        block = header
    elif kind == "long":
        block = b"x" * 4096
    elif kind == "decode":
        block = b"aHR0cHM6Ly9leGFtcGxlLmNvbQ==\0" + header
    else:
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


def measure(binary, samples, destination, workers, timeout, flags, profile=False):
    destination.mkdir()
    scratch = destination.parent / "scratch"
    scratch.mkdir()
    monitor = ResourceMonitor(scratch)
    environment = dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
    start = time.perf_counter()

    def scan(item):
        index, sample = item
        report = destination / f"{index:08d}.json"
        command = [binary, str(sample["path"]), *flags, "-q", "-j", str(report)]
        if profile:
            began = time.perf_counter()
            with tempfile.TemporaryFile() as errors:
                child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors, env=environment)
                monitor.register(child.pid)
                try:
                    child.wait(timeout=timeout)
                    if child.returncode:
                        errors.seek(0)
                        raise RuntimeError(errors.read().decode(errors="replace"))
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                    monitor.unregister(child.pid)
            elapsed, rss = time.perf_counter() - began, None
        else:
            elapsed, rss = timed_process(command, timeout, env=environment)
        # Child exit follows atomic publication. This is a conservative observable
        # first-report latency, not instrumentation of the internal commit instant.
        return report, elapsed, rss, time.perf_counter() - start

    if profile:
        monitor.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(scan, enumerate(samples)))
    finally:
        if profile:
            monitor.stop()
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
            "report_bytes": output_bytes,
            "resources": monitor.result() if profile else None}


def scratch_size(lsof_output, scratch):
    """Deduplicate open regular scratch files by device/inode, including unlinked files."""
    files = {}
    entry = {}
    prefix = str(scratch.resolve()) + os.sep

    def flush():
        if (entry.get("t") == "REG" and entry.get("n", "").startswith(prefix)
                and all(key in entry for key in ("D", "i", "s"))):
            try:
                size = int(entry["s"])
            except ValueError:
                return
            if size >= 0:
                identity = (entry["D"], entry["i"])
                files[identity] = max(files.get(identity, 0), size)

    for line in lsof_output.splitlines():
        if not line:
            continue
        if line[0] in ("p", "f"):
            flush()
            entry = {}
        entry[line[0]] = line[1:]
    flush()
    return sum(files.values())


class ResourceMonitor:
    def __init__(self, scratch):
        self.scratch = scratch
        self.pids = set()
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.rss = 0
        self.scratch_bytes = 0
        self.samples = 0
        self.observed_processes = 0
        self.errors = []

    def register(self, pid):
        with self.lock:
            self.pids.add(pid)

    def unregister(self, pid):
        with self.lock:
            self.pids.discard(pid)

    def start(self):
        self.thread.start()

    def stop(self):
        self.done.set()
        self.thread.join()

    def sample(self):
        while not self.done.wait(0.02):
            with self.lock:
                pids = sorted(self.pids)
            if not pids:
                continue
            selected = ",".join(map(str, pids))
            try:
                rss = subprocess.run(["ps", "-o", "pid=,rss=", "-p", selected], capture_output=True, text=True, timeout=5)
                # Exit 1 is normal when these short-lived children have already exited.
                if rss.returncode not in (0, 1):
                    raise RuntimeError("ps failed: " + rss.stderr.strip())
                values = [line.split() for line in rss.stdout.splitlines() if line.strip()]
                sizes = [int(size) * 1024 for pid, size in values if int(pid) in pids]
                listing = subprocess.run(["lsof", "-a", "-p", selected, "-FftsinD"], capture_output=True, text=True, timeout=5)
                if listing.returncode not in (0, 1) or listing.stderr.strip():
                    raise RuntimeError("lsof failed or reported incomplete data: " + listing.stderr.strip())
                self.rss = max(self.rss, sum(sizes))
                self.scratch_bytes = max(self.scratch_bytes, scratch_size(listing.stdout, self.scratch))
                self.observed_processes = max(self.observed_processes, len(sizes))
                self.samples += 1
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                self.errors.append(str(error))
                return

    def result(self):
        measured = self.samples > 0 and not self.errors and self.rss > 0
        return {"available": measured, "samples": self.samples,
                "max_observed_processes": self.observed_processes,
                "sampled_aggregate_rss_bytes": self.rss if measured else None,
                "sampled_open_scratch_bytes": self.scratch_bytes if measured else None,
                "errors": self.errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/binsith")
    parser.add_argument("--output", required=True)
    parser.add_argument("--files", type=positive, default=128)
    parser.add_argument("--kib", type=positive, default=64)
    parser.add_argument("--large-mib", type=positive, default=32)
    parser.add_argument("--runs", type=positive, default=5)
    parser.add_argument("--workers", type=positive, nargs="+", default=[1, 4])
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", action="store_true", help="Separate ps/lsof resource sample per scenario (Unix)")
    args = parser.parse_args()
    if Path(args.output).exists():
        parser.error("output already exists; select a new result path")
    if args.profile and platform.system() not in ("Darwin", "Linux"):
        parser.error("resource sampling currently requires macOS or Linux")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be finite and positive")
    binary = str(Path(args.binary).resolve())
    result = {
        "schema_version": 2,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "timing_helper_sha256": hashlib.sha256(Path(__file__).with_name("quality_checks.py").read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "build": subprocess.check_output([binary, "--version"], text=True, timeout=args.timeout).strip(),
        "platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
        "settings": {"corpus_version": 3, "files": args.files, "kib": args.kib,
                     "large_mib": args.large_mib, "runs": args.runs,
                     "workers": args.workers, "warmup_runs": 1, "resource_profiling": args.profile},
        "cache_policy": "warm/uncontrolled; one excluded warmup per scenario",
        "limitations": ["synthetic corpus; no cold-cache or slow-storage claim",
                        "resource profiling is separate and may miss peaks between samples",
                        "temporary storage is logical bytes of open scratch files, not allocated disk blocks",
                        "aggregate RSS sums children; excludes harness and can double-count shared pages",
                        "resource sample ps and lsof readings are sequential, not an atomic snapshot",
                        "first report observed at successful child exit; native workers not implemented"],
        "scenarios": {},
    }
    with tempfile.TemporaryDirectory(prefix="binsith-report-baseline-") as temporary:
        root = Path(temporary)
        tiny = [write_sample(root / f"tiny-{i}.bin", args.kib * 1024, i) for i in range(args.files)]
        large = [write_sample(root / "large.bin", args.large_mib * 1024 * 1024, args.files)]
        dense = [write_sample(root / f"dense-{i}.bin", 256 * 1024, args.files + 1 + i, "dense") for i in range(16)]
        long = [write_sample(root / "long.bin", 32 * 1024 * 1024, 0, "long")]
        decode = [write_sample(root / f"decode-{i}.bin", 128 * 1024, i, "decode") for i in range(32)]
        corpora = {"tiny_strings": (tiny, ["-s"]), "large_summary": (large, ["-i"]),
                   "mixed_strings": (tiny + large, ["-s"]), "dense_strings": (dense, ["-s"]),
                   "long_strings": (long, ["-s", "--max-string-bytes", "4096"]),
                   "decoding": (decode, ["-s", "--decode-depth", "2"]),
                   "extra_passes": (large, ["-s", "--scan-utf16", "--entropy"])}
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
                resource_sample = None
                if args.profile:
                    with tempfile.TemporaryDirectory(prefix="profile-", dir=root) as folder:
                        resource_sample = measure(binary, samples, Path(folder) / "output", workers, args.timeout, flags, profile=True)
                result["scenarios"][key] = {
                    "flags": flags, "files": len(samples), "input_bytes": sum(s["size"] for s in samples),
                    "samples": runs, "resource_sample": resource_sample, "median_seconds": median,
                    "corpus_sha256": hashlib.sha256(json.dumps([(s["size"], s["sha256"]) for s in samples]).encode()).hexdigest(),
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
