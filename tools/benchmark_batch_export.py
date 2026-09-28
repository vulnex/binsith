#!/usr/bin/env python3
"""Synthetic completed-batch export qualification, without sample files/network I/O.

Clones the public v0.5 artifact fixture into unique native path entries. Detail
multiplication/cardinality are structurally valid stress shapes, not scanner recall
or authenticity evidence. Cache is warm/uncontrolled. Each import is a fresh child;
fixture generation is outside timing. Results may contain local binary identity:
keep local reports in devnotes/ or target/, never upload them automatically.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/batch/released-v0.5"


def encode(value):
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def generate(destination, entries, shape, details):
    """Return the exact generated-artifact digest and byte count (no absolute roots)."""
    destination.mkdir()
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    terminal = json.loads((FIXTURE / "files.jsonl").read_text().splitlines()[1])
    template = json.loads((FIXTURE / terminal["outcome"]["report"]["location"]).read_text())
    digest = hashlib.sha256()
    total_bytes = 0

    def save(relative, data):
        nonlocal total_bytes
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest.update(relative.encode() + b"\0" + data)
        total_bytes += len(data)

    for key in ["observed_entries", "eligible", "complete", "files_with_indicators"]:
        manifest["counters"][key] = entries
    manifest["batch_id"] = "synthetic-export-benchmark-v1"
    save("manifest.json", encode(manifest))
    save("errors.jsonl", b"")
    journal_digest = hashlib.sha256()
    journal_size = 0
    with (destination / "files.jsonl").open("wb") as journal:
        for index in range(entries):
            name = f"sample-{index:08d}.bin"
            native = name.encode()
            report_id = hashlib.sha256(b"binsith:relative-path:v1\0unix-bytes-base64\0" + native).hexdigest()
            location = f"results/{report_id[:2]}/{report_id}.json"
            report = copy.deepcopy(template)
            report["file_summary"]["file_path"] = name
            if shape == "large":
                # Repeat observations inside one finding; do not inflate the string.
                report["strings"][0]["match_details"] *= details
            if shape == "cardinality":
                for finding in report["strings"]:
                    for group in [finding] + finding["decoded_layers"]:
                        for detail in group["match_details"]:
                            detail["text"] += f"-{index:08d}"
            row = copy.deepcopy(terminal)
            row.update(batch_id=manifest["batch_id"], entry_id=index + 1,
                       path={"encoding": "unix-bytes-base64", "value": base64.b64encode(native).decode()}, display_path=name)
            row["outcome"]["report"].update(report_id=report_id, location=location)
            admission = {k: v for k, v in row.items() if k != "outcome"}
            admission.update(sequence=2 * index + 1, record_type="admission")
            row["sequence"] = 2 * index + 2
            for record in [admission, row]:
                data = encode(record)
                journal.write(data)
                journal_digest.update(data)
                journal_size += len(data)
            save(location, encode(report))
    digest.update(b"files.jsonl\0" + journal_digest.digest())
    return {"sha256": digest.hexdigest(), "bytes": total_bytes + journal_size,
            "entries": entries, "shape": shape, "details_multiplier": details,
            "generator": "released-v0.5-clone-v1"}


def measure(command, timeout):
    with tempfile.TemporaryFile() as errors:
        started = time.perf_counter()
        child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
        peak = None
        try:
            if hasattr(os, "wait4"):
                while True:
                    pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                    if pid:
                        child.returncode = os.waitstatus_to_exitcode(status)
                        peak = usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)
                        break
                    if time.perf_counter() - started > timeout:
                        raise subprocess.TimeoutExpired(command, timeout)
                    time.sleep(0.005)
            else:
                child.wait(timeout=timeout)
        finally:
            if child.returncode is None:
                child.kill()
                child.wait()
        elapsed = time.perf_counter() - started
        errors.seek(0)
        if child.returncode not in (0, 1):
            raise RuntimeError(f"export exited {child.returncode}: " + errors.read().decode(errors="replace"))
        return {"elapsed_seconds": elapsed, "peak_rss_bytes": peak, "exit_code": child.returncode}


def verify(destination, sample, entries, expected_observations=None):
    manifest = json.loads((destination / "manifest.json").read_text())
    assert manifest["processing_complete"] and manifest["exit_code"] == sample["exit_code"]
    for name, receipt in manifest["artifacts"].items():
        data = (destination / name).read_bytes()
        assert len(data) == receipt["bytes"] and hashlib.sha256(data).hexdigest() == receipt["sha256"]
    indicators = json.loads((destination / "indicators.json").read_text())
    summary = json.loads((destination / "summary.json").read_text())
    assert summary["counts"] == indicators["counts"]
    assert indicators["counts"]["file_entries"] == entries
    counts = indicators["counts"]
    if expected_observations is not None:
        assert counts["observed_occurrences"] == expected_observations
    assert counts["observed_occurrences"] == (sum(i["observed_occurrences"] for i in indicators["indicators"])
                                                + counts["filtered_observations"] + counts["unretained_key_observations"])
    assert sum(i["location_observations_omitted"] for i in indicators["indicators"]) == counts["location_observations_omitted"]
    assert all(i["observed_occurrences"] == len(i["locations"]) + i["location_observations_omitted"] for i in indicators["indicators"])
    sample.update(scratch_high_water_bytes=manifest["scratch_high_water_bytes"], imported_bytes=manifest["imported_bytes"],
                  bundle_bytes=sum(p.stat().st_size for p in destination.iterdir()), counts=indicators["counts"],
                  semantic_sha256=hashlib.sha256(encode(indicators) + encode(summary)).hexdigest())


def positive(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/binsith")
    parser.add_argument("--entries", type=positive, default=1000)
    parser.add_argument("--shape", choices=["duplicate", "large", "cardinality"], default="duplicate")
    parser.add_argument("--details", type=positive, default=10000)
    parser.add_argument("--runs", type=positive, default=3)
    parser.add_argument("--timeout", type=positive, default=600)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.entries > 100000:
        parser.error("entries exceeds default importer scope of 100000")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="binsith-export-bench-") as temporary:
        base = Path(temporary).resolve()
        fixture = generate(base / "source", args.entries, args.shape, args.details)
        samples = []
        for run in range(args.runs):
            output = base / f"output-{run}"
            sample = measure([str(binary), "--batch-input", str(base / "source"), "--output-dir", str(output), "-q"], args.timeout)
            observations = args.entries * (2 * args.details + 2 if args.shape == "large" else 4)
            verify(output, sample, args.entries, observations)
            samples.append(sample)
        assert len({s["semantic_sha256"] for s in samples}) == 1, "nondeterministic semantic export"
    peaks = [s["peak_rss_bytes"] for s in samples]
    memory = "inconclusive" if any(p is None for p in peaks) else "pass" if max(peaks) <= 256 * 1024 * 1024 else "fail"
    result = {"schema_version": 1, "platform": platform.platform(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "binary_version": subprocess.check_output([str(binary), "--version"], text=True).strip(),
              "fixture": fixture, "cache_state": "warm_uncontrolled", "samples": samples,
              "median_seconds": statistics.median(s["elapsed_seconds"] for s in samples),
              "rss_gate": {"limit_bytes": 256 * 1024 * 1024, "verdict": memory},
              "throughput_gate": "baseline_only_not_yet_frozen"}
    # Exclusive report creation avoids overwriting earlier qualification evidence.
    with args.output.open("x") as report:
        json.dump(result, report, indent=2)
        report.write("\n")
    print(json.dumps({"entries": args.entries, "shape": args.shape, "median_seconds": result["median_seconds"], "rss_gate": memory}))
    return 1 if memory == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
