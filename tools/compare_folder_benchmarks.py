#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: compare_folder_benchmarks.py
# Author: Simon Roses Femerling
# Created: 2026-09-19
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Evaluate report-producing benchmarks against frozen pre-refactor gates."""
import argparse
import json
import math
from pathlib import Path
import statistics


def allowance(base, percent, minimum):
    return base + max(base * percent / 100, minimum)


def finite_numbers(values):
    return all(isinstance(value, (int, float)) and not isinstance(value, bool)
               and math.isfinite(value) and value >= 0 for value in values)


def compare(baseline, candidate, gates):
    incompatible = []
    numeric_gates = [
        "max_noise_spread_percent", "max_median_regression_percent",
        "minimum_time_allowance_seconds", "max_first_report_regression_percent",
        "minimum_first_report_allowance_seconds", "max_single_child_rss_regression_percent",
        "minimum_single_child_rss_allowance_bytes", "max_aggregate_rss_regression_percent",
        "minimum_aggregate_rss_allowance_bytes",
    ]
    if (gates.get("schema_version") != 1
            or type(gates.get("minimum_timed_runs")) is not int
            or gates["minimum_timed_runs"] <= 0
            or not finite_numbers([gates.get(key) for key in numeric_gates])):
        return {"status": "incomparable", "reasons": ["invalid gate configuration"], "scenarios": {}}
    for label, result in (("baseline", baseline), ("candidate", candidate)):
        if "profile: release" not in result.get("build", "").splitlines():
            incompatible.append(label + " is not identified as a release build")
    for key in ("schema_version", "harness_sha256", "timing_helper_sha256", "platform", "machine", "logical_cpus", "settings"):
        if key not in baseline or baseline[key] != candidate.get(key):
            incompatible.append(key)
    if baseline.get("schema_version") != 2 or set(baseline.get("scenarios", {})) != set(candidate.get("scenarios", {})):
        incompatible.append("scenario/schema set")
    if incompatible:
        return {"status": "incomparable", "reasons": incompatible, "scenarios": {}}
    outcomes = {}
    for name, before in baseline["scenarios"].items():
        after = candidate["scenarios"][name]
        failures, incomplete = [], []
        thresholds = {}
        for field in ("flags", "files", "input_bytes", "corpus_sha256"):
            if before.get(field) != after.get(field) or field not in before:
                incomplete.append("incompatible " + field)
        for label, scenario in (("baseline", before), ("candidate", after)):
            samples = scenario.get("samples", [])
            if len(samples) < gates["minimum_timed_runs"]:
                incomplete.append(label + " has too few timed runs")
            times = [sample.get("elapsed_seconds") for sample in samples]
            if not times or not finite_numbers(times) or min(times) <= 0:
                incomplete.append(label + " has invalid timings")
                continue
            median = statistics.median(times)
            spread = 100 * (max(times) - min(times)) / median
            if spread > gates["max_noise_spread_percent"]:
                incomplete.append(label + " timing spread exceeds noise gate")
            firsts = [sample.get("first_report_observed_seconds") for sample in samples]
            if not finite_numbers(firsts) or any(first > elapsed for first, elapsed in zip(firsts, times)):
                incomplete.append(label + " has invalid first-report timings")
        if not incomplete:
            for field, percent, minimum in [
                ("elapsed_seconds", gates["max_median_regression_percent"], gates["minimum_time_allowance_seconds"]),
                ("first_report_observed_seconds", gates["max_first_report_regression_percent"], gates["minimum_first_report_allowance_seconds"]),
            ]:
                base = statistics.median(sample[field] for sample in before["samples"])
                current = statistics.median(sample[field] for sample in after["samples"])
                thresholds[field] = allowance(base, percent, minimum)
                if current > thresholds[field]:
                    failures.append(field + " regression")
            for label, scenario in (("baseline", before), ("candidate", after)):
                peaks = [sample.get("max_single_child_rss_bytes") for sample in scenario["samples"]]
                if not finite_numbers(peaks) or not peaks or min(peaks) <= 0:
                    incomplete.append(label + " missing child RSS")
            if not incomplete:
                baseline_peak = max(sample["max_single_child_rss_bytes"] for sample in before["samples"])
                current_peak = max(sample["max_single_child_rss_bytes"] for sample in after["samples"])
                thresholds["single_child_rss_bytes"] = allowance(baseline_peak, gates["max_single_child_rss_regression_percent"], gates["minimum_single_child_rss_allowance_bytes"])
                if current_peak > thresholds["single_child_rss_bytes"]:
                    failures.append("single-child RSS regression")
        required = any(name.startswith(workload + "_") for workload in gates["required_resource_workloads"])
        resources = []
        for label, scenario in (("baseline", before), ("candidate", after)):
            resource = (scenario.get("resource_sample") or {}).get("resources") or {}
            valid = (resource.get("available") is True and resource.get("samples", 0) > 0
                     and not resource.get("errors")
                     and finite_numbers([resource.get("sampled_aggregate_rss_bytes"), resource.get("sampled_open_scratch_bytes")]))
            if required and not valid:
                incomplete.append(label + " required resource sample unavailable")
            if valid:
                if resource["sampled_open_scratch_bytes"] > scenario["input_bytes"]:
                    failures.append(label + " open scratch exceeds input-size bound")
                resources.append(resource)
        if len(resources) == 2:
            thresholds["sampled_aggregate_rss_bytes"] = allowance(resources[0]["sampled_aggregate_rss_bytes"], gates["max_aggregate_rss_regression_percent"], gates["minimum_aggregate_rss_allowance_bytes"])
            if resources[1]["sampled_aggregate_rss_bytes"] > thresholds["sampled_aggregate_rss_bytes"]:
                failures.append("sampled aggregate RSS regression; investigate with instrumentation")
        status = "inconclusive" if incomplete else "fail" if failures else "pass"
        outcomes[name] = {"status": status, "failures": failures, "inconclusive_reasons": incomplete, "thresholds": thresholds}
    statuses = [outcome["status"] for outcome in outcomes.values()]
    status = "inconclusive" if not statuses or "inconclusive" in statuses else "fail" if "fail" in statuses else "pass"
    return {"status": status, "scenarios": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--gates", default="tools/folder-performance-gates.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    load = lambda path: json.loads(Path(path).read_text())
    report = compare(load(args.baseline), load(args.candidate), load(args.gates))
    report["inputs"] = {"baseline": args.baseline, "candidate": args.candidate, "gates": args.gates}
    with Path(args.output).open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, allow_nan=False)
        destination.write("\n")
    print(report["status"])
    raise SystemExit(0 if report["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
