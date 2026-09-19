#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: test_folder_benchmarks.py
# Author: Simon Roses Femerling
# Created: 2026-09-19
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for benchmark observation parsing and regression gate decisions."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from benchmark_folder import scratch_size
from compare_folder_benchmarks import compare


class BenchmarkContracts(unittest.TestCase):
    def setUp(self):
        self.gates = json.loads((Path(__file__).resolve().parents[1] / "devnotes/benchmarks/folder-performance-gates.json").read_text())
        resource = {"available": True, "samples": 4, "errors": [],
                    "sampled_aggregate_rss_bytes": 8000000, "sampled_open_scratch_bytes": 1024}
        sample = {"elapsed_seconds": 1.0, "first_report_observed_seconds": 0.1,
                  "max_single_child_rss_bytes": 8000000}
        scenario = {"flags": ["-s"], "files": 1, "input_bytes": 1024,
                    "corpus_sha256": "fixture", "samples": [dict(sample) for _ in range(5)],
                    "resource_sample": {"resources": resource}}
        self.base = {"schema_version": 2, "harness_sha256": "fixture", "timing_helper_sha256": "fixture",
                     "build": "binsith fixture\nprofile: release",
                     "platform": "fixture", "machine": "fixture", "logical_cpus": 4, "settings": {},
                     "scenarios": {"mixed_strings_1_workers": scenario}}

    def test_same_run_passes_and_regression_fails(self):
        self.assertEqual(compare(self.base, self.base, self.gates)["status"], "pass")
        candidate = copy.deepcopy(self.base)
        for sample in candidate["scenarios"]["mixed_strings_1_workers"]["samples"]:
            sample["elapsed_seconds"] = 1.3
        self.assertEqual(compare(self.base, candidate, self.gates)["status"], "fail")

    def test_noisy_missing_and_nonfinite_measurements_cannot_pass(self):
        for field, value in [("elapsed_seconds", 1.5), ("elapsed_seconds", float("nan")),
                             ("first_report_observed_seconds", 2.0), ("max_single_child_rss_bytes", None)]:
            candidate = copy.deepcopy(self.base)
            candidate["scenarios"]["mixed_strings_1_workers"]["samples"][0][field] = value
            self.assertEqual(compare(self.base, candidate, self.gates)["status"], "inconclusive")
        candidate = copy.deepcopy(self.base)
        candidate["scenarios"]["mixed_strings_1_workers"]["resource_sample"] = None
        self.assertEqual(compare(self.base, candidate, self.gates)["status"], "inconclusive")

    def test_corpus_host_or_harness_changes_are_not_comparable(self):
        for field in ("settings", "platform", "harness_sha256"):
            candidate = copy.deepcopy(self.base)
            candidate[field] = "different"
            self.assertEqual(compare(self.base, candidate, self.gates)["status"], "incomparable")
        candidate = copy.deepcopy(self.base)
        candidate["scenarios"]["mixed_strings_1_workers"]["corpus_sha256"] = "different"
        self.assertEqual(compare(self.base, candidate, self.gates)["status"], "inconclusive")

    def test_snapshot_and_rss_regressions_are_reported(self):
        for field, value in [("sampled_open_scratch_bytes", 2048), ("sampled_aggregate_rss_bytes", 64000000)]:
            candidate = copy.deepcopy(self.base)
            candidate["scenarios"]["mixed_strings_1_workers"]["resource_sample"]["resources"][field] = value
            self.assertEqual(compare(self.base, candidate, self.gates)["status"], "fail")

    def test_invalid_gate_configuration_or_debug_build_cannot_pass(self):
        gates = dict(self.gates, max_median_regression_percent=float("nan"))
        self.assertEqual(compare(self.base, self.base, gates)["status"], "incomparable")
        gates = dict(self.gates, minimum_timed_runs=0)
        self.assertEqual(compare(self.base, self.base, gates)["status"], "incomparable")
        candidate = dict(self.base, build="binsith fixture\nprofile: debug")
        self.assertEqual(compare(self.base, candidate, self.gates)["status"], "incomparable")

    def test_scratch_parser_deduplicates_descriptors_and_excludes_other_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            def entry(pid, fd, inode, name, size):
                return f"p{pid}\nf{fd}\ntREG\nD1\ni{inode}\ns{size}\nn{name}\n"
            listing = (entry(10, 3, 123, root / "snapshot", 4096)
                       + entry(10, 4, 123, root / "snapshot", 4096)
                       + entry(11, 3, 123, root / "snapshot", 4096)
                       + entry(11, 5, 124, root / "deleted (deleted)", 2048)
                       + entry(11, 6, 125, str(root) + "-other/file", 999999)
                       + entry(11, 7, 126, root / "invalid", "bad"))
            self.assertEqual(scratch_size(listing, root), 6144)
            self.assertEqual(scratch_size("", root), 0)


if __name__ == "__main__":
    unittest.main()
