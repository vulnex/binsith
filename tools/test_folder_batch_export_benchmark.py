"""Qualification harness contracts: stable fixtures and independent receipt checks."""
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest

import benchmark_batch_export as benchmark


class ExportBenchmarkTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "native Windows process counters")
    def test_windows_peak_survives_allocation_release_and_process_exit(self):
        sample = benchmark.measure([sys.executable, "-c",
            "x=bytearray(64*1024*1024); x[::4096]=b'x'*(len(x)//4096); del x"], 30)
        self.assertGreaterEqual(sample["peak_rss_bytes"], 64 * 1024 * 1024)
        self.assertEqual(sample["rss_source"], "windows_peak_working_set")

    @unittest.skipUnless(os.name == "nt", "native Windows process counters")
    def test_windows_invalid_handle_cannot_report_a_memory_pass(self):
        from types import SimpleNamespace
        with self.assertRaises(OSError):
            benchmark.windows_peak_rss(SimpleNamespace(_handle=0))

    def test_fixture_identity_is_stable_and_journal_reports_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = benchmark.generate(root / "a", 3, "duplicate", 1)
            second = benchmark.generate(root / "b", 3, "duplicate", 1)
            self.assertEqual(first, second)
            records = [json.loads(line) for line in (root / "a/files.jsonl").read_text().splitlines()]
            self.assertEqual([r["sequence"] for r in records], list(range(1, 7)))
            locations = []
            for row in records[1::2]:
                report = row["outcome"]["report"]
                locations.append(report["location"])
                body = json.loads((root / "a" / report["location"]).read_text())
                self.assertEqual(body["file_summary"]["file_path"], row["display_path"])
            self.assertEqual(len(set(locations)), 3)

    def test_receipt_mismatch_is_rejected_instead_of_a_benchmark_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "indicators.json").write_text("tampered")
            (root / "manifest.json").write_text(json.dumps({
                "processing_complete": True, "exit_code": 0,
                "artifacts": {"indicators.json": {"bytes": 8, "sha256": "0" * 64}},
            }))
            with self.assertRaises(AssertionError):
                benchmark.verify(root, {"exit_code": 0}, 1)


if __name__ == "__main__":
    unittest.main()
