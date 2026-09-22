"""Regression tests for the independent scale evidence validator."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_folder_scale import descriptors, validate


class ScaleTests(unittest.TestCase):
    def test_descriptors_count_handles_but_deduplicate_storage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            scratch = root / 'scratch'
            inputs = root / 'input'
            output = root / 'output'
            listing = '\n'.join(['p42', 'fcwd', 'tDIR', f'n{inputs}',
                'f3', 'tREG', 'D1', 'i2', 's50', f'n{scratch / "x"} (deleted)',
                'f4', 'tREG', 'D1', 'i2', 's50', f'n{scratch / "x"} (deleted)',
                'f5', 'tREG', 's999', f'n{root / "input-other" / "file"}',
                'f6', 'tREG', 's10', f'n{inputs / "file"}',
                'f7', 'tDIR', f'n{inputs}',
                'f8', 'tREG', 's12', f'n{output / "results" / "ab" / ".pending-x"}'])
            result = descriptors(listing, inputs, scratch, output)
            self.assertEqual(result, {'open_descriptors': 6, 'input_files': 1,
                'input_directories': 1, 'scratch_files': 2, 'scratch_logical_bytes': 50,
                'pending_output_logical_bytes': 12})

    def test_validator_rejects_corrupt_reports_and_journals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            location = 'results/ab/abcd.json'
            report = root / location
            report.parent.mkdir(parents=True)
            body = {'file_summary': {'file_path': 'a', 'sha256': 'hash', 'size_bytes': 4},
                    'complete': True, 'processing_complete': True}
            manifest = {'batch_id': 'batch', 'status': 'complete', 'discovery_complete': True,
                'stop_reasons': [], 'counters': dict(eligible=1, complete=1, queued=0,
                    active=0, failed=0, limited=0, cancelled=0, discovery_errors=0, policy_skipped=0)}
            admission = dict(sequence=1, batch_id='batch', entry_id=1, path={'value': 'YQ=='},
                             display_path='a', record_type='admission')
            terminal = dict(admission, sequence=2, record_type='terminal', outcome={
                'status': 'complete', 'report': dict(report_id='abcd', location=location,
                                                    selected_bytes=4, duration_ms=1)})
            (root / 'manifest.json').write_text(json.dumps(manifest))
            (root / 'errors.jsonl').write_text('')
            def write(records):
                (root / 'files.jsonl').write_text('\n'.join(map(json.dumps, records)))
            report.write_text(json.dumps(body))
            write([admission, terminal])
            samples = {'a': {'sha256': 'hash', 'size': 4}}
            expected, _ = validate(root, samples)
            changed = copy.deepcopy(terminal)
            changed['outcome']['report']['duration_ms'] = 99
            write([admission, changed])
            self.assertEqual(validate(root, samples)[0], expected)
            for records in ([admission, terminal, terminal], [terminal], [admission],
                            [admission, dict(terminal, sequence=3)],
                            [admission, dict(terminal, display_path='wrong')]):
                write(records)
                with self.assertRaises((AssertionError, KeyError)):
                    validate(root, samples)
            write([admission, terminal])
            body['file_summary']['sha256'] = 'wrong'
            report.write_text(json.dumps(body))
            with self.assertRaises(AssertionError):
                validate(root, samples)


if __name__ == '__main__':
    unittest.main()
