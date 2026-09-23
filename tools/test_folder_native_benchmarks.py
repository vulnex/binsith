"""Adapter regression checks: retain semantic differences and verify fingerprints."""
import copy
import argparse
import errno
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest
from benchmark_native_folder import (
    ANALYSIS_KEYS, BATCH_PATTERN_FORMAT, LEGACY_PATTERN_FORMAT,
    assert_equivalent, normalize_analysis, pattern_hashes, existing_directory, materialize_input,
    has_published_report,
)


class NativeAdapterTests(unittest.TestCase):
    def test_first_report_requires_publication_not_pending_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertFalse(has_published_report(root))
            shard = root / 'results' / 'ab'
            shard.mkdir(parents=True)
            pending = shard / '.pending-fixture.json'
            pending.write_text('{"incomplete":')
            self.assertFalse(has_published_report(root))
            # A directory ending in .json is not a report either.
            (shard / 'directory.json').mkdir()
            self.assertFalse(has_published_report(root))
            pending.write_text('{}')
            pending.rename(shard / ('ab' + '0' * 62 + '.json'))
            self.assertTrue(has_published_report(root))

    @unittest.skipIf(os.name == 'nt', 'executable fixture uses a POSIX shebang')
    def test_timed_baseline_places_scanner_scratch_on_selected_volume(self):
        import hashlib
        import json
        from benchmark_folder import measure
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / 'scanner'
            binary.write_text("""#!/usr/bin/env python3
import hashlib, json, pathlib, sys, tempfile
source = pathlib.Path(sys.argv[1])
body = {'file_summary': {'size_bytes': source.stat().st_size,
        'sha256': hashlib.sha256(source.read_bytes()).hexdigest()},
        'scratch_directory': tempfile.gettempdir()}
pathlib.Path(sys.argv[-1]).write_text(json.dumps(body))
""")
            binary.chmod(0o700)
            source = root / 'sample'
            source.write_bytes(b'synthetic')
            sample = dict(path=source, size=9, sha256=hashlib.sha256(b'synthetic').hexdigest())
            destination = root / 'reports'
            measure(str(binary), [sample], destination, 1, 10, ['-i'])
            body = json.loads((destination / '00000000.json').read_text())
            self.assertEqual(Path(body['scratch_directory']).resolve(), root / 'scratch')

    def test_volume_inputs_preserve_bytes_without_hardlink_support(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source'
            source.write_bytes(bytes(range(256)))
            self.assertEqual(existing_directory(root), root)
            with self.assertRaises(argparse.ArgumentTypeError):
                existing_directory(source)
            with self.assertRaises(argparse.ArgumentTypeError):
                existing_directory(root / 'missing')
            with patch('benchmark_native_folder.os.link', side_effect=OSError(errno.ENOTSUP, 'unsupported')):
                self.assertEqual(materialize_input(source, root / 'copy'), 'copy')
            self.assertEqual((root / 'copy').read_bytes(), source.read_bytes())
            with patch('benchmark_native_folder.os.link', side_effect=OSError(errno.ENOSPC, 'full')):
                with self.assertRaises(OSError):
                    materialize_input(source, root / 'full')
            self.assertFalse((root / 'full').exists())

    def test_private_fixture_copy_removes_only_new_valid_appledouble(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'input'
            source.write_bytes(b'corpus bytes')
            companion = root / '._input'

            def copy_with_companion(src, dst):
                Path(dst).write_bytes(Path(src).read_bytes())
                companion.write_bytes(bytes.fromhex('0005160700020000') + b'metadata')

            with patch('benchmark_native_folder.platform.system', return_value='Darwin'), \
                 patch('benchmark_native_folder.os.link', side_effect=OSError(errno.ENOTSUP, 'unsupported')), \
                 patch('benchmark_native_folder.shutil.copyfile', side_effect=copy_with_companion):
                self.assertEqual(materialize_input(source, destination), 'copy')
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertFalse(companion.exists())

            destination.unlink()
            companion.write_bytes(b'preexisting')
            with self.assertRaises(FileExistsError):
                materialize_input(source, destination)
            self.assertEqual(companion.read_bytes(), b'preexisting')
            self.assertFalse(destination.exists())

    def test_both_fingerprint_formats_are_verified_before_normalization(self):
        legacy, native = pattern_hashes(True)
        self.assertEqual(legacy, '63f03ec8427708e3cbcf03a4d4d63b1ecd6b4058c4a45fd8475386e5478c3699')
        self.assertEqual(native, '89bb2d31a928db22b3a83739954a03741a633caec42762dc01daf20f1c9bf35e')
        settings = dict.fromkeys(ANALYSIS_KEYS, False)
        settings.update(strings=True, encoding=None, categories=[])
        report = {'file_summary': {'file_path': '/tmp/sample'}, 'metadata': {
            'configuration': dict(settings, output='/tmp/report', quiet=True),
            'effective_encoding': 'Auto', 'patterns_sha256': legacy,
            'patterns_hash_format': LEGACY_PATTERN_FORMAT}}
        folder = copy.deepcopy(report)
        folder['metadata'].update(patterns_sha256=native, patterns_hash_format=BATCH_PATTERN_FORMAT)
        self.assertEqual(normalize_analysis(copy.deepcopy(report), 'sample'), normalize_analysis(folder, 'sample'))
        for field, value in [('patterns_sha256', '0' * 64), ('patterns_hash_format', 'incorrect description')]:
            bad = copy.deepcopy(report)
            bad['metadata'][field] = value
            with self.assertRaises(AssertionError):
                normalize_analysis(bad, 'sample')

    def test_semantic_report_changes_and_entropy_drift_are_rejected(self):
        signature = ({'sample': 'digest'}, {'sample': 1.0})
        assert_equivalent(signature, ({'sample': 'digest'}, {'sample': 1.0 + 1e-13}))
        for changed in [({'sample': 'changed'}, {'sample': 1.0}),
                        ({'sample': 'digest'}, {'sample': 1.001})]:
            with self.assertRaises(AssertionError):
                assert_equivalent(signature, changed)


if __name__ == '__main__':
    unittest.main()
