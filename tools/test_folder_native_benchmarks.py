"""Adapter regression checks: retain semantic differences and verify fingerprints."""
import copy
import unittest
from benchmark_native_folder import (
    ANALYSIS_KEYS, BATCH_PATTERN_FORMAT, LEGACY_PATTERN_FORMAT,
    assert_equivalent, normalize_analysis, pattern_hashes,
)


class NativeAdapterTests(unittest.TestCase):
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
