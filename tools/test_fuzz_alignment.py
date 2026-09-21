"""Reject configuration drift that would make fuzzing test different dependencies."""
from pathlib import Path
import tempfile
import unittest
from check_fuzz_alignment import check


class FuzzAlignmentTests(unittest.TestCase):
    def test_feature_and_lock_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'fuzz').mkdir()
            manifest = '[dependencies]\nregex = { version = "1", default-features = false, features = ["std", "unicode"] }\n'
            lock = '[[package]]\nname = "regex"\nversion = "1.13.1"\nsource = "registry+example"\nchecksum = "same"\n'
            for directory in (root, root / 'fuzz'):
                (directory / 'Cargo.toml').write_text(manifest)
                (directory / 'Cargo.lock').write_text(lock)
            self.assertEqual(check(root), ['regex'])
            (root / 'fuzz/Cargo.toml').write_text(manifest.replace('["std", "unicode"]', '["unicode", "std"]'))
            self.assertEqual(check(root), ['regex'])
            (root / 'fuzz/Cargo.toml').write_text(manifest.replace('false', 'true'))
            with self.assertRaisesRegex(ValueError, 'features differ'):
                check(root)
            (root / 'fuzz/Cargo.toml').write_text(manifest)
            for changed in (lock.replace('1.13.1', '1.11.1'), lock.replace('"same"', '"different"')):
                (root / 'fuzz/Cargo.lock').write_text(changed)
                with self.assertRaisesRegex(ValueError, 'resolved packages differ'):
                    check(root)


if __name__ == '__main__':
    unittest.main()
