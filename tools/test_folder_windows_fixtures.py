"""Native Windows regression for sparse console fixtures without disk allocation."""
import os
from pathlib import Path
import tempfile
import unittest


@unittest.skipUnless(os.name == 'nt', 'native Windows allocation evidence required')
class SparseFixtures(unittest.TestCase):
    def test_extension_remains_unallocated_and_reads_as_zeros(self):
        from check_folder_windows import kernel, sparse_fixture
        with tempfile.TemporaryDirectory(prefix='binsith-sparse-test-') as temporary:
            path = Path(temporary) / 'fixture'
            size = 16 * 1024**2
            result = sparse_fixture(kernel(), path, size)
            if result.get('status') == 'skipped':
                self.skipTest(result['reason'])
            self.assertEqual(result, {'logical_bytes': size, 'allocated_bytes': 0})
            with path.open('rb') as stream:
                self.assertEqual(stream.read(64), bytes(64))
                stream.seek(size - 64)
                self.assertEqual(stream.read(64), bytes(64))
                self.assertEqual(stream.read(1), b'')
            with self.assertRaises(FileExistsError):
                sparse_fixture(kernel(), path, size)
            self.assertEqual(path.stat().st_size, size)


if __name__ == '__main__':
    unittest.main()
