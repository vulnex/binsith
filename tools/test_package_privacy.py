"""Regression checks for release identity leaks in archives and executables."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from check_package_privacy import check_archive, check_content


class PackagePrivacyTests(unittest.TestCase):
    def test_native_paths_in_binary_encodings_are_rejected(self):
        paths = ['/Users/tester/.cargo/src/lib.rs', '/home/tester/src/main.rs',
                 r'C:\Users\tester\.cargo\src\lib.rs',
                 'C:/Users/tester/project/main.rs', '/private/tmp/build/main.rs',
                 '/var/folders/xx/build/main.rs', '/root/.cargo/src/lib.rs']
        for path in paths:
            for encoding in ('utf-8', 'utf-16le', 'utf-16be'):
                for prefix in (b'', b'\xff'):
                    with self.subTest(path=path, encoding=encoding, prefix=prefix):
                        with self.assertRaisesRegex(ValueError, 'value redacted'):
                            check_content('binary', prefix + path.encode(encoding) + b'\0')

    def test_public_attribution_and_remapped_paths_are_allowed(self):
        check_content('documentation', b'Copyright VULNEX - Simon Roses Femerling\n'
                      b'https://example.org\n/src/binsith/main.rs\n/build/cargo/lib.rs')

    def test_tar_owner_and_embedded_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.tar.gz'
            for owner, content, valid in [('', b'/src/binsith/main.rs', True),
                                           ('tester', b'clean', False),
                                           ('', b'/Users/tester/main.rs', False)]:
                with tarfile.open(path, 'w:gz') as archive:
                    member = tarfile.TarInfo('candidate/binsith')
                    member.uname = owner
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                if valid:
                    check_archive(path)
                else:
                    with self.assertRaises(ValueError):
                        check_archive(path)

    def test_zip_paths_and_comments_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.zip'
            for content, comment, valid in [(b'clean', b'', True),
                                             (b'C:\\Users\\tester\\main.rs', b'', False),
                                             (b'clean', b'tester', False)]:
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('candidate/binsith.exe', content)
                    archive.comment = comment
                if valid:
                    check_archive(path)
                else:
                    with self.assertRaises(ValueError):
                        check_archive(path)


if __name__ == '__main__':
    unittest.main()
