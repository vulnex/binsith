"""Verify that the optional macOS benchmark injector is scoped and effective."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == 'Darwin' and shutil.which('clang'), 'macOS clang required')
class StorageLatency(unittest.TestCase):
    def test_write_variants_path_boundary_and_executable_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            library = root / 'delay.dylib'
            source = Path(__file__).with_name('slow_output.c')
            subprocess.run(['clang', '-dynamiclib', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(library)], check=True)
            probe = root / 'probe.c'
            probe.write_text('''#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    int fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0600);
    struct iovec parts[] = {{"d", 1}, {"e", 1}};
    if (fd < 0 || write(fd, "ab", 2) != 2 || pwrite(fd, "c", 1, 0) != 1
        || writev(fd, parts, 2) != 2 || close(fd)) return 2;
    fd = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "outside", 7) != 7 || close(fd)) return 3;
    int pipefd[2];
    if (pipe(pipefd) || write(pipefd[1], "pipe", 4) != 4) return 4;
    close(pipefd[0]); close(pipefd[1]);
    return 0;
}
''')
            binary = root / 'probe'
            subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', str(probe), '-o', str(binary)], check=True)
            reports, sibling, audit = [root / name for name in ('reports', 'reports-other', 'audit')]
            for folder in (reports, sibling, audit):
                folder.mkdir()
            environment = dict(os.environ, DYLD_INSERT_LIBRARIES=str(library),
                BINSITH_BENCH_TARGET=str(binary), BINSITH_BENCH_OUTPUT_ROOT=str(reports),
                BINSITH_BENCH_WRITE_AUDIT=str(audit), BINSITH_BENCH_WRITE_DELAY_US='1000')
            command = [str(binary), str(reports / 'result'), str(sibling / 'result')]
            subprocess.run(command, env=environment, check=True)
            records = list(audit.glob('*.json'))
            self.assertEqual(len(records), 1)
            self.assertEqual(json.loads(records[0].read_text()),
                             dict(calls=3, requested_bytes=5, delay_us=1000))
            self.assertEqual((reports / 'result').read_bytes(), b'cbde')
            self.assertEqual((sibling / 'result').read_bytes(), b'outside')
            environment['BINSITH_BENCH_TARGET'] = str(root / 'different-executable')
            subprocess.run(command, env=environment, check=True)
            self.assertEqual(list(audit.glob('*.json')), records)


if __name__ == '__main__':
    unittest.main()
