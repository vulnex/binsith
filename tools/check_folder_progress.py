#!/usr/bin/env python3
"""Exercise native Unix PTY detection and closed stderr pipes; no third-party packages.

Run against debug/release binaries. Windows console behavior needs native validation.
Each child has a 15-second deadline and is killed/joined on failure.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time


def invoke(binary, root, output, flags, terminal=False, broken=False):
    master = slave = None
    if terminal:
        master, slave = pty.openpty()
    elif broken:
        reader, slave = os.pipe()
        os.close(reader)  # No reader exists even before the child's first write.
    child = None
    try:
        child = subprocess.Popen([str(binary), str(root), '--output-dir', str(output),
                                  '--jobs', '1', *flags], stdout=subprocess.PIPE,
                                 stderr=slave if slave is not None else subprocess.PIPE)
        if slave is not None:
            os.close(slave)
            slave = None
        captured = bytearray()
        if terminal:
            deadline = time.monotonic() + 15
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('PTY child deadline exceeded')
                ready, _, _ = select.select([master], [], [], .05)
                if ready:
                    try:
                        block = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not block:
                        break
                    captured.extend(block)
            stdout, _ = child.communicate(timeout=max(.1, deadline - time.monotonic()))
            stderr = bytes(captured).replace(b'\r\n', b'\n')
        else:
            stdout, stderr = child.communicate(timeout=15)
        assert stdout == b'', stdout
        assert child.returncode in (0, 1), child.returncode
        return child.returncode, (stderr or b'').decode()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate()
        for descriptor in (master, slave):
            if descriptor is not None:
                os.close(descriptor)


def check_artifacts(output, failed=False):
    manifest = json.loads((output / 'manifest.json').read_text())
    assert manifest['status'] == 'complete'
    assert manifest['counters']['failed' if failed else 'complete'] == 1
    assert not (output / '.binsith.lock').exists()
    records = [json.loads(line) for line in (output / 'files.jsonl').read_text().splitlines()]
    assert [r['record_type'] for r in records] == ['admission', 'terminal']
    assert records[0]['entry_id'] == records[1]['entry_id']
    assert not list(output.rglob('.pending-*'))
    if not failed:
        location = records[1]['outcome']['report']['location']
        assert json.loads((output / location).read_text())['processing_complete']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/binsith'))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='binsith-progress-') as temporary:
        base = Path(temporary).resolve()
        root = base / 'input'
        root.mkdir()
        (root / 'sample').write_bytes(b'hello')
        cases = 0
        for terminal in (False, True):
            for quiet in (False, True):
                for explicit in (False, True):
                    output = base / f'case-{cases}'
                    flags = (['-q'] if quiet else []) + (['--progress'] if explicit else [])
                    code, stderr = invoke(binary, root, output, flags, terminal=terminal)
                    assert code == 0
                    show_progress = explicit or (terminal and not quiet)
                    assert ('Discovering:' in stderr) == show_progress
                    assert ('Finished: 1/1 processed' in stderr) == show_progress
                    assert ('Batch finished:' in stderr) == (not quiet)
                    assert '\x1b' not in stderr and '\r' not in stderr
                    if not quiet:
                        assert 'indicators not analyzed' in stderr
                        for label in ('Manifest:', 'Files:', 'Errors:', 'Reports:'):
                            assert label in stderr
                    check_artifacts(output)
                    cases += 1
        for quiet in (False, True):
            for failed in (False, True):
                output = base / f'case-{cases}'
                flags = ['--progress'] + (['-q'] if quiet else [])
                if failed:
                    flags += ['--offset', '999']
                code, _ = invoke(binary, root, output, flags, broken=True)
                assert code == int(failed)
                check_artifacts(output, failed)
                cases += 1
        print(f'{cases} native stream scenarios passed (8 redirected/PTY combinations, 4 closed-pipe cases)')


if __name__ == '__main__':
    main()
