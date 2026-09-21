#!/usr/bin/env python3
"""Compare --version startup RSS and linked libraries; no scanner acceptance claim."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess

from quality_checks import timed_process


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binaries = [p.resolve(strict=True) for p in (args.before, args.after)]
    result = dict(platform=platform.platform(), command=['--version'], warmups=1,
                  timed_runs=5, runs=[], method=__doc__,
                  harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  helper_sha256=hashlib.sha256(Path(__file__).with_name('quality_checks.py').read_bytes()).hexdigest())
    for binary in binaries:
        result['runs'].append(dict(path=str(binary),
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            build=subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip(),
            linked_libraries=subprocess.check_output(['otool', '-L', str(binary)], text=True, timeout=10).splitlines()[1:]
                if platform.system() == 'Darwin' else None,
            samples=[]))
    with args.output.open('x') as output:
        for iteration in range(6):
            for index in ([0, 1] if iteration % 2 == 0 else [1, 0]):
                elapsed, peak = timed_process([str(binaries[index]), '--version'], 10)
                assert peak is not None and peak > 0, 'requires per-child kernel RSS'
                if iteration:
                    result['runs'][index]['samples'].append(dict(elapsed_seconds=elapsed, peak_rss_bytes=peak))
        result['run_state'] = 'complete'
        json.dump(result, output, indent=2)
        output.write('\n')
    for run in result['runs']:
        print(run['path'], 'peak RSS bytes:', max(s['peak_rss_bytes'] for s in run['samples']))


if __name__ == '__main__':
    main()
