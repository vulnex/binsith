#!/usr/bin/env python3
"""Exercise real Linux FUSE read stalls with the production scanner and SIGINT.

Requires an explicitly supplied tools/stalled_read_fs.c executable and fusermount3.
Uses private synthetic mounts, releases outstanding requests before unmounting,
and never changes an existing filesystem or network service.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time


def wait_for(check, processes, message, timeout=15):
    deadline = time.monotonic() + timeout
    while not check():
        if any(p.poll() is not None for p in processes):
            raise AssertionError(f'process exited while waiting for {message}')
        if time.monotonic() >= deadline:
            raise AssertionError(f'timed out waiting for {message}')
        time.sleep(.01)


def interrupted(output):
    try:
        return 'interrupted' in json.loads((output / 'manifest.json').read_text())['stop_reasons']
    except FileNotFoundError:
        return False


def scenario(binary, filesystem, root, forced):
    control = root / 'control'
    mount = root / 'mount'
    output = root / 'output'
    control.mkdir(); mount.mkdir()
    scanner = None
    with (root / 'fuse.log').open('wb') as fuse_log, (root / 'scanner.log').open('wb') as scanner_log:
        server = subprocess.Popen([str(filesystem), '-f', '-s', str(mount)],
            env=dict(os.environ, BINSITH_STALL_CONTROL=str(control)), stdout=fuse_log, stderr=fuse_log)
        try:
            wait_for(lambda: mount.is_mount(), [server], 'FUSE mount')
            scanner = subprocess.Popen([str(binary), str(mount), '--recursive', '--jobs', '1',
                '--output-dir', str(output), '-q'], stdout=scanner_log, stderr=scanner_log)
            wait_for(lambda: (control / 'blocked').exists(), [server, scanner], 'actual FUSE read request')
            waits = {}
            for task in Path(f'/proc/{scanner.pid}/task').iterdir():
                try:
                    waits[task.name] = (task / 'wchan').read_text().strip()
                except FileNotFoundError:
                    pass
            assert any('request_wait_answer' in name for name in waits.values()), waits
            start = time.monotonic()
            scanner.send_signal(signal.SIGINT)
            wait_for(lambda: interrupted(output), [server, scanner], 'first interrupt checkpoint')
            acknowledged = time.monotonic() - start
            assert not (control / 'release').exists()
            assert scanner.poll() is None
            forced_exit_blocked = False
            after_second_waits = {}
            if forced:
                start = time.monotonic()
                scanner.send_signal(signal.SIGINT)
                try:
                    assert scanner.wait(timeout=5) == 130
                except subprocess.TimeoutExpired:
                    forced_exit_blocked = True
                    for task in Path(f'/proc/{scanner.pid}/task').iterdir():
                        try:
                            after_second_waits[task.name] = (task / 'wchan').read_text().strip()
                        except FileNotFoundError:
                            pass
                    # Retain failure of immediate termination; release the real
                    # kernel request so the process can finish exit_group.
                    (control / 'release').touch(exist_ok=False)
                    assert scanner.wait(timeout=5) == 130
                exit_latency = time.monotonic() - start
            else:
                (control / 'release').touch(exist_ok=False)
                start = time.monotonic()
                assert scanner.wait(timeout=5) == 130
                exit_latency = time.monotonic() - start
            manifest = json.loads((output / 'manifest.json').read_text())
            assert manifest['status'] == 'incomplete'
            assert 'interrupted' in manifest['stop_reasons']
            assert (output / '.binsith.lock').exists() == forced
            records = [json.loads(line) for line in (output / 'files.jsonl').read_text().splitlines()]
            assert [r['sequence'] for r in records] == list(range(1, len(records) + 1))
            admissions = {r['entry_id'] for r in records if r['record_type'] == 'admission'}
            terminals = [r for r in records if r['record_type'] == 'terminal']
            assert len({r['entry_id'] for r in terminals}) == len(terminals)
            assert {r['entry_id'] for r in terminals} <= admissions
            assert not list((output / 'results').glob('*/[!.]*.json'))
            return dict(forced=forced, forced_exit_blocked=forced_exit_blocked,
                after_second_wait_channels=after_second_waits, exit_code=130, first_ack_seconds=acknowledged,
                exit_after_second_or_release_seconds=exit_latency, kernel_wait_channels=waits,
                counters=manifest['counters'], records=records)
        finally:
            # Never unmount while the server deliberately withholds a read response.
            (control / 'release').touch(exist_ok=True)
            if scanner is not None and scanner.poll() is None:
                scanner.kill(); scanner.wait(timeout=10)
            if mount.is_mount():
                subprocess.run(['fusermount3', '-u', str(mount)], check=True, timeout=10)
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.terminate(); server.wait(timeout=10)
            assert not mount.is_mount()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--filesystem', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=3)
    args = parser.parse_args()
    if platform.system() != 'Linux' or args.repeat < 1:
        parser.error('Linux and positive repeat count required')
    binary = args.binary.resolve(strict=True)
    filesystem = args.filesystem.resolve(strict=True)
    result = dict(platform=platform.platform(), build=subprocess.check_output([str(binary), '--version'], text=True),
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        filesystem_sha256=hashlib.sha256(filesystem.read_bytes()).hexdigest(), cases=[],
        limitations=['Synthetic FUSE read stalls only; no physical hardware failure or Windows kernel-I/O claim.',
                      'Observed event latency is not a universal upper bound.'])
    with args.output.open('x') as evidence:
        try:
            for trial in range(args.repeat):
                for forced in (False, True):
                    with tempfile.TemporaryDirectory(prefix='binsith-stalled-io-') as directory:
                        case = scenario(binary, filesystem, Path(directory), forced)
                        case['trial'] = trial
                        result['cases'].append(case)
            result['status'] = ('forced_exit_blocked' if any(c['forced_exit_blocked'] for c in result['cases']) else 'passed')
        except Exception as error:
            result['status'] = 'failed'
            result['error'] = repr(error)
            raise
        finally:
            json.dump(result, evidence, indent=2)
            evidence.write('\n')
    if result['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
