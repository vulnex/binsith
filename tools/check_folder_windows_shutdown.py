#!/usr/bin/env python3
"""Native Windows console events while test-only report-write gates are blocked.

Uses the production InterruptHandler inside the Rust library test executable.
No fault hooks are compiled into the shipped CLI. Events target only the child
process group; never broadcast to group zero or send input to the user's desktop.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

from check_folder_windows import kernel


CHILD_TEST = 'batch::execution::shutdown_tests::stress_child'


def build_test_binary(profile):
    arguments = ['cargo', '+stable', 'test', '--locked', '--lib', '--no-run',
                 '--message-format=json']
    if profile == 'release':
        arguments.append('--release')
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError(f'test build failed: {result.stderr}\n{result.stdout}')
    executables = []
    for line in result.stdout.splitlines():
        item = json.loads(line)
        if (item.get('reason') == 'compiler-artifact' and item.get('executable')
                and item.get('profile', {}).get('test')
                and item.get('target', {}).get('kind') == ['lib']):
            executables.append(Path(item['executable']).resolve(strict=True))
    if len(executables) != 1:
        raise RuntimeError(f'expected one library test executable, found {executables}')
    return executables[0]


def wait_marker(child, marker):
    deadline = time.monotonic() + 20
    while not marker.exists():
        if child.poll() is not None:
            raise AssertionError(f'child exited {child.returncode} before {marker.name}')
        if time.monotonic() >= deadline:
            raise AssertionError(f'timed out waiting for {marker.name}')
        time.sleep(.01)
    assert child.poll() is None, f'child exited before event at {marker.name}'


def scenario(binary, base, name):
    result = {'scenario': name, 'events_sent': 0}
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child = subprocess.Popen([str(binary), '--exact', CHILD_TEST, '--nocapture'],
            env=dict(os.environ, BINSITH_SHUTDOWN_TEST_CHILD=str(base),
                     BINSITH_SHUTDOWN_TEST_SCENARIO=name),
            stdout=stdout, stderr=stderr,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            # The marker is written only after four workers reach ReportWrite
            # and the manifest records four active plus eight queued entries.
            wait_marker(child, base / 'ready')
            child.send_signal(signal.CTRL_BREAK_EVENT)
            result['events_sent'] += 1
            if name == 'signal_second':
                wait_marker(child, base / 'first_interrupt')
                result['first_event_acknowledged_while_blocked'] = True
                child.send_signal(signal.CTRL_BREAK_EVENT)
                result['events_sent'] += 1
            assert child.wait(timeout=15) == 130, f'exit code: {child.returncode}'
            root = base / 'output'
            manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
            assert manifest['status'] == 'incomplete'
            assert 'interrupted' in manifest['stop_reasons']
            forced = name == 'signal_second'
            assert (root / '.binsith.lock').exists() == forced
            records = [json.loads(line) for line in
                       (root / 'files.jsonl').read_text(encoding='utf-8').splitlines()]
            assert [r['sequence'] for r in records] == list(range(1, len(records) + 1))
            admissions = {r['entry_id'] for r in records if r['record_type'] == 'admission'}
            terminals = [r for r in records if r['record_type'] == 'terminal']
            terminal_ids = [r['entry_id'] for r in terminals]
            assert len(terminal_ids) == len(set(terminal_ids))
            assert set(terminal_ids) <= admissions
            assert len(admissions) == 12
            assert all(r['outcome']['status'] == 'cancelled' for r in terminals)
            if name == 'signal_first':
                assert set(terminal_ids) == admissions
                assert manifest['counters']['cancelled'] == 12
            if forced:
                assert admissions - set(terminal_ids), 'blocked workers must remain unresolved'
            result.update(status='passed', exit_code=child.returncode,
                          counters=manifest['counters'], journal_records=len(records),
                          unresolved_entries=len(admissions - set(terminal_ids)),
                          stale_claim_preserved=forced)
        except Exception as error:
            result.update(status='failed', reason=str(error))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=15)
            stdout.seek(0)
            stderr.seek(0)
            result['stdout'] = stdout.read().decode('utf-8', errors='replace')
            result['stderr'] = stderr.read().decode('utf-8', errors='replace')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['debug', 'release'], required=True)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('requires native Windows execution')
    if not 1 <= args.repeat <= 10:
        parser.error('--repeat must be between 1 and 10')
    evidence = {'schema_version': 1, 'platform': platform.platform(),
        'profile': args.profile, 'cases': [],
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'limitations': ['Targeted CTRL_BREAK events, not physical Ctrl+C keypresses.',
            'Report writes are blocked at deterministic test-only gates, not stalled kernel I/O.',
            'No physical storage, power-loss, or final release qualification.']}
    api = kernel()
    allocated = False
    with args.output.open('x', encoding='utf-8') as destination:
        try:
            binary = build_test_binary(args.profile)
            evidence['test_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            if not api.GetConsoleCP():
                if not api.AllocConsole():
                    raise RuntimeError(f'console unavailable: {ctypes.get_last_error()}')
                allocated = True
            with tempfile.TemporaryDirectory(prefix='binsith-windows-shutdown-') as temporary:
                for repeat in range(1, args.repeat + 1):
                    for name in ('signal_first', 'signal_second', 'signal_journal'):
                        base = Path(temporary).resolve() / f'{name}-{repeat}'
                        base.mkdir()
                        result = scenario(binary, base, name)
                        result['repeat'] = repeat
                        evidence['cases'].append(result)
                        print(name, repeat, result['status'], flush=True)
                        if result['status'] != 'passed':
                            raise RuntimeError(result['reason'])
        except Exception as error:
            evidence['error'] = str(error)
            raise
        finally:
            if allocated:
                api.FreeConsole()
            json.dump(evidence, destination, indent=2, ensure_ascii=True)
            destination.write('\n')


if __name__ == '__main__':
    main()
