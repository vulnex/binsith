#!/usr/bin/env python3
"""Windows-only junction, ACL, long-path and targeted console-event probes.

All paths and child process groups are owned by this run. Evidence records skips;
unsupported fixture setup is never counted as a passed Windows behavior.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import tempfile
import time

from check_folder_filesystems import identity, scan


def command(arguments, **kwargs):
    return subprocess.run(arguments, capture_output=True, timeout=30, check=True, **kwargs)


def junction(binary, base):
    root, outside, output = base / 'junction-input', base / 'outside', base / 'junction-output'
    root.mkdir()
    outside.mkdir()
    (outside / 'secret').write_bytes(b'must not be scanned')
    link = root / 'junction'
    # Environment arguments keep user/temporary path text out of PowerShell code.
    command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
        "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:BINSITH_TEST_LINK -Target $env:BINSITH_TEST_TARGET | Out-Null"],
        env=dict(os.environ, BINSITH_TEST_LINK=str(link), BINSITH_TEST_TARGET=str(outside)))
    try:
        counters = scan(binary, root, output, {})
        assert counters['policy_skipped'] == 1
        result = subprocess.run([str(binary), str(link), '--output-dir', str(base / 'rejected-root'), '-q'],
                                capture_output=True, timeout=30)
        assert result.returncode == 2 and not (base / 'rejected-root').exists()
        assert (outside / 'secret').read_bytes() == b'must not be scanned'
        return {'status': 'passed', 'counters': counters}
    finally:
        # Remove just the reparse point, never recursively follow it into its target.
        link.rmdir()


def acl_denial(binary, base, directory):
    label = 'subtree' if directory else 'file'
    root, output = base / ('acl-' + label), base / ('acl-' + label + '-out')
    root.mkdir()
    denied = root / 'denied'
    if directory:
        denied.mkdir()
        (denied / 'unseen').write_bytes(b'unseen')
    else:
        denied.write_bytes(b'denied')
    (root / 'good').write_bytes(b'good')
    # Deny only read-data/list-directory on a new owned object. Preserve attributes
    # access and ACL editing, so cleanup can restore this exact test-only deny ACE.
    principal = '*S-1-1-0'
    try:
        command(['icacls.exe', str(denied), '/deny', principal + ':(RD)'])
        try:
            if directory:
                list(denied.iterdir())
            else:
                denied.read_bytes()
        except PermissionError:
            pass
        else:
            raise AssertionError('deny ACE did not prevent fixture access')
        counters = scan(binary, root, output, {identity('good'): b'good'}, code=1)
        assert counters['discovery_errors'] == int(directory)
        assert counters['failed'] == int(not directory)
        assert counters['eligible'] == (1 if directory else 2)
        return {'status': 'passed', 'counters': counters}
    finally:
        command(['icacls.exe', str(denied), '/remove:d', principal])


def long_paths(binary, base):
    root = base / 'long-input'
    root.mkdir()
    # Use extended paths only for fixture creation/cleanup. The scanner receives
    # the ordinary short root and must discover/open the long descendant itself.
    absolute = str(root.resolve())
    extended = Path('\\\\?\\UNC\\' + absolute[2:] if absolute.startswith('\\\\')
                    else '\\\\?\\' + absolute)
    parent = root
    while len(str(parent)) < 320:
        parent /= 'long-component'
    try:
        try:
            fixture_parent = extended / parent.relative_to(root)
            fixture_parent.mkdir(parents=True)
            (fixture_parent / 'sample').write_bytes(b'long')
        except OSError as error:
            return {'status': 'skipped', 'reason': 'volume/process long-path fixture unavailable: ' + str(error)}
        relative = str((parent / 'sample').relative_to(root))
        counters = scan(binary, root, base / 'long-output', {identity(relative): b'long'})
        return {'status': 'passed', 'path_characters': len(str(parent / 'sample')),
                'fixture_path_mode': 'extended', 'scanner_root_mode': 'ordinary', 'counters': counters}
    finally:
        # The ordinary Python path may itself hit MAX_PATH during recursive cleanup.
        shutil.rmtree(extended)


class FileStandardInfo(ctypes.Structure):
    _fields_ = [('allocation_size', ctypes.c_longlong), ('end_of_file', ctypes.c_longlong),
                ('links', wintypes.DWORD), ('delete_pending', ctypes.c_ubyte),
                ('directory', ctypes.c_ubyte)]


def kernel():
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.GetConsoleCP.argtypes = []
    api.GetConsoleCP.restype = wintypes.UINT
    for name in ('AllocConsole', 'FreeConsole'):
        getattr(api, name).argtypes = []
        getattr(api, name).restype = wintypes.BOOL
    api.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    api.DeviceIoControl.restype = wintypes.BOOL
    api.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                    ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    api.SetFilePointerEx.restype = wintypes.BOOL
    api.SetEndOfFile.argtypes = [wintypes.HANDLE]
    api.SetEndOfFile.restype = wintypes.BOOL
    api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                wintypes.LPVOID, wintypes.DWORD]
    api.GetFileInformationByHandleEx.restype = wintypes.BOOL
    return api


def sparse_fixture(api, path, length):
    import msvcrt
    with path.open('xb') as stream:
        handle = msvcrt.get_osfhandle(stream.fileno())
        returned = wintypes.DWORD()
        # FSCTL_SET_SPARSE from winioctl.h.
        if not api.DeviceIoControl(handle, 590020, None, 0, None, 0,
                                   ctypes.byref(returned), None):
            return {'status': 'skipped',
                    'reason': f'sparse fixture unavailable: {ctypes.get_last_error()}'}
        # Python/CRT truncate may write zeros while extending a file, defeating
        # sparse allocation. Move the native pointer and set EOF without writes.
        if not api.SetFilePointerEx(handle, length, None, 0) or not api.SetEndOfFile(handle):
            raise ctypes.WinError(ctypes.get_last_error())
        info = FileStandardInfo()
        # FileStandardInfo = 1. Verify allocation before starting the scanner.
        if not api.GetFileInformationByHandleEx(handle, 1, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.end_of_file != length or info.allocation_size != 0:
            raise AssertionError(f'fixture is not an unallocated sparse file: '
                                 f'length={info.end_of_file}, allocation={info.allocation_size}')
        return {'logical_bytes': info.end_of_file, 'allocated_bytes': info.allocation_size}


def console_interrupt(binary, base):
    api = kernel()
    allocated = False
    child = None
    if not api.GetConsoleCP():
        if not api.AllocConsole():
            return {'status': 'skipped', 'reason': f'no available console: {ctypes.get_last_error()}'}
        allocated = True
    try:
        root, output = base / 'console-input', base / 'console-output'
        root.mkdir()
        fixtures = []
        for index in range(5):
            fixture = sparse_fixture(api, root / str(index), 8 * 1024**3)
            if fixture.get('status') == 'skipped':
                return fixture
            fixtures.append(fixture)
        # New process group shares this console. CTRL_BREAK is scoped to the
        # child's group; never broadcast CTRL_C/CTRL_BREAK to group zero.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            child = subprocess.Popen([str(binary), str(root), '--output-dir', str(output),
                '--jobs', '1', '--progress'], stdout=stdout, stderr=stderr,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            deadline = time.monotonic() + 20
            while True:
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('scanner did not reach active/queued checkpoint')
                try:
                    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
                except FileNotFoundError:
                    pass
                else:
                    if manifest['counters']['active'] == 1 and manifest['counters']['queued'] == 2:
                        break
                time.sleep(.02)
            child.send_signal(signal.CTRL_BREAK_EVENT)
            assert child.wait(timeout=15) == 130
            manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
            assert manifest['status'] == 'incomplete'
            assert 'interrupted' in manifest['stop_reasons']
            assert manifest['counters']['cancelled'] == 3
            assert manifest['counters']['active'] == manifest['counters']['queued'] == 0
            assert not (output / '.binsith.lock').exists()
            stdout.seek(0)
            assert stdout.read() == b''
            stderr.seek(0)
            assert b'Batch incomplete: 3 processed' in stderr.read()
            records = [json.loads(line) for line in (output / 'files.jsonl').read_text(encoding='utf-8').splitlines()]
            assert len(records) == 6
            assert [r['sequence'] for r in records] == list(range(1, 7))
            admissions = {r['entry_id'] for r in records if r['record_type'] == 'admission'}
            terminals = [r for r in records if r['record_type'] == 'terminal']
            assert {r['entry_id'] for r in terminals} == admissions
            assert all(r['outcome']['status'] == 'cancelled' for r in terminals)
            return {'status': 'passed', 'event': 'targeted CTRL_BREAK_EVENT',
                    'counters': manifest['counters'], 'fixtures': fixtures}
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=15)
        if allocated:
            api.FreeConsole()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/binsith.exe'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('requires native Windows; a compile or mock check is not execution evidence')
    binary = args.binary.resolve(strict=True)
    evidence = {'schema_version': 1, 'platform': platform.platform(),
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'cases': {}, 'limitations': ['Targeted CTRL_BREAK tests the shared interrupt handler, not a physical Ctrl+C keypress.',
            'Repeated console events and forced exit during blocked Windows I/O remain separate tests.']}
    with args.output.open('x', encoding='utf-8') as destination:
        try:
            with tempfile.TemporaryDirectory(prefix='binsith-windows-') as temporary:
                base = Path(temporary).resolve()
                for name, operation in [('junction', lambda: junction(binary, base)),
                    ('acl_subtree', lambda: acl_denial(binary, base, True)),
                    ('acl_file', lambda: acl_denial(binary, base, False)),
                    ('long_path', lambda: long_paths(binary, base)),
                    ('console_interrupt', lambda: console_interrupt(binary, base))]:
                    try:
                        evidence['cases'][name] = operation()
                    except Exception as error:
                        evidence['cases'][name] = {'status': 'failed', 'reason': str(error)}
                        raise
                    print(name, evidence['cases'][name]['status'], flush=True)
        finally:
            json.dump(evidence, destination, indent=2, ensure_ascii=True)
            destination.write('\n')


if __name__ == '__main__':
    main()
