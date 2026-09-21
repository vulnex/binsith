#!/usr/bin/env python3
"""Probe actual volume behavior and native folder identities; report unsupported fixtures.

Uses only owned temporary paths. chmod denial is Unix-only and always restored.
This complements controlled mutation/reparse/output tests in cargo test.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile


def identity(name):
    if os.name == 'nt':
        return 'windows-utf16le-base64', base64.b64encode(name.encode('utf-16le', 'surrogatepass')).decode()
    return 'unix-bytes-base64', base64.b64encode(os.fsencode(name)).decode()


def scan(binary, root, output, expected, code=0):
    result = subprocess.run([str(binary), str(root), '--recursive', '--jobs', '2',
                             '--output-dir', str(output), '-q'], capture_output=True, timeout=30)
    assert result.returncode == code, (result.returncode, result.stderr)
    assert result.stdout == b''
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['status'] == 'complete' and manifest['discovery_complete']
    admitted, terminal, locations = {}, set(), set()
    for sequence, line in enumerate((output / 'files.jsonl').read_text(encoding='utf-8').splitlines(), 1):
        record = json.loads(line)
        assert record['sequence'] == sequence and record['batch_id'] == manifest['batch_id']
        key = (record['path']['encoding'], record['path']['value'])
        if record['record_type'] == 'admission':
            assert record['entry_id'] not in admitted
            admitted[record['entry_id']] = key
        elif record['record_type'] == 'terminal':
            if record['outcome']['status'] == 'skipped':
                assert record['entry_id'] not in admitted
                continue
            assert admitted[record['entry_id']] == key and record['entry_id'] not in terminal
            terminal.add(record['entry_id'])
            if record['outcome']['status'] == 'complete':
                report = record['outcome']['report']
                assert key in expected
                assert report['location'] not in locations
                locations.add(report['location'])
                body = json.loads((output / report['location']).read_text(encoding='utf-8'))
                assert body['file_summary']['sha256'] == hashlib.sha256(expected[key]).hexdigest()
                assert body['processing_complete']
    assert terminal == set(admitted)
    assert len(locations) == len(expected)
    assert manifest['counters']['complete'] == len(expected)
    assert not (output / '.binsith.lock').exists()
    return manifest['counters']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/binsith' + ('.exe' if os.name == 'nt' else '')))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    evidence = {'schema_version': 1, 'platform': platform.platform(),
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'build': subprocess.check_output([str(binary), '--version'], text=True, timeout=30).strip(),
        'cases': [], 'limitations': ['Only the temporary directory volume and current account are tested.',
            'Windows ACL denial, console events and junction-specific behavior need native platform checks.',
            'No network filesystems, mount creation or physical disk exhaustion tested.']}
    with args.output.open('x', encoding='utf-8') as evidence_file:
        with tempfile.TemporaryDirectory(prefix='binsith-fs-') as temporary:
            base = Path(temporary).resolve()
            for label, names in [('case', ['a', 'A']), ('normalization', ['caf\u00e9', 'cafe\u0301']),
                ('native_encoding', ['native\ud800', 'native\ufffd'] if os.name == 'nt' else [os.fsdecode(b'native\xff'), 'native\ufffd']),
                ('hidden', ['.hidden', 'visible']), ('hierarchy', ['a', 'a.json/b'])]:
                root = base / label
                root.mkdir()
                aliases, unsupported = [], []
                for i, name in enumerate(names):
                    path = root / name
                    try:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        with path.open('xb') as stream:
                            stream.write(f'payload-{i}'.encode())
                    except FileExistsError:
                        aliases.append(name)
                    except (OSError, UnicodeError) as error:
                        unsupported.append({'name': name, 'reason': str(error)})
                # Use actual directory entry spelling: volumes may normalize names.
                expected = {identity(str(p.relative_to(root))): p.read_bytes()
                            for p in root.rglob('*') if p.is_file()}
                counters = scan(binary, root, base / (label + '-out'), expected)
                evidence['cases'].append({'name': label, 'status': 'partial' if unsupported else 'passed',
                    'distinct_files': len(expected), 'aliases': aliases, 'unsupported_fixtures': unsupported,
                    'counters': counters})
            root = base / 'hardlinks'
            root.mkdir()
            (root / 'a').write_bytes(b'hardlink')
            try:
                os.link(root / 'a', root / 'b')
            except OSError as error:
                evidence['cases'].append({'name': 'hardlinks', 'status': 'skipped', 'reason': str(error)})
            else:
                scan(binary, root, base / 'hardlinks-out', {identity(n): b'hardlink' for n in ('a', 'b')})
                evidence['cases'].append({'name': 'hardlinks', 'status': 'passed'})
            root = base / 'links'
            root.mkdir()
            target = base / 'outside'
            target.mkdir()
            (target / 'secret').write_bytes(b'must not scan')
            try:
                os.symlink(target, root / 'link', target_is_directory=True)
            except OSError as error:
                evidence['cases'].append({'name': 'directory_symlink', 'status': 'skipped', 'reason': str(error)})
            else:
                counters = scan(binary, root, base / 'links-out', {})
                assert counters['policy_skipped'] == 1
                evidence['cases'].append({'name': 'directory_symlink', 'status': 'passed'})
            if os.name == 'posix':
                root = base / 'denial'
                root.mkdir()
                denied = root / 'denied'
                denied.mkdir()
                (denied / 'unseen').write_bytes(b'unseen')
                (root / 'good').write_bytes(b'good')
                denied.chmod(0)
                try:
                    try:
                        os.listdir(denied)
                    except PermissionError:
                        counters = scan(binary, root, base / 'denial-out', {identity('good'): b'good'}, code=1)
                        assert counters['discovery_errors'] == 1 and counters['eligible'] == 1
                        evidence['cases'].append({'name': 'unreadable_subtree', 'status': 'passed', 'counters': counters})
                    else:
                        evidence['cases'].append({'name': 'unreadable_subtree', 'status': 'skipped',
                                                  'reason': 'account can read chmod(0) directory'})
                finally:
                    denied.chmod(0o700)
            else:
                evidence['cases'].append({'name': 'unreadable_subtree', 'status': 'skipped', 'reason': 'Windows ACL fixture required'})
        json.dump(evidence, evidence_file, indent=2, ensure_ascii=True)
        evidence_file.write('\n')
    for case in evidence['cases']:
        print(case['name'], case['status'])


if __name__ == '__main__':
    main()
