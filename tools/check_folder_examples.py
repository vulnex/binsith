#!/usr/bin/env python3
"""Execute the README's POSIX folder examples in an owned temporary directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/binsith'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix':
        parser.error('these are the README macOS/Linux shell examples')
    binary = args.binary.resolve(strict=True)
    readme = Path(__file__).resolve().parents[1] / 'README.md'
    source = readme.read_text()
    cases = []
    blocks = {}
    for name in ('setup', 'summary', 'recursive', 'limited', 'inspect'):
        matches = re.findall(r'<!-- folder-example: ' + name + r' -->\s*```sh\n(.*?)\n```', source, re.S)
        assert len(matches) == 1, f'missing or duplicate README example: {name}'
        blocks[name] = matches[0]
    with args.output.open('x') as evidence, tempfile.TemporaryDirectory(prefix='binsith-examples-') as temporary:
        root = Path(temporary).resolve()
        for name, expected in [('setup', 0), ('summary', 0), ('recursive', 0), ('limited', 1), ('inspect', 0)]:
            if name in ('setup', 'inspect'):
                command = ['sh', '-c', blocks[name]]
            else:
                command = shlex.split(blocks[name])
                assert command[0] == 'binsith'
                command[0] = str(binary)
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            assert result.returncode == expected, (name, result.returncode, result.stderr)
            if name in ('summary', 'recursive', 'limited'):
                assert result.stdout == '', 'folder stdout must remain empty'
            if name == 'inspect':
                lines = result.stdout.splitlines()
                assert lines[0] == 'complete 3' and len(lines) == 4
            cases.append(dict(name=name, exit_code=result.returncode, passed=True))
        for name, total in [('summary', 2), ('recursive', 3), ('limited', 3)]:
            output = root / 'folder-demo' / name
            manifest = json.loads((output / 'manifest.json').read_text())
            assert manifest['status'] == 'complete' and manifest['discovery_complete']
            counters = manifest['counters']
            assert counters['eligible'] == total
            assert counters['active'] == counters['queued'] == counters['failed'] == 0
            assert counters['limited'] == (2 if name == 'limited' else 0)
            assert counters['complete'] == (1 if name == 'limited' else total)
            assert counters['files_with_indicators'] == (None if name == 'summary' else 0 if name == 'limited' else 2)
            records = [json.loads(line) for line in (output / 'files.jsonl').read_text().splitlines()]
            terminals = [r for r in records if r['record_type'] == 'terminal']
            reports = [r for r in terminals if r['outcome']['status'] in ('complete', 'limited')]
            assert len(reports) == total
            assert sum(r['record_type'] == 'admission' for r in records) == total
            assert len(terminals) == total + counters['policy_skipped']
            for record in reports:
                report = json.loads((output / record['outcome']['report']['location']).read_text())
                assert 'file_summary' in report
            assert not (output / '.binsith.lock').exists()
        # The guide requires a fresh destination: a repeat must refuse reuse.
        command = shlex.split(blocks['recursive']); command[0] = str(binary)
        retry = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
        assert retry.returncode == 2 and not retry.stdout
        cases.append(dict(name='refuse_destination_reuse', exit_code=2, passed=True))
        json.dump(dict(run_state='complete', build=subprocess.check_output([str(binary), '--version'], text=True).strip(),
                       binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                       readme_sha256=hashlib.sha256(readme.read_bytes()).hexdigest(),
                       harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=cases), evidence, indent=2)
        evidence.write('\n')
    print(f'{len(cases)}/{len(cases)} README example checks passed')


if __name__ == '__main__':
    main()
