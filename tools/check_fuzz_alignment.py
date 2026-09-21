#!/usr/bin/env python3
"""Verify direct dependencies shared by the CLI and fuzz workspace stay aligned."""
from pathlib import Path
import tomllib


def dependency(value):
    result = {'version': value} if isinstance(value, str) else dict(value)
    result.setdefault('default-features', True)
    result['features'] = sorted(result.get('features', []))
    return result


def check(root):
    cli = tomllib.loads((root / 'Cargo.toml').read_text())['dependencies']
    fuzz = tomllib.loads((root / 'fuzz/Cargo.toml').read_text())['dependencies']
    locks = [tomllib.loads((root / path).read_text())['package']
             for path in ('Cargo.lock', 'fuzz/Cargo.lock')]
    shared = sorted(cli.keys() & fuzz.keys())
    for name in shared:
        if dependency(cli[name]) != dependency(fuzz[name]):
            raise ValueError(f'{name}: CLI/fuzz dependency requirements or features differ')
        resolved = [sorted((p['version'], p.get('source'), p.get('checksum'))
                           for p in lock if p['name'] == name) for lock in locks]
        if not resolved[0] or resolved[0] != resolved[1]:
            raise ValueError(f'{name}: CLI/fuzz resolved packages differ')
    return shared


if __name__ == '__main__':
    names = check(Path(__file__).resolve().parents[1])
    print(f'{len(names)} shared CLI/fuzz dependencies align (features and locked packages)')
