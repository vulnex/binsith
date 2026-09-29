#!/usr/bin/env python3
"""Build release binaries with machine-specific source paths remapped."""
import os
from pathlib import Path
import shlex
import subprocess


def build():
    root = Path(__file__).resolve().parents[1]
    home = Path.home()
    env = os.environ.copy()
    encoded = env.get('CARGO_ENCODED_RUSTFLAGS')
    flags = ([flag for flag in encoded.split('\x1f') if flag] if encoded is not None
             else shlex.split(env.get('RUSTFLAGS', '')))
    # Rust uses the last matching mapping. Put broad roots before specific roots.
    mappings = [
        (home, '/build/user-root'),
        (Path(env.get('CARGO_HOME', home / '.cargo')).resolve(), '/build/cargo'),
        (Path(env.get('RUSTUP_HOME', home / '.rustup')).resolve(), '/build/rustup'),
        (root, '/src/binsith'),
    ]
    for source, destination in mappings:
        for spelling in dict.fromkeys((str(source), source.as_posix())):
            flags.append(f'--remap-path-prefix={spelling}={destination}')
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    subprocess.run(['cargo', 'build', '--release', '--locked'], cwd=root, env=env, check=True)


if __name__ == '__main__':
    build()
