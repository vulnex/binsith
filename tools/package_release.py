#!/usr/bin/env python3
#
# VULNEX -BinSith-
#
# File: package_release.py
# Author: Simon Roses Femerling
# Created: 2026-09-19
# Last Modified: 2026-09-19
# Version: 0.4.2
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Package explicitly allowlisted release files, then verify and smoke-test them."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import zipfile

from check_folder_examples import check_examples

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUPPORTED = {'aarch64-apple-darwin', 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'}


def command(root, *args):
    return subprocess.check_output(args, cwd=root, text=True).strip()


def package(root):
    if command(root, 'git', 'status', '--porcelain', '--untracked-files=normal'):
        raise SystemExit('Commit release inputs before packaging: checkout is not clean.')
    revision = command(root, 'git', 'rev-parse', 'HEAD')
    version = re.search(r'^version = "([^"]+)"', (root/'Cargo.toml').read_text(), re.M)[1]
    executable = 'binsith.exe' if os.name == 'nt' else 'binsith'
    binary = root/'target/release'/executable
    if binary.is_symlink() or not binary.is_file():
        raise SystemExit(f'Expected a regular trusted target/release/{executable} binary.')
    identity = command(root, str(binary), '--version')
    fields = dict(line.split(': ', 1) for line in identity.splitlines()[1:])
    digest = hashlib.sha256()
    # Rust PathBuf ordering is case-sensitive on every host. WindowsPath's
    # default ordering folds case, which would produce a different fingerprint.
    paths = sorted([pathlib.Path(n) for n in ('Cargo.toml', 'Cargo.lock', 'build.rs')] +
                   [p.relative_to(root) for p in (root/'src').rglob('*') if p.is_file()],
                   key=lambda path: path.parts)
    for path in paths:
        data = (root/path).read_bytes()
        digest.update(path.as_posix().encode())
        digest.update(b'\0')
        digest.update(len(data).to_bytes(8, 'little'))
        digest.update(data)
    if (identity.splitlines()[0] != 'binsith '+version or fields.get('revision') != revision
            or fields.get('source SHA256') != digest.hexdigest() or fields.get('profile') != 'release'):
        raise SystemExit('Release binary does not match committed inputs; rebuild with cargo build --release --locked.')
    target = fields['target']
    if target not in SUPPORTED:
        raise SystemExit(f'Unsupported package target: {target}')
    output = root/'dist'
    output.mkdir(exist_ok=True)
    name = f'binsith-{version}-{target}'
    windows = target.endswith('windows-msvc')
    archive = output/(name+('.zip' if windows else '.tar.gz'))
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    files = {executable: binary, **{n: root/n for n in ('README.md', 'CHANGELOG.md', 'RELEASE.md', 'LICENSE')}}
    files['assets/branding/binsith-logo.png'] = root/'assets/branding/binsith-logo.png'
    with tempfile.TemporaryDirectory(prefix='binsith-release-') as temp:
        build = pathlib.Path(temp)/'BUILD-INFO.json'
        build.write_text(json.dumps(dict(version=version, revision=revision, target=target,
            source_sha256=digest.hexdigest(), binary_sha256=binary_hash, signed=False), indent=2)+'\n', encoding='utf-8')
        files['BUILD-INFO.json'] = build
        for source in files.values():
            if source.is_symlink() or not source.is_file():
                raise SystemExit(f'Not a regular release input: {source.name}')
        if windows:
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package_file:
                for filename, source in files.items():
                    package_file.write(source, arcname=name+'/'+filename)
        else:
            with tarfile.open(archive, 'w:gz') as package_file:
                for filename, source in files.items():
                    info = package_file.gettarinfo(str(source), arcname=name+'/'+filename)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    with source.open('rb') as stream:
                        package_file.addfile(info, stream)
        # Read back only the exact allowlist. Do not extract arbitrary archive paths.
        expected = {name+'/'+filename for filename in files}
        contents = {}
        if windows:
            with zipfile.ZipFile(archive) as package_file:
                names = package_file.namelist()
                if set(names) != expected or len(names) != len(expected):
                    raise SystemExit('Unexpected ZIP members.')
                contents = {n: package_file.read(n) for n in names}
        else:
            with tarfile.open(archive, 'r:gz') as package_file:
                members = package_file.getmembers()
                if (set(package_file.getnames()) != expected or len(members) != len(expected)
                        or not all(m.isfile() for m in members)):
                    raise SystemExit('Unexpected TAR members.')
                contents = {m.name: package_file.extractfile(m).read() for m in members}
        for filename, source in files.items():
            if contents[name+'/'+filename] != source.read_bytes():
                raise SystemExit(f'Archive content mismatch: {filename}')
        extracted = pathlib.Path(temp)/executable
        extracted.write_bytes(contents[name+'/'+executable])
        extracted.chmod(0o755)
        if command(root, str(extracted), '--version') != identity:
            raise SystemExit('Packaged binary identity mismatch.')
        result = subprocess.check_output(
            [str(extracted), '--export-indicators', '-', '--category', 'URL', '-'],
            input=b'https://example.org/release-smoke', cwd=root,
        )
        report = json.loads(result)
        if (not report['context']['processing_complete']
                or report['indicators'][0]['value'] != 'https://example.org/release-smoke'):
            raise SystemExit('Packaged binary export smoke test failed.')
        if not windows:
            readme = pathlib.Path(temp)/'README.md'
            readme.write_bytes(contents[name+'/README.md'])
            evidence = pathlib.Path(temp)/'folder-examples.json'
            check_examples(extracted, readme, evidence)
            (output/f'folder-examples-{target}.json').write_bytes(evidence.read_bytes())
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = f'{archive_hash}  {archive.name}\n'
    # Target-specific files can be downloaded together without name collisions.
    (output/f'SHA256SUMS-{target}').write_text(checksum, encoding='utf-8')
    (output/'SHA256SUMS').write_text(checksum, encoding='utf-8')
    print(archive)
    print(f'SHA256 {archive_hash}')
    print('PASS archive allowlist, contents, identity, and extracted-binary smoke test')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=ROOT,
                        help='Clean checkout to package (defaults to this repository)')
    package(parser.parse_args().root.resolve())
