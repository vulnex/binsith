#!/usr/bin/env python3
"""Package only explicitly allowlisted release files; never sample/evaluation data."""
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()

def main():
    if command('git', 'status', '--porcelain', '--untracked-files=normal'):
        raise SystemExit('Commit release inputs before packaging: checkout is not clean.')
    revision = command('git', 'rev-parse', 'HEAD')
    version = re.search(r'^version = "([^"]+)"', (ROOT/'Cargo.toml').read_text(), re.M)[1]
    binary = ROOT/'target/release/binsith'
    if binary.is_symlink() or not binary.is_file():
        raise SystemExit('Expected a regular trusted target/release/binsith binary.')
    identity = command(str(binary), '--version')
    fields = dict(line.split(': ', 1) for line in identity.splitlines()[1:])
    digest = hashlib.sha256()
    paths = sorted([pathlib.Path(n) for n in ('Cargo.toml', 'Cargo.lock', 'build.rs')] +
                   [p.relative_to(ROOT) for p in (ROOT/'src').rglob('*') if p.is_file()])
    for path in paths:
        data = (ROOT/path).read_bytes()
        digest.update(path.as_posix().encode())
        digest.update(b'\0')
        digest.update(len(data).to_bytes(8, 'little'))
        digest.update(data)
    if (identity.splitlines()[0] != 'binsith '+version or fields.get('revision') != revision
            or fields.get('source SHA256') != digest.hexdigest() or fields.get('profile') != 'release'):
        raise SystemExit('Release binary does not match committed inputs; rebuild with cargo build --release --locked.')
    target = fields['target']
    if target != 'aarch64-apple-darwin':
        raise SystemExit('This local packager currently verifies the macOS ARM64 artifact only.')
    output = ROOT/'dist'
    output.mkdir(exist_ok=True)
    name = f'binsith-{version}-{target}'
    archive = output/(name+'.tar.gz')
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    files = {'binsith': binary, **{n: ROOT/n for n in ('README.md', 'CHANGELOG.md', 'RELEASE.md')}}
    with tempfile.TemporaryDirectory(prefix='binsith-release-') as temp:
        build = pathlib.Path(temp)/'BUILD-INFO.json'
        build.write_text(json.dumps(dict(version=version, revision=revision, target=target,
            source_sha256=digest.hexdigest(), binary_sha256=binary_hash, signed=False), indent=2)+'\n')
        files['BUILD-INFO.json'] = build
        with tarfile.open(archive, 'w:gz') as tar:
            for filename, source in files.items():
                if source.is_symlink() or not source.is_file():
                    raise SystemExit(f'Not a regular release input: {filename}')
                info = tar.gettarinfo(str(source), arcname=name+'/'+filename)
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                with source.open('rb') as stream:
                    tar.addfile(info, stream)
    with tarfile.open(archive, 'r:gz') as tar:
        assert set(tar.getnames()) == {name+'/'+n for n in files}
        assert all(m.isfile() for m in tar.getmembers())
        assert hashlib.sha256(tar.extractfile(name+'/binsith').read()).hexdigest() == binary_hash
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output/'SHA256SUMS').write_text(f'{archive_hash}  {archive.name}\n')
    print(archive)
    print(f'SHA256 {archive_hash}')

if __name__ == '__main__':
    main()
