#!/usr/bin/env python3
"""Reject identifying build paths and archive owner metadata without printing them.

This is a release gate for known leaks, not a general-purpose PII detector.
Intentional author attribution and example data still require human review.
"""
import argparse
from pathlib import Path
import re
import tarfile
import zipfile


PRIVATE_PATH = re.compile(
    r"(?:/(?:Users|home)/[^/\s\x00]+/|/root/|[A-Za-z]:[/\\]Users[/\\]"
    r"[^/\\\s\x00]+[/\\]|/private/(?:var|tmp)/|/var/folders/)",
    re.IGNORECASE,
)


def check_content(name, data):
    # UTF-16 paths can occur in Windows executables; check both byte alignments.
    texts = [data.decode('utf-8', errors='replace')]
    for encoding in ('utf-16le', 'utf-16be'):
        texts.extend(data[offset:].decode(encoding, errors='replace') for offset in (0, 1))
    if any(PRIVATE_PATH.search(text) for text in texts):
        raise ValueError(f'{name}: identifying build or temporary path (value redacted)')


def check_archive(path):
    """Read members directly; never extract or execute a supplied archive."""
    path = Path(path)
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            if archive.comment:
                raise ValueError('unexpected ZIP archive comment')
            for member in archive.infolist():
                if member.comment or member.extra:
                    raise ValueError('unexpected ZIP member metadata')
                check_content('archive member name', member.filename.encode())
                check_content(member.filename, archive.read(member))
    else:
        with tarfile.open(path) as archive:
            for member in archive:
                if member.uid or member.gid or member.uname or member.gname:
                    raise ValueError('archive contains owner identity metadata')
                if not member.isfile():
                    raise ValueError('archive contains a non-regular member')
                check_content('archive member name', member.name.encode())
                check_content('archive extended metadata', repr(member.pax_headers).encode())
                check_content(member.name, archive.extractfile(member).read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archives', nargs='+', type=Path)
    args = parser.parse_args()
    failed = False
    for path in args.archives:
        try:
            check_archive(path)
            print(f'PASS {path.name}: no identifying paths or owner metadata detected')
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            print(f'FAIL {path.name}: {error}')
            failed = True
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
