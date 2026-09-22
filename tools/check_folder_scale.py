#!/usr/bin/env python3
"""Native folder equivalence/resource probe; stdlib only, macOS/Linux ps + lsof.

Samples are observations, not hard memory quotas or throughput measurements.
Only child PIDs and temporary directories created by this run are inspected.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

from benchmark_folder import scratch_size, write_sample


def descriptors(output, input_root, scratch, destination):
    entries, entry = [], {}
    for line in output.splitlines():
        if not line:
            continue
        if line[0] in ('p', 'f'):
            if entry.get('f', '').isdigit():
                entries.append(entry)
            entry = {}
        entry[line[0]] = line[1:]
    if entry.get('f', '').isdigit():
        entries.append(entry)
    def under(record, root):
        return record.get('n', '').startswith(str(root) + os.sep)
    return {
        'open_descriptors': len(entries),
        'input_files': sum(e.get('t') == 'REG' and under(e, input_root) for e in entries),
        'input_directories': sum(e.get('t') == 'DIR' and
                                 (under(e, input_root) or e.get('n') == str(input_root))
                                 for e in entries),
        'scratch_files': sum(e.get('t') == 'REG' and under(e, scratch) for e in entries),
        'scratch_logical_bytes': scratch_size(output, scratch),
        'pending_output_logical_bytes': sum(int(e.get('s', '0')) for e in entries
            if e.get('t') == 'REG' and under(e, destination)
            and Path(e.get('n', '')).name.startswith(('.pending-', '.manifest-'))),
    }


def validate(destination, samples):
    manifest = json.loads((destination / 'manifest.json').read_text())
    assert manifest['status'] == 'complete' and manifest['discovery_complete']
    assert not manifest['stop_reasons']
    counters = manifest['counters']
    assert counters['eligible'] == counters['complete'] == len(samples)
    assert all(counters[k] == 0 for k in ('queued', 'active', 'failed', 'limited',
                                        'cancelled', 'discovery_errors', 'policy_skipped'))
    assert (destination / 'errors.jsonl').read_bytes() == b''
    admitted, terminals, reports = {}, {}, set()
    for sequence, line in enumerate((destination / 'files.jsonl').read_text().splitlines(), 1):
        record = json.loads(line)
        assert record['sequence'] == sequence
        assert record['batch_id'] == manifest['batch_id']
        entry_id = record['entry_id']
        if record['record_type'] == 'admission':
            assert entry_id not in admitted
            admitted[entry_id] = (record['path'], record['display_path'])
            continue
        assert record['record_type'] == 'terminal'
        assert admitted[entry_id] == (record['path'], record['display_path'])
        name = record['display_path']
        assert name in samples and name not in terminals
        outcome = copy.deepcopy(record['outcome'])
        assert outcome['status'] == 'complete'
        receipt = outcome['report']
        receipt.pop('duration_ms')
        location = receipt['location']
        assert location == f"results/{receipt['report_id'][:2]}/{receipt['report_id']}.json"
        assert location not in reports
        reports.add(location)
        body = json.loads((destination / location).read_text())
        summary = body['file_summary']
        assert summary['file_path'] == name
        assert summary['sha256'] == samples[name]['sha256']
        assert summary['size_bytes'] == receipt['selected_bytes'] == samples[name]['size']
        assert body['complete'] and body['processing_complete']
        terminals[name] = {'path': record['path'], 'outcome': outcome, 'body': body}
    assert len(admitted) == len(terminals) == len(samples)
    actual = {p.relative_to(destination).as_posix() for p in destination.rglob('*.json')}
    assert actual == reports | {'manifest.json'}
    assert not list(destination.rglob('.pending-*'))
    assert not list(destination.glob('.manifest-*')) and not (destination / '.binsith.lock').exists()
    digest = hashlib.sha256(json.dumps(terminals, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return digest, manifest


def run(binary, root, scratch, destination, jobs, samples):
    command = [str(binary), str(root), '--recursive', '--jobs', str(jobs),
               '--output-dir', str(destination), '-s', '--scan-utf16', '--entropy', '-q']
    peak, count, manifests = {}, 0, 0
    start = time.monotonic()
    with tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors,
            env=dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch)))
        try:
            while child.poll() is None:
                if time.monotonic() - start > 180:
                    raise TimeoutError('native scan exceeded 180 seconds')
                ps = subprocess.run(['ps', '-o', 'rss=', '-p', str(child.pid)],
                                    capture_output=True, text=True, timeout=10)
                opened = subprocess.run(['lsof', '-a', '-p', str(child.pid), '-FftsinD'],
                                        capture_output=True, text=True, timeout=10)
                if ps.returncode not in (0, 1) or opened.returncode not in (0, 1) or opened.stderr:
                    raise RuntimeError(f'resource inspection failed: {ps.stderr} {opened.stderr}')
                if ps.stdout.strip() and opened.stdout.strip():
                    values = descriptors(opened.stdout, root, scratch, destination)
                    values['rss_bytes'] = int(ps.stdout.strip()) * 1024
                    count += 1
                    for key, value in values.items():
                        peak[key] = max(peak.get(key, 0), value)
                try:
                    state = json.loads((destination / 'manifest.json').read_text())
                except FileNotFoundError:
                    pass
                else:
                    manifests += 1
                    for key in ('active', 'queued'):
                        peak[key] = max(peak.get(key, 0), state['counters'][key])
                    assert state['counters']['active'] <= jobs
                    assert state['counters']['queued'] <= 2 * jobs
                time.sleep(.02)
            if child.returncode:
                errors.seek(0)
                raise RuntimeError(errors.read().decode(errors='replace'))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    assert count > 0, 'no resource samples; increase corpus size'
    assert peak['input_files'] <= jobs
    # Discovery owns one directory; transient no-follow validation may own a second.
    assert peak['input_directories'] <= 2
    assert peak['scratch_files'] <= jobs + 1
    assert not list(scratch.iterdir())
    digest, manifest = validate(destination, samples)
    return {'jobs': jobs, 'files': len(samples), 'input_bytes': sum(s['size'] for s in samples.values()),
            'sample_count': count, 'manifest_samples': manifests, 'observed_peaks': peak,
            'elapsed_seconds_with_sampling': round(time.monotonic() - start, 3),
            'equivalence_sha256': digest, 'build': manifest['build']}


def corpus(root, kind):
    samples = {}
    count = 4096 if kind == 'wide4096' else 1024
    if kind == 'mixed':
        count = 72
    for i in range(count):
        parent = root
        if kind == 'fanout':
            parent = root / f'd{i:04d}'
        elif kind.startswith('deep'):
            depth = int(kind[4:])
            parent = root.joinpath(*(['d'] * (i % depth + 1)))
        parent.mkdir(parents=True, exist_ok=True)
        size = 16 * 1024 * 1024 if kind == 'mixed' and i < 8 else 4096
        path = parent / f'f{i:04d}'
        sample = write_sample(path, size, i)
        # Exercise decoding and both UTF-16 extraction passes without truncation.
        with path.open('r+b') as stream:
            stream.seek(128)
            stream.write(b'aHR0cHM6Ly9leGFtcGxlLmNvbQ==\0' + 'https://utf16.example'.encode('utf-16le') + b'\0\0')
        sample['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        samples[str(path.relative_to(root))] = sample
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/binsith'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    evidence = {'schema_version': 1, 'platform': platform.platform(),
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'limitations': ['Warm/uncontrolled cache; profiling overhead included; not a throughput benchmark.',
            'Sequential ps/lsof and periodic manifests are not atomic and can miss peaks.',
            'RSS covers all threads in the child; scratch bytes are logical sizes, including unlinked files.',
            'Observed maxima are not memory quotas; exact queue/worker bounds use controlled Rust tests.',
            'Platform-local run; other operating systems require native validation.'], 'cases': {}}
    # Reserve evidence before expensive work, avoiding accidental overwrite.
    with args.output.open('x') as output:
        for kind in ('wide1024', 'wide4096', 'fanout', 'deep32', 'deep128', 'mixed'):
            with tempfile.TemporaryDirectory(prefix='binsith-scale-') as temporary:
                base = Path(temporary).resolve()
                root, scratch = base / 'input', base / 'scratch'
                root.mkdir()
                scratch.mkdir()
                samples = corpus(root, kind)
                runs = []
                for jobs in (1, 2, 4, 8):
                    result = run(binary, root, scratch, base / f'output-{jobs}', jobs, samples)
                    if runs:
                        assert result['equivalence_sha256'] == runs[0]['equivalence_sha256'], kind
                    runs.append(result)
                    print(f'{kind} jobs={jobs}: equivalent, {result["sample_count"]} samples', flush=True)
                evidence['cases'][kind] = runs
                output.seek(0)
                json.dump(evidence, output, indent=2)
                output.write('\n')
                output.truncate()
                output.flush()


if __name__ == '__main__':
    main()
