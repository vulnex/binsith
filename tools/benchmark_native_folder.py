#!/usr/bin/env python3
"""FS-20 paired external/native adapter using frozen FS-04 corpora and numeric gates.

Analysis reports must be equivalent; native journals/manifest are additional measured
work. Warm timings and separate resource samples; optional synthetic write latency.
"""
import argparse
import functools
import errno
import shutil
import tomllib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import threading
import time

from benchmark_folder import measure, ResourceMonitor, write_sample
from compare_folder_benchmarks import compare


ANALYSIS_KEYS = ('strings', 'matches_only', 'no_decode', 'max_string_bytes',
    'max_decode_bytes', 'encoding', 'scan_utf16', 'offset', 'length', 'min_length',
    'categories', 'decode_depth', 'entropy', 'entropy_window', 'entropy_threshold')


LEGACY_PATTERN_FORMAT = 'SHA256 of compact JSON array of sorted [name, expression] pairs after category filtering'
BATCH_PATTERN_FORMAT = 'SHA256 of binsith:patterns:v1\\0 then u64LE byte length and UTF-8 bytes for each sorted name and expression after category filtering'


@functools.cache
def pattern_hashes(strings):
    source = Path(__file__).resolve().parents[1] / 'src/regex_patterns.toml'
    pairs = sorted(tomllib.loads(source.read_text()).items())
    legacy = hashlib.sha256(json.dumps(pairs if strings else [], separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    framed = hashlib.sha256(b'binsith:patterns:v1\0')
    for pair in pairs:
        for value in pair:
            encoded = value.encode()
            framed.update(len(encoded).to_bytes(8, 'little'))
            framed.update(encoded)
    return legacy, framed.hexdigest()


def normalize_analysis(body, name):
    # Folder reports store frozen analysis settings; single-file reports also
    # contain CLI transport/display options, which do not describe the analysis.
    body['file_summary']['file_path'] = name
    metadata = body['metadata']
    for key in ('revision', 'source_sha256', 'rustc'):
        metadata.pop(key, None)
    config = metadata['configuration']
    metadata['configuration'] = {key: config[key] for key in ANALYSIS_KEYS}
    metadata['configuration']['encoding'] = config['encoding'] or 'auto'
    metadata['effective_encoding'] = metadata['effective_encoding'].lower()
    assert not config['categories'], 'adapter corpus expects all bundled patterns'
    legacy, batch = pattern_hashes(config['strings'])
    fmt = metadata['patterns_hash_format']
    assert fmt in (LEGACY_PATTERN_FORMAT, BATCH_PATTERN_FORMAT)
    assert metadata['patterns_sha256'] == (legacy if fmt == LEGACY_PATTERN_FORMAT else batch), 'pattern identity mismatch'
    metadata['patterns_sha256'] = legacy
    metadata['patterns_hash_format'] = LEGACY_PATTERN_FORMAT
    return body


def analysis_signature(destination, samples, native):
    if native:
        manifest = json.loads((destination / 'manifest.json').read_bytes())
        counters = manifest['counters']
        assert manifest['status'] == 'complete' and manifest['discovery_complete']
        assert counters['complete'] + counters['limited'] == len(samples)
        assert all(counters[k] == 0 for k in ('failed', 'cancelled', 'queued', 'active', 'discovery_errors'))
        assert not (destination / '.binsith.lock').exists()
        paths = {}
        admissions = {}
        terminals = set()
        for seq, line in enumerate((destination / 'files.jsonl').read_bytes().splitlines(), 1):
            record = json.loads(line)
            assert record['sequence'] == seq
            assert record['batch_id'] == manifest['batch_id']
            if record['record_type'] == 'admission':
                assert record['entry_id'] not in admissions
                admissions[record['entry_id']] = record['path']
            else:
                assert admissions[record['entry_id']] == record['path']
                assert record['entry_id'] not in terminals
                terminals.add(record['entry_id'])
                assert record['display_path'] not in paths
                paths[record['display_path']] = destination / record['outcome']['report']['location']
        assert len(admissions) == len(terminals) == len(samples)
    else:
        paths = {s['path'].name: destination / f'{i:08d}.json' for i, s in enumerate(samples)}
    hashes, entropies = {}, {}
    for sample in samples:
        name = sample['path'].name
        body = json.loads(paths[name].read_bytes())
        summary = body['file_summary']
        assert summary['size_bytes'] == sample['size'] and summary['sha256'] == sample['sha256']
        entropies[name] = summary.pop('entropy')
        normalize_analysis(body, name)
        hashes[name] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return hashes, entropies


def assert_equivalent(before, after):
    assert before[0] == after[0], 'analysis reports differ beyond path/build provenance'
    assert before[1].keys() == after[1].keys()
    assert all(math.isclose(before[1][key], value, abs_tol=1e-12, rel_tol=0)
               for key, value in after[1].items()), 'summary entropy differs'


def has_published_report(destination):
    # pathlib globs include dotfiles: .pending-*.json exists before publication.
    return any(path.is_file() for path in (destination / 'results').glob('*/[!.]*.json'))


def native_measure(binary, samples, destination, workers, timeout, flags, profile):
    scratch = destination.parent / 'scratch'
    scratch.mkdir()
    monitor = ResourceMonitor(scratch)
    command = [binary, str(samples[0]['path'].parent), '--output-dir', str(destination),
               '--jobs', str(workers), '-q', *flags]
    first = []
    finished = threading.Event()
    start = time.perf_counter()
    def watch():
        while not finished.wait(.001):
            if has_published_report(destination):
                first.append(time.perf_counter() - start)
                return
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    peak = None
    with tempfile.TemporaryFile() as errors:
        child = None
        try:
            child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors,
                env=dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch)))
            if profile:
                monitor.register(child.pid)
                monitor.start()
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    peak = usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024)
                    break
                if time.perf_counter() - start > timeout:
                    raise TimeoutError('native scan timed out')
                time.sleep(.001)
            elapsed = time.perf_counter() - start
            errors.seek(0)
            assert child.returncode in (0, 1), errors.read().decode(errors='replace')
            # Limited native outcomes exit 1; validation rejects operational failure.
        finally:
            if child is not None and child.returncode is None:
                child.kill()
                child.wait()
            finished.set()
            watcher.join()
            if profile and child is not None:
                monitor.unregister(child.pid)
                monitor.stop()
    return {'elapsed_seconds': elapsed, 'first_report_observed_seconds': min(first[0], elapsed) if first else elapsed,
            'max_single_child_rss_bytes': peak,
            'report_bytes': sum(p.stat().st_size for p in (destination / 'results').glob('*/*.json')),
            'operational_artifact_bytes': sum(p.stat().st_size for p in destination.iterdir() if p.is_file()),
            'resources': monitor.result() if profile else None}


def storage_measure(function, binary, samples, destination, workers, timeout, flags, profile, args):
    if not args.write_delay_us:
        return function(binary, samples, destination, workers, timeout, flags, profile)
    audit = destination.parent / 'write-audit'
    audit.mkdir()
    environment = dict(DYLD_INSERT_LIBRARIES=str(args.write_delay_library.resolve()),
        BINSITH_BENCH_TARGET=str(Path(binary).resolve()),
        BINSITH_BENCH_OUTPUT_ROOT=str(destination.resolve()),
        BINSITH_BENCH_WRITE_AUDIT=str(audit.resolve()),
        BINSITH_BENCH_WRITE_DELAY_US=str(args.write_delay_us))
    previous = {key: os.environ.get(key) for key in environment}
    try:
        os.environ.update(environment)
        metric = function(binary, samples, destination, workers, timeout, flags, profile)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    records = [json.loads(path.read_text()) for path in audit.glob('*.json')]
    expected = 1 if function is native_measure else len(samples)
    assert len(records) == expected, 'missing write-delay audit: injection may be unavailable'
    assert all(r['calls'] > 0 and r['delay_us'] == args.write_delay_us for r in records), 'write delay did not affect every scanner'
    metric['write_delay'] = dict(processes=len(records), calls=sum(r['calls'] for r in records),
        requested_bytes=sum(r['requested_bytes'] for r in records), delay_us=args.write_delay_us)
    return metric


def existing_directory(value):
    try:
        path = Path(value).resolve(strict=True)
        if not path.is_dir():
            raise ValueError("not a directory")
        return path
    except (OSError, ValueError) as error:
        raise argparse.ArgumentTypeError(f"benchmark work directory: {error}") from error


def materialize_input(source, destination):
    """Create a fresh private corpus file without synthetic metadata companions."""
    companion = destination.with_name('._' + destination.name)
    if os.path.lexists(destination) or os.path.lexists(companion):
        raise FileExistsError(errno.EEXIST, 'fixture destination already exists', str(destination))
    try:
        os.link(source, destination)
        method = 'hardlink'
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP):
            raise
        shutil.copyfile(source, destination)
        method = 'copy'
    # macOS can add com.apple.provenance even for data-only copies on FAT32.
    # Only this newly created private fixture companion may be removed. The
    # scanner itself still includes hidden files, and user inputs are untouched.
    if platform.system() == 'Darwin' and os.path.lexists(companion):
        if companion.is_symlink() or not companion.is_file():
            raise ValueError('unexpected fixture companion type')
        with companion.open('rb') as metadata:
            if metadata.read(8) != bytes.fromhex('0005160700020000'):
                raise ValueError('unexpected fixture companion header')
        companion.unlink()
    return method


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, default=Path('target/release/binsith'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, nargs='+', default=[1, 2, 4, 8])
    parser.add_argument('--workloads', nargs='+')
    parser.add_argument('--work-dir', type=existing_directory,
                        help='existing volume directory for temporary inputs, reports and scratch; defaults to system temp')
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--write-delay-us', type=int, default=0)
    parser.add_argument('--write-delay-library', type=Path)
    args = parser.parse_args()
    if args.write_delay_us < 0 or args.write_delay_us > 1000000:
        parser.error('write delay must be between 0 and 1000000 microseconds')
    if bool(args.write_delay_us) != bool(args.write_delay_library):
        parser.error('write delay and library must be supplied together')
    if args.write_delay_us and (platform.system() != 'Darwin' or not args.write_delay_library.is_file()):
        parser.error('write injection requires macOS and a compiled slow_output.c library')
    if args.write_delay_us and os.environ.get('DYLD_INSERT_LIBRARIES'):
        parser.error('refusing to replace an existing DYLD_INSERT_LIBRARIES setting')
    if not hasattr(os, 'wait4'):
        parser.error('requires Unix wait4 plus ps/lsof profiling')
    if args.runs < 1 or any(w < 1 for w in args.workers) or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('positive runs, workers and timeout required')
    work_parent = args.work_dir or Path(tempfile.gettempdir()).resolve()
    binaries = [str(args.baseline.resolve(strict=True)), str(args.candidate.resolve(strict=True))]
    helper_hash = hashlib.sha256(b''.join(Path(__file__).with_name(name).read_bytes() for name in
        ('benchmark_folder.py', 'quality_checks.py', 'compare_folder_benchmarks.py'))).hexdigest()
    common = dict(schema_version=2, harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        timing_helper_sha256=helper_hash, platform=platform.platform(), machine=platform.machine(), logical_cpus=os.cpu_count(),
        settings=dict(adapter_version=6, work_directory=str(work_parent),
                      work_device=work_parent.stat().st_dev, write_delay_us=args.write_delay_us,
                      write_delay_library_sha256=hashlib.sha256(args.write_delay_library.read_bytes()).hexdigest() if args.write_delay_library else None,
                      write_delay_source_sha256=hashlib.sha256(Path(__file__).with_name("slow_output.c").read_bytes()).hexdigest() if args.write_delay_library else None, corpus_version=3, runs=args.runs, workers=args.workers,
                      workloads=args.workloads, warmup_runs=1, resource_profiling=True,
                      patterns_source_sha256=hashlib.sha256(Path('src/regex_patterns.toml').read_bytes()).hexdigest()))
    results = [dict(common, binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        build=subprocess.check_output([binary, '--version'], text=True).strip(),
        engine='external' if i == 0 else 'native', scenarios={}) for i, binary in enumerate(binaries)]
    gates = json.loads(Path('devnotes/benchmarks/folder-performance-gates.json').read_text())
    evidence = {'run_state': 'running', 'expected_scenarios': len(args.workers) * (len(args.workloads) if args.workloads else 7),
        'baseline': results[0], 'candidate': results[1], 'gates': gates,
        'limitations': ['Warm/uncontrolled cache only; optional synthetic per-write latency is not a physical slow disk, bandwidth cap, fsync delay, or cold-cache measurement.',
            'Equivalent analysis reports; native journals/manifest are additional candidate work included in elapsed time.',
            'Baseline first-report observation at child exit; native atomic report observed by 1ms filesystem polling.',
            'External resource totals exclude Python harness; native coordinator is included.',
            'Profile samples never enter timing medians; resource samples can miss transient peaks.',
            'Effective analysis configuration compared; CLI transport options/build provenance excluded; encoding spelling normalized; both pattern fingerprints independently verified against bundled source; entropy tolerance 1e-12.']}
    with args.output.open('x') as output, tempfile.TemporaryDirectory(prefix='binsith-native-bench-', dir=work_parent) as temporary:
        root = Path(temporary).resolve()
        source = root / 'source'
        source.mkdir()
        selected = set(args.workloads or ('tiny_strings', 'large_summary', 'mixed_strings',
            'dense_strings', 'long_strings', 'decoding', 'extra_passes'))
        tiny = ([write_sample(source / f'tiny-{i}.bin', 64 * 1024, i) for i in range(128)]
            if selected & {'tiny_strings', 'mixed_strings'} else [])
        large = ([write_sample(source / 'large.bin', 32 * 1024**2, 128)]
            if selected & {'large_summary', 'mixed_strings', 'extra_passes'} else [])
        dense = ([write_sample(source / f'dense-{i}.bin', 256 * 1024, 129+i, 'dense') for i in range(16)]
            if 'dense_strings' in selected else [])
        long = ([write_sample(source / 'long.bin', 32 * 1024**2, 0, 'long')]
            if 'long_strings' in selected else [])
        decode = ([write_sample(source / f'decode-{i}.bin', 128 * 1024, i, 'decode') for i in range(32)]
            if 'decoding' in selected else [])
        corpora = {'tiny_strings': (tiny, ['-s']), 'large_summary': (large, ['-i']),
            'mixed_strings': (tiny+large, ['-s']), 'dense_strings': (dense, ['-s']),
            'long_strings': (long, ['-s', '--max-string-bytes', '4096']),
            'decoding': (decode, ['-s', '--decode-depth', '2']),
            'extra_passes': (large, ['-s', '--scan-utf16', '--entropy'])}
        if args.workloads and not set(args.workloads) <= corpora.keys():
            parser.error('unknown workload')
        for name, (originals, flags) in corpora.items():
            if args.workloads and name not in args.workloads:
                continue
            inputs = root / name
            inputs.mkdir()
            samples = []
            materialization = set()
            for sample in originals:
                path = inputs / sample['path'].name
                materialization.add(materialize_input(sample['path'], path))
                samples.append(dict(sample, path=path))
            for workers in args.workers:
                key = f'{name}_{workers}_workers'
                scenario = dict(flags=flags, files=len(samples), input_materialization=sorted(materialization), input_bytes=sum(s['size'] for s in samples),
                    corpus_sha256=hashlib.sha256(json.dumps([(s['size'], s['sha256']) for s in samples]).encode()).hexdigest())
                for result in results:
                    result['scenarios'][key] = dict(scenario, samples=[])
                reference = None
                for iteration in range(args.runs + 2):
                    profiling = iteration == args.runs + 1
                    # Alternate order without altering corpora or measurement settings.
                    for index in ([0, 1] if iteration % 2 == 0 else [1, 0]):
                        with tempfile.TemporaryDirectory(dir=root, prefix='output-') as folder:
                            destination = Path(folder) / 'reports'
                            metric = storage_measure(measure if index == 0 else native_measure,
                                binaries[index], samples, destination, workers, args.timeout, flags, profiling, args)
                            signature = analysis_signature(destination, samples, index == 1)
                            if reference is None:
                                reference = signature
                            else:
                                assert_equivalent(reference, signature)
                        current = results[index]['scenarios'][key]
                        if profiling:
                            current['resource_sample'] = metric
                        elif iteration:
                            current['samples'].append(metric)
                for result in results:
                    current = result['scenarios'][key]
                    current['analysis_sha256'] = hashlib.sha256(json.dumps(reference[0], sort_keys=True).encode()).hexdigest()
                evidence['comparison'] = compare(*results, gates)
                output.seek(0)
                json.dump(evidence, output, indent=2)
                output.write('\n')
                output.truncate()
                output.flush()
                medians = [statistics.median(s['elapsed_seconds'] for s in r['scenarios'][key]['samples']) for r in results]
                print(f'{key}: external={medians[0]:.3f}s native={medians[1]:.3f}s {evidence["comparison"]["scenarios"][key]["status"]}', flush=True)
        evidence['run_state'] = 'complete'
        output.seek(0)
        json.dump(evidence, output, indent=2)
        output.write('\n')
        output.truncate()
        print('Overall:', evidence['comparison']['status'])
    raise SystemExit(0 if evidence['comparison']['status'] == 'pass' else 1)


if __name__ == '__main__':
    main()
