#!/usr/bin/env python3
"""Direct native/native build-profile diagnostic; not an FS-20 acceptance gate.

Compare two release binaries built from identical source. Alternating order,
one excluded warmup and five timed trials; validate every analysis report.
Kernel RSS and elapsed time only: no sampled aggregate-resource claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile

from benchmark_native_folder import native_measure, analysis_signature, assert_equivalent
from benchmark_folder import write_sample


def identity(path):
    return dict(path=str(path), size_bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                build=subprocess.check_output([str(path), '--version'], text=True).strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-build-setting', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binaries = [p.resolve(strict=True) for p in (args.baseline, args.candidate)]
    builds = [identity(p) for p in binaries]
    sources = [next(line for line in b['build'].splitlines() if line.startswith('source SHA256:')) for b in builds]
    assert sources[0] == sources[1], 'profile experiment requires identical source inputs'
    assert all('profile: release' in b['build'].splitlines() for b in builds)
    evidence = dict(run_state='running', scope=__doc__, platform=platform.platform(),
        candidate_build_settings=args.candidate_build_setting, baseline=builds[0], candidate=builds[1],
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        helper_hashes={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                       for name in ('benchmark_native_folder.py', 'benchmark_folder.py')},
        warmups=1, timed_runs=5, scenarios={})
    with args.output.open('x') as output, tempfile.TemporaryDirectory(prefix='binsith-profile-') as temporary:
        root = Path(temporary).resolve()
        tiny = root / 'tiny'; tiny.mkdir()
        large = root / 'large'; large.mkdir()
        corpora = [('tiny_strings', [write_sample(tiny / f'tiny-{i}.bin', 64*1024, i) for i in range(128)], ['-s']),
                   ('large_summary', [write_sample(large / 'large.bin', 32*1024**2, 128)], ['-i'])]
        for name, samples, flags in corpora:
            for workers in (1, 8):
                key = f'{name}_{workers}_workers'
                result = dict(flags=flags, workers=workers, baseline=[], candidate=[])
                reference = None
                for iteration in range(6):
                    for index in ([0, 1] if iteration % 2 == 0 else [1, 0]):
                        with tempfile.TemporaryDirectory(dir=root) as destination:
                            reports = Path(destination) / 'reports'
                            metric = native_measure(str(binaries[index]), samples, reports, workers, 120, flags, False)
                            signature = analysis_signature(reports, samples, True)
                            if reference is None:
                                reference = signature
                            else:
                                assert_equivalent(reference, signature)
                        if iteration:
                            result['baseline' if index == 0 else 'candidate'].append(metric)
                result['summary'] = {}
                for label in ('baseline', 'candidate'):
                    timings = [s['elapsed_seconds'] for s in result[label]]
                    median = statistics.median(timings)
                    result['summary'][label] = dict(median_seconds=median,
                        spread_percent=100*(max(timings)-min(timings))/median,
                        peak_rss_bytes=max(s['max_single_child_rss_bytes'] for s in result[label]))
                result['analysis_sha256'] = hashlib.sha256(json.dumps(reference[0], sort_keys=True).encode()).hexdigest()
                evidence['scenarios'][key] = result
                output.seek(0); json.dump(evidence, output, indent=2); output.write('\n'); output.truncate(); output.flush()
                print(key, result['summary'], flush=True)
        evidence['run_state'] = 'complete'
        output.seek(0); json.dump(evidence, output, indent=2); output.write('\n'); output.truncate()


if __name__ == '__main__':
    main()
