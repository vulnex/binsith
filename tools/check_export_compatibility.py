#!/usr/bin/env python3
"""Check JSON/CSV parity using independent standard-library consumers."""
import csv
import io
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLUMNS = [
    'record_type', 'category', 'value', 'validation_status', 'validation_reason',
    'observed_occurrences', 'locations_json', 'locations_omitted', 'context_json',
]


def main():
    binary = ROOT / 'target/release/binsith'
    if not binary.exists():
        binary = binary.with_suffix('.exe')
    with tempfile.TemporaryDirectory(prefix='binsith-consumer-') as directory:
        patterns = pathlib.Path(directory) / 'patterns.toml'
        patterns.write_text('custom = ".+"\n', encoding='utf-8')
        cases = [
            ('empty', b'', []),
            ('mixed', b'https://example.org/a\0https://example.org/a\0'
             b'https://example.org/cert.crt0E\0MaxReceiveBufferPerConnection',
             ['--category', 'URL,litecoin']),
            ('quoted-unicode', 'caf\u00e9,"quoted",value'.encode('utf-8'),
             ['--encoding', 'utf8', '--patterns', str(patterns)]),
            ('limited', b'https://example.org/very-long-path',
             ['--max-string-bytes', '8']),
        ]
        for name, data, options in cases:
            for validation in ('all', 'actionable', 'validated'):
                documents = {}
                for fmt in ('json', 'csv'):
                    command = [str(binary), '--export-indicators', '-',
                               '--export-format', fmt, '--export-validation', validation,
                               *options, '-']
                    documents[fmt] = subprocess.run(
                        command, input=data, capture_output=True, check=True,
                    ).stdout.decode('utf-8')
                report = json.loads(documents['json'])
                reader = csv.DictReader(io.StringIO(documents['csv'], newline=''))
                assert reader.fieldnames == COLUMNS, name
                rows = list(reader)
                assert all(None not in row and None not in row.values() for row in rows), name
                contexts = [row for row in rows if row['record_type'] == 'context']
                assert len(contexts) == 1, name
                context = json.loads(contexts[0]['context_json'])
                context['metadata']['configuration']['export_format'] = 'json'
                assert context == report['context'], name
                assert context['schema_version'] == 1 and context['processing_complete'], name
                entries = []
                for row in rows:
                    if row['record_type'] == 'context':
                        continue
                    assert row['record_type'] == 'indicator', name
                    entries.append({
                        **{key: row[key] for key in (
                            'category', 'value', 'validation_status', 'validation_reason')},
                        'observed_occurrences': int(row['observed_occurrences']),
                        'locations': json.loads(row['locations_json']),
                        'locations_omitted': int(row['locations_omitted']),
                    })
                assert entries == report['indicators'], name
                if name == 'empty':
                    assert not entries
                if name == 'quoted-unicode' and validation != 'validated':
                    assert [entry['value'] for entry in entries] == [data.decode('utf-8')]
                if name == 'limited':
                    assert context['analysis_coverage']['status'] != 'complete_within_configured_scope'
                print(f'PASS {name}: {validation} JSON/CSV parity')
    print('12 standard-parser checks passed; downstream application integrations remain separate.')


if __name__ == '__main__':
    main()
