#!/usr/bin/env python3
"""Compare all tagged rules with the Python oracle across HMAC key lengths.

File keys go through the real Python load_key (bytes.strip); the redactor API also
accepts raw bytes, where whitespace must remain significant. The existing corpus
protocol accepts per-vector keys, so no production mutation selector is needed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LENGTHS = (31, 32, 33, 64, 128)


def check(binary, artifacts):
    artifacts.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('key_oracle', ROOT / 'vendor/memory-mcp/session_redact.py')
    sr = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(sr)
    samples = {
        'aws-key': 'AKIA' + 'C' * 16,
        'github-token': 'ghp_' + 'a' * 36,
        'anthropic-key': 'sk-ant-' + 'b' * 24,
        'openai-key': 'sk-' + 'c' * 24,
        'slack-token': 'xoxb-' + '1' * 12,
        'google-api-key': 'AIza' + 'd' * 35,
        'gitlab-token': 'glpat-' + 'e' * 20,
        'jwt': 'eyJ' + 'a' * 8 + '.' + 'b' * 8 + '.' + 'c' * 8,
    }
    assert set(samples) == {name for name, _ in sr._TAGGED}, 'tagged rule missing'
    vectors = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'key'
        for length in LENGTHS:
            # Include binary bytes and internal whitespace without trimmable ends.
            key = b'K' + bytes((i * 37) % 256 for i in range(length - 2)) + b'Z'
            padded = b' \t\r\n\v\f' + key + b'\f\v\n\r\t '
            path.write_bytes(padded)
            loaded = sr.load_key(str(path))
            assert loaded == key and len(loaded) == length
            for source, supplied in (('direct', key), ('file-padded', loaded), ('raw-padded', padded)):
                for kind, text in samples.items():
                    for op, value in (('redact_text', text), ('redact_record', {'message': [text]})):
                        output, counts = getattr(sr, op)(value, supplied)
                        encoded = json.dumps(output)
                        assert counts == {kind: 1} and re.search(r':[0-9a-f]{8}\]', encoded)
                        vectors.append({'id': f'hmac-key/{length}/{source}/{kind}/{op}',
                                        'op': op, 'input': value, 'hmac_key_hex': supplied.hex(),
                                        'expect': {'output': output, 'counts': counts}})
    # Preserve the server-owned corpus bytes and append only in a temporary input.
    corpus = ROOT / 'vendor/memory-mcp/conformance/session_redact_r1.jsonl'
    header_bytes, body = corpus.read_bytes().split(b'\n', 1)
    header = json.loads(header_bytes)
    assert body.endswith(b'\n')
    assert hashlib.sha256(body).hexdigest() == header['sha256_of_vectors']
    body += b''.join((json.dumps(v, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
                     for v in vectors)
    header['vectors'] += len(vectors)
    header['sha256_of_vectors'] = hashlib.sha256(body).hexdigest()
    payload = json.dumps(header).encode() + b'\n' + body
    result = subprocess.run([binary, '_conformance', 'redact'], input=payload, capture_output=True)
    log = (result.stdout + result.stderr).decode()
    (artifacts / 'hmac-keys.log').write_text(log)
    failures = re.findall(r'^FAIL conformance: "(hmac-key/[^\"]+)"$', log, re.MULTILINE)
    summary = {'key_lengths': list(LENGTHS), 'file_whitespace_bytes': 12,
               'tagged_rules': len(samples), 'oracle_vectors': len(vectors),
               'total_vectors': header['vectors'], 'exit': result.returncode,
               'hmac_mismatches': len(failures), 'failed_ids': failures}
    (artifacts / 'hmac-keys.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    if result.returncode:
        print(log[-2000:], file=sys.stderr)
        return 1
    assert not result.stdout and not failures
    assert f'vectors={header["vectors"]} failures=0 emitted=0' in log, 'missing comparison evidence'
    print('PASS HMAC Python differential: key lengths 31, 32, 33, 64, 128; loaded and raw whitespace')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    sys.exit(check(args.binary.resolve(), args.artifacts.resolve()))
