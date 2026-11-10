#!/usr/bin/env python3
"""Compare text helpers with independent CPython calls through a real process."""
import random
import re
import shlex
import subprocess
import sys
import urllib.parse
from pathlib import Path

binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('target/debug/examples/text_probe')
rng = random.Random(20261109)
cases = []

def case(op, value, extra=''):
    raw = value if isinstance(value, bytes) else value.encode()
    try:
        if op == 'decode': result = [raw.decode('utf-8', 'replace')]
        elif op == 'casefold': result = [value.casefold()]
        elif op == 'strip': result = [value.strip()]
        elif op == 'split': result = value.split()
        elif op == 'splitlines': result = value.splitlines()
        elif op == 'quote': result = [urllib.parse.quote(value, safe=extra)]
        elif op == 'shell': result = [shlex.quote(value)]
        elif op == 'word': result = [str(re.fullmatch(r'\w+', value) is not None).lower()]
        elif op == 'space': result = [str(value.isspace()).lower()]
        elif op == 'urlsplit':
            p = urllib.parse.urlsplit(value)
            result = [p.scheme, p.netloc, p.path, p.query, p.fragment, p.hostname or '']
        expected = str(len(result)) + ':' + '\t'.join(s.encode().hex() for s in result)
    except ValueError:
        expected = '!error'
    cases.append((op + '\t' + raw.hex() + '\t' + extra.encode().hex(), expected, repr(value)))

alphabet = 'A zßİςΣﬃ日本🙂\r\n\t\v\f\x1c\x1d\x1e\x1f\x85\u2003\u2028\u2029\u0301\u00b2\u200b\ufeff\'"/:%&+-'
for _ in range(1500):
    s = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(60)))
    for op in ('casefold', 'strip', 'split', 'splitlines', 'quote', 'shell'):
        case(op, s, '/:-' if op == 'quote' and rng.randrange(2) else '')
for cp in list(range(256)) + [rng.randrange(0x110000) for _ in range(6000)]:
    if 0xD800 <= cp <= 0xDFFF: continue
    for op in ('casefold', 'word', 'space'): case(op, chr(cp))
for b in [bytes([i]) for i in range(256)] + [bytes(rng.randrange(256) for _ in range(rng.randrange(30))) for _ in range(3000)]: case('decode', b)
for authority in ('localhost', 'USER:pass@EXAMPLE.com:80', '[::1]:42', '[127.0.0.1]', '[v1.future]', '[v.bad]', '[::1%Zone]', 'bad[::1]suffix', 'a＠b', 'a／b', 'ß.Example', '[bad', 'bad]'):
    for prefix in ('https://', '//', '\x00\x20HTTP://', '\tHtTp://'):
        case('urlsplit', prefix + authority + '/path?q=x#f')
for authority in ('ΑΣ', 'ΑΣΑ', 'ΑΣ\u0301', 'AΣ\u0345A', 'AΣ\u0345.', '[::1%]', '[::1%a%b]', '[::1%Zone]'):
    case('urlsplit', 'https://' + authority + '/')
# Sample every Unicode block in Final_Sigma context, including cased/ignorable overlap.
for cp in range(0, 0x110000, 37):
    if 0xD800 <= cp <= 0xDFFF or chr(cp) in '/?#@[]:': continue
    for tail in ['A', '.']:
        case('urlsplit', 'https://AΣ' + chr(cp) + tail + '/')
result = subprocess.run([str(binary.resolve())], input='\n'.join(c[0] for c in cases) + '\n', text=True, capture_output=True, check=True)
rows = result.stdout.splitlines()
if len(rows) != len(cases): raise SystemExit(f'FAIL output rows {len(rows)} != {len(cases)}')
failures = [(i, inp.split('\t')[0], desc, expected, actual) for i, ((inp, expected, desc), actual) in enumerate(zip(cases, rows)) if expected != actual]
for row in failures[:20]: print('FAIL', *row)
print(f'Python {sys.version.split()[0]}: text cases={len(cases)} pass={len(cases)-len(failures)} fail={len(failures)}')
raise SystemExit(bool(failures))
