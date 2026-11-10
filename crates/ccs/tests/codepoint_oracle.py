import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from probe import REPO, run_requests
sys.path.insert(0, str(REPO))
import ccs
spec = importlib.util.spec_from_file_location('ccs.session_codex', REPO / 'vendor/memory-mcp/session_codex.py')
sc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sc
spec.loader.exec_module(sc)
ccs.session_codex = sc
from ccs import extract, fallback, util

cases = []
def add(label, request, expected):
    cases.append((label, request, expected))
def snapshot(session):
    result = dict(vars(session))
    result.update(interactive=session.interactive, resume_cwd=session.resume_cwd)
    return result
def user(content, **fields):
    return dict(type='user', message={'content': content}, **fields)

for cp in range(0xD800, 0xE000):
    s = chr(cp)
    text = '\x1c<system-reminder>' + s + '</system-reminder> Straße' + s + 'needle\u2003'
    records = [user(text), user([{'type': 'text', 'text': text}, {'type': 'tool_use', 'text': s}, {'type': 'text', 'text': s + ' tail'}]), user(text, isMeta=True)]
    for rec in records:
        add('record/%04x' % cp, {'op': 'record_text', 'input': rec}, extract.record_text(rec))
    add('casefold/%04x' % cp, {'op': 'casefold_points', 'input': text}, text.casefold())

with tempfile.TemporaryDirectory(prefix='ccs-codepoints-') as home:
    os.environ['HOME'] = home
    os.environ['CODEX_HOME'] = home + '/.codex'
    project = Path(home) / '.claude/projects/-resume--'
    project.mkdir(parents=True)
    native = Path(home) / '.codex/sessions/2026/11/10'
    native.mkdir(parents=True)
    def write(path, rows, i):
        path.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        os.utime(path, (1800000000 + i, 1800000000 + i))
    for i, cp in enumerate([0xD800, 0xDBFF, 0xDC00, 0xDC80, 0xDFFF, 0xFFFD]):
        s = chr(cp)
        sid = '%08d-0000-0000-0000-000000000000' % i
        path = project / (sid + '.jsonl')
        rows = [user('Straße' + s + 'needle', cwd='/work/' + s, relocatedCwd='/resume/' + s, entrypoint='cli'),
                {'type': 'custom-title', 'customTitle': ' \x1c' + ('x' + s) * 80 + '\u2003title '},
                {'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': s + 'needle tail'}]}}]
        write(path, rows, i)
        for q in ['', 'needle', 'STRASSE', '\ufffd']:
            add('scan/claude/%04x' % cp, {'op': 'scan', 'input': str(path), 'query': q}, snapshot(extract.scan(str(path), q)))
        npath = native / ('rollout-2026-11-10T00-00-00-' + sid + '.jsonl')
        nrows = [{'type': 'session_meta', 'payload': {'id': sid, 'cwd': '/native/' + s, 'source': 'cli'}},
                 {'type': 'response_item', 'payload': {'type': 'message', 'id': 'message-' + sid, 'role': 'user', 'content': 'Straße' + s + 'needle'}}]
        write(npath, nrows, i + 100)
        for q in ['', 'needle', 'STRASSE', '\ufffd']:
            add('scan/codex/%04x' % cp, {'op': 'scan', 'input': str(npath), 'query': q}, snapshot(extract.scan(str(npath), q)))
    for q in ['', 'needle']:
        for prefix in [None, '/work', '/work/\ufffd', '/native', '/native/\ufffd']:
            opts = dict(query=q, cwd_prefix=prefix)
            add('search', {'op': 'search', 'input': opts}, [snapshot(s) for s in fallback.search(**opts)])
    actual = run_requests([r for _, r, _ in cases])
    assert len(actual) == len(cases)
    failures = [(name, expected, got) for (name, _, expected), got in zip(cases, actual)
                if json.dumps(expected) != json.dumps(got)]
    for failure in failures[:3]:
        print('FAIL', ascii(failure))
    print('Codepoint oracle: cases=%d pass=%d fail=%d; all 2048 lone surrogates; Python %s' %
          (len(cases), len(cases) - len(failures), len(failures), sys.version.split()[0]))
    assert not failures
    # Without a message ID Python must hash the record as UTF-8, which rejects
    # a lone surrogate. The production Result boundary must preserve failure.
    bad = native / 'rollout-2026-11-10T00-00-00-ffffffff-ffff-ffff-ffff-ffffffffffff.jsonl'
    write(bad, [{'type': 'response_item', 'payload': {'type': 'message', 'role': 'user', 'content': 'needle\ud800'}}], 1000)
    try:
        extract.scan(str(bad), 'needle')
    except UnicodeEncodeError:
        pass
    else:
        raise AssertionError('Python normalization no longer rejects invalid UTF-8 hash input')
    requests = [{'op': 'scan', 'input': str(bad), 'query': 'needle'},
                {'op': 'extract', 'input': str(bad)},
                {'op': 'search', 'input': {'query': 'needle'}}]
    assert run_requests(requests) == [{'error': True}] * 3
    print('PASS normalization errors: checked scan, extract and fallback search preserve Python failure (3 cases)')
