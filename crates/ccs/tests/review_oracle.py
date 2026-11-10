"""Regression cases for edge semantics at the local-reading adapter boundary."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import random
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
from ccs import codex, extract, fallback, util

cases = []
failure_count = 0
def add(label, request, expected):
    cases.append((label, request, json.loads(json.dumps(expected))))
def snapshot(session):
    return dict(vars(session), interactive=session.interactive, resume_cwd=session.resume_cwd)
def user(content, **fields):
    return dict(type='user', message={'content': content}, **fields)
def check(cases, env=None):
    global failure_count
    actual = run_requests([r for _, r, _ in cases], env=env)
    failures = [(name, expected, got) for (name, _, expected), got in zip(cases, actual)
                if expected != got]
    seen = set()
    for failure in failures:
        group = failure[0].split('/')[0]
        if group not in seen:
            print('FAIL', ascii(failure)[:1500])
            seen.add(group)
    failure_count += len(failures)
    return len(cases)

# CPython's C fromisoformat accepts a positive trailing-data status before a tz.
for date in ['2024-01-01', '20240101', '2024-W01-1', '2024W011']:
    for clock in ['', '12:', '12:30:00.', '12.', '12:00:00.1234567x', '12:34:56.123456', '12:34:56,123456']:
        for zone in ['', 'Z', '+05:00', '-05:30:12.34']:
            value = date + ('T' + clock if clock else '') + zone
            add('timestamp/' + value, {'op': 'parse_ts', 'input': value}, util.parse_ts(value))
for sep in ['\ud800', '\udfff', '☃', '\n']:
    for pad in ['', '\x1c  ']:
        value = pad + '2024-01-01' + sep + '12:00:00Z  '
        add('separator', {'op': 'parse_ts', 'input': value}, util.parse_ts(value))
rng = random.Random(117)
for _ in range(500):
    value = '2024-01-01T' + rng.choice(['12', '12:34', '12:34:56', '123456']) + rng.choice(['.', ':', ',', '.1234567x', '.1234567', 'x', '']) + rng.choice(['', '+05:00', '-07:12:34.5'])
    add('timestamp-fuzz', {'op': 'parse_ts', 'input': value}, util.parse_ts(value))

for saved in [{'next_ordinal': -5}, {'next_ordinal': 2.0}, {'next_ordinal': True},
              {'next_ordinal': -(10**100)}, {'next_ordinal': 10**100},
              {'start_ordinal': 2.5}, {'start_ordinal': -1}, [['next_ordinal', 7]],
              [['next_ordinal', 1], ['next_ordinal', 7]], {'next_ordinal': 9007199254740993, 'start_ordinal': 9007199254740992.0}]:
    records = [{'type': 'other'}] * 4
    state = sc.IndexState('child', saved)
    accepted = [state.accept(r) for r in records]
    add('saved-ordinal', {'op': 'index_state', 'input': records, 'session_id': 'child', 'saved': saved}, {'accepted': accepted, 'state': state.state})
for a, b in [(1, 1.0), (True, 1), ({'a': 1, 'b': [2]}, {'b': [2.0], 'a': 1.0}), (9007199254740993, 9007199254740992.0)]:
    records = [{'type': 'session_meta', 'payload': {'id': b, 'forked_from_id': 'parent'}},
               {'type': 'event_msg', 'payload': {'type': 'thread_settings_applied', 'thread_id': b}}]
    state = sc.IndexState(a)
    accepted = [state.accept(r) for r in records]
    add('id-equality', {'op': 'index_state', 'input': records, 'session_id': a}, {'accepted': accepted, 'state': state.state})

for fields in [{'isCompactSummary': True}, {'isMeta': True}, {'isCompactSummary': 1}, {'isMeta': 1}, {}]:
    record = user('needle', **fields)
    add('record-flags', {'op': 'record_text', 'input': record}, extract.record_text(record))
for tail in ['{"a":1,"a":2}', '{"number":' + '1' * 4301 + '}', '{"number":1}']:
    value = '[' * 300 + tail + ']' * 300
    try:
        expected = extract.loads_strict(value)
    except ValueError:
        expected = {'error': True}
    add('deep-strict', {'op': 'strict', 'input': value}, expected)

count = 0
for home in ['', '/home/example///', None]:
    env = dict(os.environ)
    if home is None:
        env.pop('HOME', None)
        expanded = pwd.getpwuid(os.getuid()).pw_dir.rstrip('/') or '/'
    else:
        env['HOME'] = home
        expanded = home.rstrip('/') or '/'
    cwd = expanded + '/project'
    short = '~' + cwd[len(expanded):]
    count += check([('home', {'op': 'home', 'input': cwd}, {'home': expanded, 'short': short})], env)

with tempfile.TemporaryDirectory(prefix='ccs-review-') as home:
    os.environ['HOME'] = home
    os.environ['CODEX_HOME'] = home + '/.codex'
    project = Path(home) / '.claude/projects/-work'
    native = Path(home) / '.codex/sessions/day'
    project.mkdir(parents=True)
    native.mkdir(parents=True)
    sid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    def rollout(i):
        return native / ('rollout-2026-11-10T00-00-00-%08d-0000-0000-0000-000000000000.jsonl' % i)
    def write(path, rows, tail=b''):
        path.write_bytes(b''.join((json.dumps(row) + '\n').encode() for row in rows) + tail)
        os.utime(path, ns=(1700000000000000000, 1700000000000000000))
    def scan_case(path, query='needle'):
        add('scan/' + path.name, {'op': 'scan', 'input': str(path), 'query': query}, snapshot(extract.scan(str(path), query)))
    # A real native rollout must retain the searchable message despite tool
    # arguments/results containing lone surrogates and explicit message IDs.
    path = rollout(1)
    rows = [{'type': 'session_meta', 'payload': {'id': codex.ROLLOUT_RE.fullmatch(path.name).group(1), 'cwd': '/work', 'source': 'cli'}},
            {'type': 'response_item', 'payload': {'type': 'message', 'id': 'message', 'role': 'user', 'content': 'needle'}},
            {'type': 'response_item', 'payload': {'type': 'function_call', 'id': 'call1', 'arguments': {'cmd': 'x\ud800'}}},
            {'type': 'response_item', 'payload': {'type': 'function_call_output', 'id': 'out1', 'output': ['\udc80']}}]
    write(path, rows)
    scan_case(path)
    for rec in rows[2:]:
        add('tool-codepoints', {'op': 'normalize_full', 'input': rec}, sc.normalize(rec))
    # Non-dict lines never advance the inherited-history ordinal.
    path = rollout(2)
    write(path, [{'type': 'session_meta', 'payload': {'id': codex.ROLLOUT_RE.fullmatch(path.name).group(1), 'cwd': '/work', 'source': 'cli', 'ccs_index_start_ordinal': 2}}, [],
                 {'type': 'response_item', 'payload': {'type': 'message', 'id': 'inherited', 'role': 'user', 'content': 'needle'}}])
    scan_case(path)
    for i, cwd in enumerate(['/work', '/w\ud800']):
        path = rollout(i + 10)
        meta = {'id': codex.ROLLOUT_RE.fullmatch(path.name).group(1), 'cwd': cwd, 'source': 'cli', 'unknown': 0}
        for _ in range(300):
            meta['unknown'] = [meta['unknown']]
        write(path, [{'type': 'session_meta', 'payload': meta}])
        add('deep-metadata', {'op': 'metadata', 'input': str(path)}, codex.metadata(str(path)))
        add('metadata-classify', {'op': 'classify', 'input': str(path)}, codex.classify(str(path)))
        add('metadata-find', {'op': 'find_local', 'input': meta['id'], 'hint': str(path)}, codex.find_local(meta['id'], str(path)))
    for i, encoding in enumerate(['utf-8', 'utf-8-sig', 'utf-16-be', 'utf-16-le', 'utf-32-be', 'utf-32-le']):
        path = rollout(20 + i)
        raw = json.dumps({'type': 'session_meta', 'payload': {'id': 'x', 'cwd': '/w\ud800'}}, ensure_ascii=False)
        path.write_bytes((raw + '\n').encode(encoding, 'surrogatepass'))
        add('metadata-encoding/' + encoding, {'op': 'metadata', 'input': str(path)}, codex.metadata(str(path)))
    path = project / (sid + '.jsonl')
    write(path, [user('needle first', cwd='/first', entrypoint='cli'), user('needle second', cwd='/second'), {'type': 'custom-title', 'customTitle': 'long ' * 40}], tail=json.dumps(user('needle partial')).encode())
    scan_case(path)
    headless = project / 'headless.jsonl'
    write(headless, [user('needle', cwd='/headless', entrypoint='sdk')])
    for opts in [{'query': 'needle', 'exclude_session_id': sid}, {'query': 'needle', 'since_epoch': 1700000001}, {'query': 'needle'}, {'query': 'needle', 'include_headless': True}]:
        add('search-filters', {'op': 'search', 'input': opts}, [snapshot(s) for s in fallback.search(**opts)])
    # Keep the old file first so a nanosecond quantization tie reverses the result.
    older, newer = project / 'older.txt', project / 'newer.txt'
    older.touch(); newer.touch()
    for path, ns in [(older, 1700000000000001550), (newer, 1700000000000001789)]:
        os.utime(path, ns=(ns, ns))
    assert older.stat().st_mtime < newer.stat().st_mtime
    add('mtime-order', {'op': 'newest', 'input': [str(older), str(newer)]}, fallback._newest([str(older), str(newer)], None))
    for path, root in [(project / 'missing', project), (project / 'missing/../present', project), (project, project), (project, Path('/')), (project / 'missing/child', project / 'missing')]:
        add('non-strict-realpath', {'op': 'is_within', 'input': str(path), 'root': str(root)}, util.is_within(str(path), str(root)))
    count += check(cases)
    # D5 only warns for a relevant transcript, including one below a byte path.
    log = Path(util.log_path())
    log.unlink(missing_ok=True)
    for parent in [project, native]:
        os.mkdir(os.fsencode(parent) + b'/irrelevant-\xff')
        with open(os.fsencode(parent) + b'/irrelevant-\xff.txt', 'wb') as f:
            f.write(b'ignored')
    run_requests([{'op': 'main_files', 'input': str(project.parent)}, {'op': 'paths'}])
    assert not log.exists(), 'irrelevant byte paths emitted WARN'
    byte_dir = os.fsencode(native) + b'/irrelevant-\xff'
    with open(byte_dir + b'/rollout-2026-11-10T00-00-00-' + sid.encode() + b'.jsonl', 'wb') as f:
        f.write(b'{}\n')
    run_requests([{'op': 'paths'}])
    assert log.read_text().count(' WARN ') == 1, 'relevant byte path did not emit one WARN'
    log.unlink()
    run_requests([{'op': 'log', 'input': 'first\nsecond'}])
    assert log.read_text().endswith(' WARN first second\n') and len(log.read_text().splitlines()) == 1
    count += 3
assert failure_count == 0, '%d differential cases failed' % failure_count
print('PASS local review oracle: %d cases; real rollouts, timestamp quirks, saved state, metadata, path filtering and logs' % count)
