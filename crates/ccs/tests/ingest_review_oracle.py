"""Review regressions, real authentication, clock budgets and crash checkpoints."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


def review_cases(run, record_comparison, LINE, SID, SID2, scripted):
    def paths(f):
        for suffix in ('/.', '//.'):
            for mode in ('sweep', 'backfill'):
                f.reset()
                env = dict(f.env, HOME=str(f.home) + suffix)
                f.pair('path-home-' + mode + suffix, [mode], env=env)
        f.reset()
        env = dict(f.env, HOME=str(f.home).replace('/ccs-ingest-', '//ccs-ingest-'))
        f.pair('path-interior-slash', ['sweep'], env=env)
        sub = f.path.with_suffix('') / 'subagents/agent-review.jsonl'
        sub.parent.mkdir(parents=True)
        sub.write_bytes(LINE)
        f.reset()
        f.pair('relative-file-subagent-state', ['file', str(f.path.relative_to(f.home)), '--with-subagents'])
        actual = json.loads(f.state.read_text())['files']
        assert str(sub.relative_to(f.home)) in actual
    run('review_paths', paths)

    def numeric(f):
        for name, status, raw, requests in [
            ('negative-zero-next', 200, b'{"next_offset":-0}', 2),
            ('huge-next', 200, b'{"next_offset":18446744073709551616}', 1),
            ('larger-next', 200, b'{"next_offset":' + b'9' * 100 + b'}', 1),
            ('huge-resync', 409, b'{"expected_offset":18446744073709551616}', 1),
            ('negative-zero-resync', 409, b'{"expected_offset":-0}', 2),
        ]:
            f.reset()
            result = f.pair(name, factory=scripted(status, raw))
            assert len(result['requests']) == requests
        f.seed(offset=True)
        f.pair('boolean-offset-restored-after-resync', factory=scripted(409, {'expected_offset': 2**64}))
        for generation in [2.5, -2.5, '3', ' +1_002 ', '٣', 2**100, 1e100, None]:
            f.seed(inode=0, generation=generation)
            result = f.pair('generation-coercion-' + repr(generation))
            assert result['exit'] == (1 if generation is None else 0)
        for reset in (False, True):
            f.seed(inode=0 if reset else f.path.stat().st_ino)
            state = json.loads(f.state.read_text())
            del state['files'][str(f.path)]['generation']
            f.state.write_text(json.dumps(state))
            result = f.pair('missing-generation-reset-' + str(reset))
            assert result['exit'] == (0 if reset else 1)
        f.seed(offset=True)
        result = f.pair('boolean-offset-retained')
        assert json.loads(result['requests'][0][3])['segment']['offset'] is True
    run('review_numbers', numeric)

    def responses(f):
        for label, status, prefix in [
            ('deep-success-response', 200, b'{"session_key":"deep",'),
            ('deep-resync-response', 409, ('{"expected_offset":%d,' % len(LINE)).encode()),
        ]:
            f.path.write_bytes(LINE * 2)
            f.reset()
            raw = prefix + b'"unused":' + b'[' * 300 + b'0' + b']' * 300 + b'}'
            result = f.pair(label, factory=scripted(status, raw))
            assert result['exit'] == 0
            assert len(result['requests']) == (2 if status == 409 else 1)
            if status == 200:
                assert json.loads(f.state.read_text())['files'][str(f.path)]['session_key'] == 'deep'
    run('review_responses', responses)

    def blobs(f):
        folder = f.path.with_suffix('') / 'tool-results'
        folder.mkdir(parents=True)
        blob = folder / 'toolu_review.txt'
        blob.write_bytes(b'A' * 1_000_001)
        result = f.pair('MA-blob-value-cap')
        assert json.loads(result['requests'][1][3])['content'] == '[REDACTED:oversize]'
        blob.write_bytes(b'ordinary blob')
        f.seed(inode=0, blobs={blob.name: hashlib.sha256(blob.read_bytes()).hexdigest()})
        result = f.pair('MB-rotation-resends-unchanged-blob')
        assert len(result['requests']) == 2
        for sent in ([1], None, 'invalid'):
            f.seed(offset=len(LINE), blobs=sent)
            result = f.pair('malformed-blob-state-' + repr(sent))
            assert result['exit'] == 1 and not result['requests']
        for files in ([], None, 'invalid'):
            f.state.write_text(json.dumps({'version': 1, 'files': files}))
            f.pair('MF-invalid-files-' + repr(files), ['sweep'])
    run('review_blobs', blobs)

    def symlink(f):
        actual = f.project / SID2 / 'subagents'
        actual.mkdir(parents=True)
        (actual / 'agent-linked.jsonl').write_bytes(LINE)
        session = f.path.with_suffix('')
        session.mkdir()
        (session / 'subagents').symlink_to(actual, target_is_directory=True)
        result = f.pair('ME-symlinked-subagents', ['file', str(f.path), '--with-subagents'])
        assert len(result['requests']) == 1
    run('review_symlink', symlink)

    def non_utf8(f):
        f.path.unlink()
        name = os.fsencode(f.project) + b'/\xff-' + SID.encode() + b'.jsonl'
        with open(name, 'wb') as out:
            out.write(LINE)
        py = f.capture(f.commands(['sweep'])[0], lambda req: (200, {}, {}))
        f.reset()
        rust = f.capture(f.commands(['sweep'])[1], lambda req: (200, {}, {}))
        record_comparison('D5-invalid-UTF8-name', py, rust)
        assert py['exit'] == 1 and rust['exit'] == 0
        assert not rust['requests'] and not json.loads(rust['state'])['files']
        assert rust['warnings'] == ['ingest: non-UTF-8 name skipped'], 'non-UTF8 name needs exactly one WARN'
        print('PASS D5-invalid-UTF8-name skipped with exactly one WARN', flush=True)
    run('review_names', non_utf8)

    def warnings(f):
        f.path.write_bytes(b'{"v":"\\ud800"}\n' + LINE)
        result = f.pair('surrogate-warning')
        assert result['warnings'] == ['ingest: surrogate at offset 0 -> tombstoned']
        f.reset()
        result = f.pair('422-warning-detail', factory=scripted(422, {'lines': [1], 'kinds': ['example', '日本']}))
        assert any('lines=[1] kinds=example,日本 -> tombstoned' in line for line in result['warnings'])
    run('review_warnings', warnings)

    def auth(f):
        secret = f.home / 'client.secret'
        secret.write_text('synthetic-client-secret')
        secret.chmod(0o600)
        f.config.parent.chmod(0o700)
        f.settings['auth'] = dict(type='client_credentials', token_url=f.server.base + '/token', client_id='synthetic-client', secret_file=str(secret))
        f.config.write_text(json.dumps(f.settings))
        def clear_cache():
            for p in f.config.parent.glob('token*.json'):
                p.unlink()
        def response_factory(rejections, same=False, token_status=200):
            def factory():
                clear_cache()
                tokens = ingests = 0
                def handler(req):
                    nonlocal tokens, ingests
                    if req['path'] == '/token':
                        tokens += 1
                        return token_status, dict(access_token='synthetic-bearer-' + str(1 if same else tokens), expires_in=3600), {}
                    ingests += 1
                    if ingests <= rejections:
                        return 401, {}, {}
                    return 200, dict(session_key='auth', next_offset=req['body']['segment']['end_offset']), {}
                return handler
            return factory
        for label, rejects, status in [('new-bearer-retry', 1, 200), ('401-twice', 2, 200), ('token-500', 0, 500)]:
            f.reset()
            f.pair(label, factory=response_factory(rejects, token_status=status))
        f.reset()
        other = f.project / (SID2 + '.jsonl')
        other.write_bytes(LINE)
        os.utime(other, (100, 100)); os.utime(f.path, (200, 200))
        py = f.capture(f.commands(['sweep'])[0], response_factory(1, same=True)())
        f.reset()
        rust = f.capture(f.commands(['sweep'])[1], response_factory(1, same=True)())
        record_comparison('D8-rejected-bearer-never-reused', py, rust)
        assert py['exit'] == 0 and rust['exit'] == 3
        assert [r[1] for r in rust['requests']] == ['/token', '/memory/sessions/v1/ingest', '/token']
        assert rust['requests'] == py['requests'][:3]
        assert json.loads(rust['state'])['files'][str(f.path)]['offset'] == 0
        assert str(other) not in json.loads(rust['state'])['files'], 'remaining files must be held after auth failure' 
        print('PASS D8-rejected-bearer-never-reused cursor held; exit 3', flush=True)
    run('review_auth', auth)

    def budgets(f):
        library = f.home / 'clock.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', str(Path(__file__).with_name('ingest_clock.c')), '-ldl', '-o', str(library)], check=True, capture_output=True)
        offset = f.home / 'clock-offset'
        offset.write_text('0')
        env = dict(f.env, LD_PRELOAD=str(library), CCS_TEST_CLOCK_FILE=str(offset))
        check = subprocess.Popen([sys.executable, '-c', 'import time,sys; print(time.monotonic(),time.time(),flush=True); sys.stdin.readline(); print(time.monotonic(),time.time(),flush=True)'], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        first = list(map(float, check.stdout.readline().split()))
        offset.write_text('100')
        check.stdin.write(b'go\n'); check.stdin.flush()
        second = list(map(float, check.stdout.readline().split()))
        check.stdin.close(); check.stdout.close(); check.wait(timeout=5)
        assert 99 < second[0]-first[0] < 102 and 0 <= second[1]-first[1] < 2, 'clock shim control'
        for i in range(5):
            sub = f.path.with_suffix('') / ('subagents/agent-%d.jsonl' % i)
            sub.parent.mkdir(parents=True, exist_ok=True)
            sub.write_bytes(LINE)
            os.utime(sub, (100+i, 100+i))
        os.utime(f.path, (110, 110))
        for mode, seconds, count in [('file', 6, 4), ('sweep', 31, 4), ('backfill', 31, 6)]:
            def factory():
                offset.write_text('0')
                sends = 0
                def handler(req):
                    nonlocal sends
                    sends += 1
                    offset.write_text(str(sends * seconds))
                    return 200, dict(session_key='budget', next_offset=req['body']['segment']['end_offset']), {}
                return handler
            f.reset()
            args = ['file', str(f.path), '--with-subagents'] if mode == 'file' else [mode]
            result = f.pair('MC-MD-budget-' + mode, args, factory=factory, env=env)
            assert len(result['requests']) == count
    run('review_budgets', budgets)

    def checkpoint(f):
        # At most one of these lines fits in a raw segment. Hold the second
        # response, observe the first persisted cursor, then SIGKILL the client.
        line = b'{"value":"' + b'A' * 2_200_000 + b'"}\n'
        f.path.write_bytes(line * 2)
        snapshots = []
        for command in f.commands(['file', str(f.path)]):
            f.reset()
            entered, release = threading.Event(), threading.Event()
            count = 0
            def handler(req):
                nonlocal count
                count += 1
                if count == 2:
                    entered.set()
                    assert release.wait(30), 'checkpoint release timeout'
                return 200, dict(session_key='checkpoint', next_offset=req['body']['segment']['end_offset']), {}
            f.server.requests.clear(); f.server.handler = handler
            process = subprocess.Popen(command, cwd=f.home, env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert entered.wait(25), 'second segment not observed'
                process.kill(); process.communicate(timeout=5)
                assert f.state.exists(), 'MG acknowledged cursor not checkpointed'
                state = json.loads(f.state.read_text())
                assert state['files'][str(f.path)]['offset'] == len(line), 'MG wrong checkpoint offset'
                state['files'][str(f.path)]['last_ok'] = '<call-time>'
                snapshots.append(state)
            finally:
                release.set()
                if process.poll() is None:
                    process.kill(); process.communicate(timeout=5)
        assert snapshots[0] == snapshots[1], 'checkpoint state mismatch'
        print('PASS MG-SIGKILL-between-acks Python/Rust state identical offset=%d' % len(line), flush=True)
    run('review_checkpoint', checkpoint)
