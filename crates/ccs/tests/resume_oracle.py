#!/usr/bin/env python3
"""Compare resume functions in real processes, with identical filesystem inputs.

The only normalization is wall-clock timestamps. Each case compares exit status,
stdout/stderr, every file's bytes and mode, HTTP requests, and exec argv/cwd/env.
The fake agents replace the process and deliberately return 17. No real services,
credentials or agent binaries are used. Pass --evidence to retain both observations.
"""
import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import resume_review_cases
from resume_review_cases import CASES as REVIEW_CASES, BASE_CASE, D5_CASES, amend_fixture

REPO = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(REPO), str(REPO / 'tests')]
from support import FakeServer, SID, SID2

PYTHON = r'''
import importlib.util, json, os, sys
from pathlib import Path
repo = Path(sys.argv[1]); sys.path.insert(0, str(repo))
spec = importlib.util.spec_from_file_location('ccs.session_codex', repo / 'vendor/memory-mcp/session_codex.py')
module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
from ccs import resume
req = json.loads(sys.argv[2])
if req.get('close_stderr'): os.close(2)
try:
    code = resume.resume(req['session_key'], do_print=req.get('print', False), fork=req.get('fork', False), to_dir=req.get('to_dir'), force=req.get('force', False))
except OSError:
    # Compare the function's I/O error status, without CPython's additional
    # interpreter-shutdown flush failure (120) on the already closed stream.
    if req.get('close_stderr'): os._exit(1)
    raise
raise SystemExit(code)
'''


def encoded(path):
    return re.sub('[^A-Za-z0-9-]', '-', str(path))


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def rows(*values):
    return ''.join(json.dumps(v, ensure_ascii=True) + '\n' for v in values).encode()


def tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as archive:
        for name, kind, data, mode in members:
            entry = tarfile.TarInfo(name)
            entry.mode = mode
            entry.type = kind
            entry.linkname = '/outside'
            entry.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(entry, io.BytesIO(data))
    return buf.getvalue()


# D11 rejects these formats before touching the tool-results destination.
D11_CASES = {
    'restore-bzip2-tools': 'bzip2',
    'restore-xz-tools': 'xz',
    'restore-bzip2-existing-tools': 'bzip2',
    'restore-xz-existing-tools': 'xz',
    'restore-lzma-alone': 'xz',
    'restore-lzma-alone-existing': 'xz',
}

# (name, expected Python status). The fixture defines each independent input.
CASES = [(n, code) for n, code in [
    ('restore', 17), ('restore-closed-stderr', 1), ('restore-print', 0), ('restore-fork', 17),
    ('restore-utf8-replace', 17), ('restore-bad-project', 17),
    ('restore-gzip-tools', 17), ('restore-no-tools', 17), ('restore-empty-tools', 17),
    ('restore-bzip-prefix-tools', 17),
    *[(name, 17) for name in D11_CASES],
    ('restore-tool-mode', 17), ('restore-missing-to', 4), ('restore-print-needs-to', 4),
    ('restore-invalid-to', 4), ('restore-tilde-to', 17), ('restore-relative-to', 17),
    ('restore-username-to', 17), ('restore-symlink-to', 17), ('restore-sha', 4), ('restore-sha-missing', 4),
    ('restore-conflict', 4), ('restore-http', 4), ('restore-tools-http', 4),
    ('restore-existing', 4), ('restore-force', 17), ('restore-identical', 17),
    ('restore-stale-tmp', 17), ('restore-tmp-directory', 1),
    ('restore-target-link', 4), ('restore-project-link', 4), ('restore-session-link', 4),
    ('restore-tools-link', 4), ('restore-member-inside-link', 17), ('restore-member-dangling-link', 17), ('restore-member-link', 1), ('restore-tar-invalid', 1),
    ('restore-tar-traversal', 4), ('restore-tar-absolute', 4), ('restore-tar-directory', 4),
    ('restore-tar-symlink', 4), ('restore-tar-hardlink', 4), ('restore-tar-hidden', 4),
    ('restore-tar-late-invalid', 4), ('restore-tar-newline', 17),
    ('restore-concurrent-state', 17), ('restore-record-preserve', 17), ('restore-record-invalid', 17),
    ('restore-tty-no', 17), ('restore-tty-yes', 17), ('restore-tty-other', 17),
    ('local', 17), ('local-print', 0), ('local-fork', 17), ('local-to', 17),
    ('local-to-mismatch', 4), ('local-missing', 4), ('local-recorded-mismatch', 4),
    ('local-relocated', 17), ('local-collision', 4), ('local-collision-to', 17),
    ('local-cwd-link', 4), ('local-file-link', 4), ('local-parent-link', 4),
    ('local-restored', 17), ('local-restored-gone', 4), ('local-restored-ignores-to', 17),
    ('local-restored-bool-version', 17), ('local-malformed-lines', 17),
    ('local-long-line', 17), ('local-surrogate', 4), ('local-home-slash', 17),
    ('local-home-empty', 4), ('local-home-unset', 4), ('local-deep-line', 1),
    ('local-no-config', 17), ('local-no-agent', 4), ('local-agent-permission', 1),
    ('remote-local', 17), ('remote-local-scan', 17), ('remote-ignores-cwd', 17),
    ('remote-unsafe-hint', 17), ('remote-view-only', 4), ('remote-subagent', 4),
    ('remote-incomplete', 4), ('remote-missing-local', 4), ('remote-unknown', 4), ('remote-closed-stderr', 1),
    ('remote-http', 3), ('remote-invalid-id', 4), ('remote-newline-id', 17),
    ('remote-null-id', 4), ('remote-invalid-config', 3), ('remote-no-config', 3),
    ('codex-local', 17), ('codex-local-print', 0), ('codex-local-fork', 17),
    ('codex-local-to', 17), ('codex-local-relative-to', 4), ('codex-local-missing', 4),
    ('codex-local-cwd-link', 17), ('codex-local-file-link', 4),
    ('codex-remote-local', 17), ('codex-restore', 17), ('codex-print', 0),
    ('codex-paginated', 17), ('codex-display', 17), ('codex-fork', 17),
    ('codex-subagent', 17), ('codex-boundary', 17), ('codex-ancestor', 17),
    ('codex-empty-owned', 17), ('codex-sha', 4), ('codex-http', 4),
    ('codex-duplicate', 4), ('codex-bad-id', 4), ('codex-bad-type', 4),
    ('codex-array-record', 4), ('codex-empty', 4), ('codex-utf8', 4),
    ('codex-surrogate', 4), ('codex-existing', 4), ('codex-force', 17),
    ('codex-root-link', 4), ('codex-date-link', 4),
]]
CASES += REVIEW_CASES


def fixture(root, name, base):
    home = root / 'home'; home.mkdir(parents=True)
    cwd = home / "work space's" / '日本'; cwd.mkdir(parents=True)
    other = home / 'other'; other.mkdir()
    projects = home / '.claude/projects'
    target = projects / encoded(cwd) / (SID + '.jsonl')
    tr = target.parent / SID / 'tool-results'
    state = home / '.claude/session-search/restored.json'
    native = home / '.codex/sessions/2020/01/02' / ('rollout-2020-01-02T03-04-05-' + SID + '.jsonl')
    bindir = root / 'bin'; bindir.mkdir()
    config = home / 'config.json'
    write(config, json.dumps(dict(endpoint=base, host_label='local', auth={'type': 'tailnet'}, hmac_key_file=str(home / 'unused'))))
    for agent in ('claude', 'codex'):
        script = bindir / agent
        write(script, '#!' + sys.executable + '\nimport json, os, sys\n'
              'with open(os.environ["CCS_EXEC_LOG"], "w") as f:\n'
              ' json.dump(dict(argv=[os.path.basename(sys.argv[0])]+sys.argv[1:], cwd=os.getcwd(), env=dict(os.environ)), f, sort_keys=True)\n'
              'raise SystemExit(17)\n')
        script.chmod(0o755)
    env = dict(HOME=str(home), CODEX_HOME=str(home / '.codex'), CCS_CONFIG=str(config),
               CCS_EXEC_LOG=str(home / 'exec.json'), PATH=str(bindir), LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', NO_PROXY='*', CLAUDE_CODE_SESSION_ID='caller',
               CODEX_THREAD_ID='caller-thread', CCS_RESUME_SENTINEL='preserve this environment')
    req = dict(session_key='remote-key', to_dir=str(cwd))
    meta = dict(session_id=SID, host='remote', project_dir='-old-project', resume_cwd=str(other),
                archived=True, archive_complete=True, entrypoint='cli', jsonl_exists=True)
    original_path = '/home/old/.claude/projects/-old-project/' + SID + '/tool-results/out.txt'
    body = rows(dict(type='user', cwd='/untrusted', message={'content': 'history ' + original_path}),
                dict(type='assistant', message={'content': 'reply'}))
    tools = tar([('out.txt', tarfile.REGTYPE, b'tool contents\n', 0o644)])
    preview_status = archive_status = tool_status = 200
    sha = None
    answers = None
    initial = rows(dict(type='user', cwd=str(cwd), message={'content': 'local text'}))
    if name.startswith('local') or name in ('remote-local', 'remote-local-scan', 'remote-ignores-cwd', 'remote-unsafe-hint'):
        write(target, initial)
        req = dict(session_key='local:' + str(target))
        if name.startswith('remote'):
            req['session_key'] = 'remote-key'; meta.update(host='local', jsonl_path=str(target))
        if name == 'remote-local-scan': meta.pop('jsonl_path')
        if name == 'remote-unsafe-hint': meta['jsonl_path'] = str(other / (SID + '.jsonl'))
        if name.endswith('print'): req['print'] = True
        if name.endswith('fork'): req['fork'] = True
        if name == 'local-to': req['to_dir'] = str(cwd)
        if name == 'local-to-mismatch': req['to_dir'] = str(other)
        if name == 'local-missing': target.unlink()
        if name == 'local-recorded-mismatch': write(target, rows(dict(type='user', cwd=str(other))))
        if name == 'local-relocated': write(target, rows(dict(type='user', cwd='/gone', relocatedCwd=str(cwd))))
        if name.startswith('local-collision'):
            collision = Path(str(cwd).replace("work space's/日本", 'work-space-s---'))
            collision.mkdir()
            assert encoded(collision) == encoded(cwd)
            write(target, rows(dict(type='user', cwd=str(cwd), relocatedCwd=str(collision))))
            if name.endswith('-to'): req['to_dir'] = str(cwd)
        if name == 'local-cwd-link':
            moved = home / 'moved'; cwd.rename(moved); cwd.symlink_to(moved)
        if name == 'local-file-link':
            saved = home / 'saved'; target.rename(saved); target.symlink_to(saved)
        if name == 'local-parent-link':
            saved = projects / 'saved'; target.parent.rename(saved); target.parent.symlink_to(saved)
        if name.startswith('local-restored'):
            write(target, rows(dict(type='user', cwd=str(other))))
            rec_cwd = str(cwd) if name != 'local-restored-gone' else str(home / 'gone')
            version = True if name.endswith('bool-version') else 1
            write(state, json.dumps(dict(version=version, sessions={encoded(cwd) + '/' + SID: {'cwd': rec_cwd}})))
            if name.endswith('ignores-to'): req['to_dir'] = str(other)
        if name == 'local-malformed-lines': write(target, b'{bad}\n\xff\n' + initial)
        if name == 'local-long-line': write(target, rows(dict(type='user', cwd=str(cwd), message={'content': 'a' * 1100000})))
        if name == 'local-surrogate': write(target, b'{"type":"user","cwd":"\\ud800"}\n' + initial)
        if name == 'local-home-slash': env['HOME'] += '///'
        if name == 'local-home-empty': env['HOME'] = ''
        if name == 'local-home-unset': env.pop('HOME')
        if name == 'local-deep-line': write(target, b'{"unused":' + b'[' * 12000 + b'0' + b']' * 12000 + b'}\n' + initial)
        if name == 'local-no-config': config.unlink()
        if name == 'local-no-agent': (bindir / 'claude').unlink()
        if name == 'local-agent-permission': (bindir / 'claude').chmod(0o600)
    if name.startswith('remote-'):
        if name == 'remote-view-only': meta['archived'] = False
        if name == 'remote-subagent': meta.update(archived=False, kind='subagent')
        if name == 'remote-incomplete': meta['archive_complete'] = False
        if name == 'remote-missing-local': meta.update(host='local', archived=False)
        if name in ('remote-unknown', 'remote-closed-stderr'): preview_status = 404
        if name == 'remote-http': preview_status = 503
        if name == 'remote-invalid-id': meta['session_id'] = '../escape'
        if name == 'remote-newline-id': meta['session_id'] += '\n'
        if name == 'remote-null-id': meta['session_id'] = None
        if name == 'remote-invalid-config': write(config, '{}')
        if name == 'remote-no-config': config.unlink()
    if name.startswith('restore'):
        if name == 'restore-print': req['print'] = True
        if name == 'restore-fork': req['fork'] = True
        if name == 'restore-utf8-replace': body += b'\xff\xed\xa0\x80\n'
        if name == 'restore-bad-project': meta['project_dir'] = '../../escape'
        if name == 'restore-gzip-tools': tools = gzip.compress(tools)
        if name == 'restore-bzip-prefix-tools': tools = tar([('BZh9report.txt', tarfile.REGTYPE, b'plain tar', 0o644)])
        if name in D11_CASES:
            tools = (bz2.compress if D11_CASES[name] == 'bzip2' else lzma.compress)(tools)
            if 'existing' in name: write(tr / 'out.txt', 'keep existing output')
        if name == 'restore-no-tools': tool_status = 404
        if name == 'restore-empty-tools': tools = b''
        if name == 'restore-tool-mode': tools = tar([('out.txt', tarfile.REGTYPE, b'tool', 0o6777), ('user.txt', tarfile.REGTYPE, b'u', 0o0055)])
        if name in ('restore-missing-to', 'restore-print-needs-to'): req.pop('to_dir')
        if name == 'restore-print-needs-to': req['print'] = True
        if name == 'restore-invalid-to': req['to_dir'] = str(home / 'missing')
        if name == 'restore-tilde-to': req['to_dir'] = '~/' + str(cwd.relative_to(home))
        if name == 'restore-username-to': req['to_dir'] = '~' + pwd.getpwuid(os.getuid()).pw_name
        if name == 'restore-relative-to': req['to_dir'] = str(cwd.relative_to(home))
        if name == 'restore-symlink-to':
            alias = home / 'alias'; alias.symlink_to(cwd); req['to_dir'] = str(alias)
        if name == 'restore-sha': sha = '0' * 64
        if name == 'restore-sha-missing': sha = ''
        if name == 'restore-conflict': archive_status = 409; body = b'{"error":"incomplete"}'
        if name == 'restore-http': archive_status = 502
        if name == 'restore-tools-http': tool_status = 503
        if name in ('restore-existing', 'restore-force'): write(target, '{}\n')
        if name == 'restore-force': req['force'] = True
        if name == 'restore-identical': write(target, body.replace(original_path.encode(), str(tr / 'out.txt').encode()))
        if name == 'restore-stale-tmp': write(Path(str(target) + '.tmp'), 'old temporary data')
        if name == 'restore-tmp-directory': Path(str(target) + '.tmp').mkdir(parents=True)
        links = {'restore-target-link': target, 'restore-project-link': target.parent,
                 'restore-session-link': tr.parent, 'restore-tools-link': tr}
        if name in links:
            p = links[name]; p.parent.mkdir(parents=True, exist_ok=True); p.symlink_to(other)
        if name == 'restore-member-link':
            tr.mkdir(parents=True); write(other / 'victim', 'unchanged'); (tr / 'out.txt').symlink_to(other / 'victim')
        if name in ('restore-member-inside-link', 'restore-member-dangling-link'):
            tr.mkdir(parents=True); (tr / 'out.txt').symlink_to(tr / 'other.txt')
            if name == 'restore-member-inside-link': write(tr / 'other.txt', 'old data')
        if name == 'restore-tar-invalid': tools = b'not a tar'
        bad = {'restore-tar-traversal': ('../escape', tarfile.REGTYPE),
               'restore-tar-absolute': ('/escape', tarfile.REGTYPE),
               'restore-tar-directory': ('dir', tarfile.DIRTYPE),
               'restore-tar-symlink': ('link', tarfile.SYMTYPE),
               'restore-tar-hardlink': ('link', tarfile.LNKTYPE),
               'restore-tar-hidden': ('.hidden', tarfile.REGTYPE),
               'restore-tar-newline': ('out.txt\n', tarfile.REGTYPE)}
        if name in bad: tools = tar([(*bad[name], b'bad', 0o644)])
        if name == 'restore-tar-late-invalid': tools = tar([('first', tarfile.REGTYPE, b'not written', 0o644), ('../escape', tarfile.REGTYPE, b'bad', 0o644)])
        if name == 'restore-record-preserve': write(state, json.dumps(dict(version=1, extra='keep', sessions={'other/session': {'cwd': '/other'}})))
        if name == 'restore-record-invalid': write(state, '{"version":2,"sessions":[]}')
        if name.startswith('restore-tty'):
            req.pop('to_dir')
            answers = {'restore-tty-no': b'n\n\n', 'restore-tty-yes': b'y\n', 'restore-tty-other': ('n\n' + str(cwd) + '\n').encode()}[name]
    if name.startswith('codex'):
        meta['entrypoint'] = 'codex-cli'
        header = dict(type='session_meta', payload=dict(id=SID, cwd='/untrusted', source='cli', custom='keep'))
        user = dict(type='response_item', timestamp='2025-01-01T00:00:00Z', payload=dict(type='message', role='user', content=[{'type':'input_text', 'text':'question'}]))
        reply = dict(type='response_item', payload=dict(type='message', role='assistant', content=[{'type':'output_text', 'text':'answer'}]))
        records = [header, dict(type='turn_context', payload={'cwd':'/unsafe', 'approval_policy':'never'}),
                   dict(type='world_state', payload={'settings':'unsafe'}),
                   dict(type='event_msg', payload={'type':'thread_settings_applied', 'thread_id':SID}), user,
                   dict(type='response_item', payload=dict(type='message', role='assistant', channel='analysis', content='private reasoning')), reply]
        if name.startswith('codex-local') or name == 'codex-remote-local':
            header['payload']['cwd'] = str(cwd)
            write(native, rows(header, user))
            req = dict(session_key='local:' + str(native))
            if name == 'codex-remote-local': req['session_key'] = 'remote-key'; meta.update(host='local', jsonl_path=str(native))
            if name.endswith('print'): req['print'] = True
            if name.endswith('fork'): req['fork'] = True
            if name == 'codex-local-to': req['to_dir'] = str(other)
            if name == 'codex-local-relative-to': req['to_dir'] = 'other'
            if name == 'codex-local-missing': native.unlink()
            if name == 'codex-local-cwd-link': cwd.rmdir(); cwd.symlink_to(other)
            if name == 'codex-local-file-link': saved = home / 'saved'; native.rename(saved); native.symlink_to(saved)
        if name == 'codex-print': req['print'] = True
        if name in ('codex-display', 'codex-paginated'):
            records.insert(4, dict(type='event_msg', payload=dict(type='user_message', message='existing display')))
        if name == 'codex-paginated': header['payload']['history_mode'] = 'paginated'
        if name in ('codex-fork', 'codex-ancestor', 'codex-empty-owned'):
            header['payload']['forked_from_id'] = SID2
            records.insert(1, dict(type='response_item', payload=dict(type='message', role='user', content='ancestor message')))
        if name == 'codex-ancestor': records.insert(2, dict(type='session_meta', payload=dict(id=SID2, cwd='/ancestor')))
        if name == 'codex-empty-owned': records = records[:3]
        if name == 'codex-subagent': header['payload']['subagent_history_start_ordinal'] = 4
        if name == 'codex-boundary': header['payload']['ccs_index_start_ordinal'] = 5
        if name == 'codex-bad-id': header['payload']['id'] = SID2
        if name == 'codex-bad-type': header['type'] = 'user'
        if name == 'codex-array-record': records.append([])
        if name == 'codex-surrogate': user['payload']['content'][0]['text'] = '\ud800'
        body = rows(*records)
        if name == 'codex-duplicate': body = body.replace(b'"custom": "keep"', b'"custom": "a", "custom": "b"')
        if name == 'codex-empty': body = b' \n\n'
        if name == 'codex-utf8': body += b'\xff\n'
        if name == 'codex-sha': sha = '0' * 64
        if name == 'codex-http': archive_status = 409
        if name in ('codex-existing', 'codex-force'):
            local_header = dict(type='session_meta', payload=dict(id=SID, cwd=str(cwd), source='cli'))
            write(native, rows(local_header))
            if name == 'codex-force': req['force'] = True
        if name == 'codex-root-link':
            p = home / '.codex/sessions'; p.parent.mkdir(); p.symlink_to(other)
        if name == 'codex-date-link':
            p = home / '.codex/sessions' / time.strftime('%Y', time.gmtime()); p.parent.mkdir(parents=True); p.symlink_to(other)
    sha = hashlib.sha256(body).hexdigest() if sha is None else sha
    response = dict(meta=meta, body=body, tools=tools, sha=sha,
                    preview_status=preview_status, archive_status=archive_status, tool_status=tool_status)
    if name.endswith('closed-stderr'): req['close_stderr'] = True
    return req, env, home, response, answers


_base_fixture = fixture
def fixture(root, name, base):
    return amend_fixture(root, name, base, _base_fixture(root, BASE_CASE.get(name, name), base), globals())


def snapshot(home, preserve_names=False):
    result = {}
    for path in sorted(home.rglob('*')):
        rel = str(path.relative_to(home))
        if not preserve_names:
            rel = re.sub(r'rollout-\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d-', 'rollout-TIME-', rel)
        if rel == '.rss': continue
        st = path.lstat()
        mtime = 'NOW' if st.st_mtime > 1700000000 else st.st_mtime_ns
        if path.is_symlink(): result[rel] = {'symlink': os.readlink(path)}
        elif path.is_dir(): result[rel] = dict(directory=True, mode=stat.S_IMODE(st.st_mode), mtime=mtime)
        elif path.is_file():
            if st.st_size > 1 << 20:
                with path.open('rb') as f: data = dict(sha256=hashlib.file_digest(f, 'sha256').hexdigest(), size=st.st_size)
            else:
                content = path.read_bytes()
                if rel.endswith('/restored.json'):
                    content = re.sub(rb'("restored_at": ")[^"]+', rb'\1TIME', content)
                data = dict(bytes=content.hex())
            result[rel] = dict(**data, mode=stat.S_IMODE(st.st_mode), mtime=mtime)
    return result


def run_process(command, env, home, answers, mask=0o022):
    if answers is None:
        return subprocess.run(command, env=env, cwd=home, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=15, umask=mask)
    master, slave = pty.openpty()
    try:
        with subprocess.Popen(command, env=env, cwd=home, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=mask) as proc:
            os.close(slave); slave = -1
            os.write(master, answers)
            try:
                out, err = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill(); out, err = proc.communicate()
                return subprocess.CompletedProcess(command, 124, out, err)
            return subprocess.CompletedProcess(command, proc.returncode, out, err)
    finally:
        os.close(master)
        if slave >= 0: os.close(slave)


def compare(probe, cases, evidence=None):
    observations = []; failures = []
    with tempfile.TemporaryDirectory(prefix='ccs-resume-') as temp:
        root = Path(temp) / 'sandbox'
        response = {}
        def handler(req):
            if req['path'].endswith('/token'):
                response['token_requests'] += 1
                return (200, {'access_token':'synthetic-resume-token', 'expires_in':3600}, {}) if response['token_requests'] == 1 else (500, {}, {})
            if req['path'].endswith('/preview'):
                return response['preview_status'], {'session':response['meta']}, {}
            if req['path'].endswith('/archive/tool-results'):
                if name == 'restore-concurrent-state':
                    write(root / 'home/.claude/session-search/restored.json', json.dumps(dict(version=1, sessions={'concurrent/session': {'cwd': '/other'}})))
                return response['tool_status'], response['tools'], {}
            if req['path'].endswith('/archive'):
                if name == 'restore-auth-refresh': return 401, {}, {}
                return response['archive_status'], response['body'], {'X-Archive-Sha256':response['sha']}
            return 404, {}, {}
        server = FakeServer(handler)
        original_do = server.httpd.RequestHandlerClass._do
        def network_failure(request):
            import urllib.parse
            url = urllib.parse.urlsplit(request.path)
            tools = url.path.endswith('/archive/tool-results')
            archive_request = url.path.endswith('/archive')
            if ((name == 'restore-archive-drop' and archive_request)
                    or (name == 'restore-archive-truncated' and archive_request)
                    or (name == 'restore-error-truncated' and archive_request)
                    or (name == 'restore-tools-error-truncated' and tools)
                    or (name in ('restore-tools-truncated', 'restore-tools-reset') and tools)):
                server.requests.append(dict(method=request.command, path=url.path,
                                            query=dict(urllib.parse.parse_qsl(url.query)), raw=b''))
                request.close_connection = True
                if name.endswith('-drop'):
                    request.connection.shutdown(socket.SHUT_RDWR); return
                data = response['tools' if tools else 'body']
                request.send_response(503 if 'error-truncated' in name else 200)
                request.send_header('Content-Length', str(len(data)+100))
                if archive_request: request.send_header('X-Archive-Sha256',response['sha'])
                request.end_headers(); request.wfile.write(data); request.wfile.flush()
                if name == 'restore-tools-reset':
                    import struct
                    time.sleep(0.1)
                    request.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                return
            original_do(request)
        server.httpd.RequestHandlerClass._do = network_failure
        server.httpd.RequestHandlerClass.do_GET = network_failure
        try:
            for name, expected_code in cases:
                resume_review_cases.TARGET_TIME = int(time.time())
                pair = []
                for engine in ('python', 'rust'):
                    if root.exists(): shutil.rmtree(root)
                    root.mkdir(mode=0o700)
                    req, env, home, response, answers = fixture(root, name, server.base)
                    preserve_names = name in ('codex-target-link', 'codex-target-directory')
                    before = snapshot(home, preserve_names)
                    if name in D11_CASES:
                        destination = home / '.claude/projects' / encoded(home / "work space's" / '日本') / SID / 'tool-results'
                        destination_existed = destination.exists()
                    arg = json.dumps(req)
                    command = [sys.executable, '-c', PYTHON, str(REPO), arg] if engine == 'python' else [str(probe), arg]
                    if name == 'restore-large-member':
                        command = [sys.executable, str(Path(__file__).with_name('resume_measure.py')), str(home/'.rss'), *command]
                    server.requests.clear()
                    # A pooled HTTP socket can reuse fd 2 after it was closed.
                    server.httpd.RequestHandlerClass.protocol_version = ('HTTP/1.1' if name.endswith('closed-stderr') else 'HTTP/1.0')
                    process_cwd = Path(os.fsdecode(bytes.fromhex(req['_process_cwd']))) if '_process_cwd' in req else home
                    result = run_process(command, env, process_cwd, answers, 0o002 if name == 'restore-umask' else 0o022)
                    observed = dict(exit=result.returncode, stdout=result.stdout.decode('utf-8', 'replace'),
                                    stderr=result.stderr.decode('utf-8', 'replace'), files=snapshot(home, preserve_names),
                                    http=[{k:r[k] for k in ('method','path','query','raw')} for r in server.requests])
                    for r in observed['http']: r['raw'] = r['raw'].hex()
                    if name in D11_CASES:
                        observed.update(initial_files=before, destination_existed=destination_existed,
                                        destination_exists=destination.exists())
                    if name in D5_CASES: observed['initial_files'] = before
                    if name == 'restore-large-member': observed['rss_kib'] = int((home/'.rss').read_text().splitlines()[-1])
                    pair.append(observed)
                python, rust = pair
                deviation = ''
                checks = {}
                check_python, check_rust = dict(python), dict(rust)
                if expected_code == 1 and name != 'local-deep-line':
                    # D6 changes diagnostics only. Status, side effects and requests still match.
                    deviation = 'D6'
                    if rust['stderr'] != ('' if name.endswith('closed-stderr') else 'ccs: internal error\n'):
                        check_rust['invalid_internal_diagnostic'] = rust['stderr']
                    check_python.pop('stderr'); check_rust.pop('stderr')
                if name == 'restore-archive-drop':
                    # Transport wording is owned by the HTTP boundary; preserve
                    # the reachability status, request trace and every side effect.
                    checks['transport_diagnostic'] = rust['stderr'].startswith('ccs: server unreachable: ') and rust['stderr'].count('\n') == 1
                    check_python.pop('stderr'); check_rust.pop('stderr')
                if name == 'restore-large-member':
                    checks['bounded_rss'] = 0 < rust['rss_kib'] < 80*1024 and 0 < python['rss_kib'] < 80*1024
                    check_python.pop('rss_kib'); check_rust.pop('rss_kib')
                if name in ('restore-tar-newline', 'remote-newline-id'):
                    deviation = 'D1'
                    passed = python['exit'] == 17 and rust['exit'] == 4 and 'exec.json' not in rust['files']
                    if name == 'remote-newline-id': passed &= len(rust['http']) == 1
                    else: passed &= not any(p.endswith('.jsonl') for p in rust['files'])
                elif name in D11_CASES:
                    deviation = 'D11'
                    reason = ('ccs: refusing tool-results archive: unsupported %s compression '
                              '(only uncompressed and gzip are supported)\n' % D11_CASES[name])
                    extracted = [v for p, v in python['files'].items() if p.endswith('/tool-results/out.txt')]
                    checks = dict(
                        python_extract=(python['exit'] == 17 and len(extracted) == 1
                                        and extracted[0]['bytes'] == b'tool contents\n'.hex()),
                        exit_4=rust['exit'] == 4, empty_stdout=rust['stdout'] == '',
                        one_line_reason=rust['stderr'] == reason,
                        http_requests=rust['http'] == python['http'],
                        no_writes={p:v for p,v in rust['files'].items() if not v.get('directory')} == {p:v for p,v in rust['initial_files'].items() if not v.get('directory')},
                        destination_metadata={p:v for p,v in rust['files'].items() if '/tool-results' in p} == {p:v for p,v in rust['initial_files'].items() if '/tool-results' in p},
                        destination_unchanged=rust['destination_exists'] == rust['destination_existed'])
                    passed = all(checks.values())
                elif name in D5_CASES:
                    deviation = 'D5'
                    checks = dict(python_exec=python['exit'] == 17, exit_4=rust['exit'] == 4,
                                  warning=rust['stderr'] == 'ccs: WARN: refusing non-UTF-8 resume cwd\n',
                                  no_writes=rust['files'] == rust['initial_files'])
                    passed = all(checks.values())
                elif name == 'local-deep-line':
                    deviation = 'D10'
                    passed = python['exit'] == 1 and 'RecursionError' in python['stderr'] and rust['exit'] == 17
                else:
                    passed = python['exit'] == expected_code and check_python == check_rust and all(checks.values())
                observation = dict(case=name, pass_=passed, deviation=deviation, checks=checks, python=python, rust=rust)
                observations.append(observation)
                if not passed:
                    failures.append(name)
                    print('FAIL', name, 'expected', expected_code, 'exit', python['exit'], rust['exit'])
                    if checks: print('  failed checks:', [key for key, ok in checks.items() if not ok])
                    for key in check_python:
                        if check_python[key] != check_rust[key]:
                            if key == 'files':
                                print('  files differing:', [p for p in set(python['files']) | set(rust['files']) if python['files'].get(p) != rust['files'].get(p)])
                            else: print(' ', key, repr(python[key])[:1000], repr(rust[key])[:1000])
                else: print('PASS', name, deviation)
        finally: server.close()
    if evidence:
        Path(evidence).write_text(json.dumps(observations, ensure_ascii=True, indent=1) + '\n')
    print('resume function oracle: %d/%d passed' % (len(cases) - len(failures), len(cases)))
    return failures


def main():
    from resume_printable import verify
    verify()
    parser = argparse.ArgumentParser()
    parser.add_argument('probe', nargs='?', default=str(REPO / 'target/release/examples/resume_probe'))
    parser.add_argument('--case', action='append')
    parser.add_argument('--evidence')
    args = parser.parse_args()
    cases = [(n, c) for n, c in CASES if not args.case or n in args.case]
    assert cases, 'no matching cases'
    raise SystemExit(bool(compare(Path(args.probe).resolve(), cases, args.evidence)))


if __name__ == '__main__': main()
