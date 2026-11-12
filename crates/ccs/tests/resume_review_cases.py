"""Additional process inputs for resume's independent compatibility review."""
import datetime
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import pwd
import tarfile
import time

BASE_CASE = {
    'local-surrogate-collision': 'local', 'local-surrogateescape': 'local',
    'local-restored-surrogateescape': 'local-restored',
    'local-restored-wrong-project': 'local-restored', 'local-restored-float-version': 'local-restored',
    'local-trailing-slash': 'local-to', 'local-agent-no-shebang': 'local',
    'restore-raw-cwd': 'restore-tty-no', 'restore-raw-to': 'restore',
    'restore-tty-print': 'restore-tty-no', 'restore-tty-yes-word': 'restore-tty-yes',
    'restore-sha-uppercase': 'restore', 'restore-lzma-alone': 'restore',
    'restore-lzma-alone-existing': 'restore', 'restore-umask': 'restore',
    'restore-large-member': 'restore', 'restore-tar-contiguous': 'restore',
    'restore-tar-global-pax': 'restore', 'restore-tar-late-corrupt': 'restore',
    'restore-tar-signed-checksum': 'restore', 'restore-tar-mtime': 'restore',
    'restore-tar-pax-mtime': 'restore', 'restore-tar-repr-nbsp': 'restore',
    'restore-tar-repr-format': 'restore', 'restore-tar-repr-lines': 'restore',
    'restore-tar-repr-private': 'restore', 'restore-tar-repr-astral': 'restore',
    'restore-conflict-list': 'restore', 'restore-conflict-empty-list': 'restore',
    'restore-archive-truncated': 'restore', 'restore-tools-truncated': 'restore',
    'restore-archive-drop': 'restore', 'restore-auth-refresh': 'restore',
    'restore-tools-reset': 'restore',
    'restore-error-truncated': 'restore', 'restore-tools-error-truncated': 'restore',
    'codex-cwd-link-print': 'codex-local-print', 'codex-target-link': 'codex-restore',
    'codex-target-directory': 'codex-restore', 'codex-username-home': 'codex-restore',
    'codex-username-local': 'codex-local',
    'restore-tar-global-mtime': 'restore', 'restore-tar-negative-mtime': 'restore',
    'restore-tar-lzma-prefix': 'restore', 'restore-tar-gzip-truncated': 'restore',
}
CODES = {
    'local-surrogate-collision': 4, 'local-surrogateescape': 17,
    'local-restored-surrogateescape': 17, 'local-restored-wrong-project': 4,
    'local-restored-float-version': 17, 'local-trailing-slash': 4, 'local-agent-no-shebang': 1,
    'restore-raw-cwd': 17, 'restore-raw-to': 17, 'restore-tty-print': 4,
    'restore-tty-yes-word': 17, 'restore-sha-uppercase': 17, 'restore-umask': 17,
    'restore-large-member': 17, 'restore-tar-contiguous': 17, 'restore-tar-global-pax': 17,
    'restore-tar-late-corrupt': 17, 'restore-tar-signed-checksum': 17, 'restore-tar-mtime': 17,
    'restore-tar-pax-mtime': 17, 'restore-tar-repr-nbsp': 4, 'restore-tar-repr-format': 4,
    'restore-tar-repr-lines': 4, 'restore-tar-repr-private': 4, 'restore-tar-repr-astral': 4,
    'restore-conflict-list': 1, 'restore-conflict-empty-list': 4,
    'restore-archive-truncated': 1, 'restore-tools-truncated': 1,
    'restore-archive-drop': 3, 'restore-auth-refresh': 1,
    'restore-tools-reset': 1,
    'restore-error-truncated': 4, 'restore-tools-error-truncated': 4,
    'codex-cwd-link-print': 0, 'codex-target-link': 4, 'codex-target-directory': 4,
    'codex-username-home': 17,
    'codex-username-local': 17, 'restore-tar-global-mtime': 17,
    'restore-tar-negative-mtime': 17, 'restore-tar-lzma-prefix': 17,
    'restore-tar-gzip-truncated': 1,
}
CASES = list(CODES.items())
D5_CASES = {'local-surrogateescape', 'local-restored-surrogateescape', 'restore-raw-cwd', 'restore-raw-to'}
FIXTURE_TIME = 946684800
TARGET_TIME = None


def archive(entries, **kwargs):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', **kwargs) as tf:
        for entry, data in entries:
            tf.addfile(entry, io.BytesIO(data))
    return out.getvalue()


def amend_fixture(root, name, base, original, helpers):
    req, env, home, response, answers = original
    sid = helpers['SID']; write = helpers['write']; rows = helpers['rows']; encoded = helpers['encoded']
    cwd = home / "work space's" / '日本'
    target = home / '.claude/projects' / encoded(cwd) / (sid + '.jsonl')
    tr = target.parent / sid / 'tool-results'
    state = home / '.claude/session-search/restored.json'
    if name in ('local-surrogate-collision', 'local-surrogateescape', 'local-restored-surrogateescape'):
        value = str(home) + '/x' + ('\ud800' if name == 'local-surrogate-collision' else '\udcff') + 'y'
        Path(value.replace('\ud800', '\ufffd')).mkdir()
        dest = home / '.claude/projects' / encoded(value) / (sid + '.jsonl')
        write(dest, rows(dict(type='user', cwd=value)))
        req['session_key'] = 'local:' + str(dest)
        if name.startswith('local-restored'):
            write(state, json.dumps(dict(version=1, sessions={encoded(value)+'/'+sid: {'cwd':value}})))
    if name in ('restore-raw-cwd', 'restore-raw-to'):
        raw = Path(os.fsdecode(os.fsencode(home) + b'/w\xe6\x97x')); raw.mkdir()
        response['meta']['resume_cwd'] = '/does-not-exist'
        if name == 'restore-raw-cwd':
            req['_process_cwd'] = os.fsencode(raw).hex(); answers = b'\n'
        else:
            req['to_dir'] = str(raw); req['_to_dir_bytes'] = os.fsencode(raw).hex()
    if name == 'local-restored-wrong-project':
        write(state, json.dumps(dict(version=1, sessions={encoded(cwd)+'/'+sid: {'cwd':str(home/'other')}})))
    if name == 'local-restored-float-version':
        data = json.loads(state.read_text()); data['version'] = 1.0; write(state, json.dumps(data))
    if name == 'local-trailing-slash': req['session_key'] += '/'
    if name == 'local-agent-no-shebang': write(root/'bin/claude', 'exit 17\n')
    if name == 'restore-tty-print': req['print'] = True
    if name == 'restore-tty-yes-word': answers = b'yes\n'
    if name == 'restore-sha-uppercase': response['sha'] = response['sha'].upper()
    if name.startswith('restore-lzma-alone'):
        response['tools'] = lzma.compress(response['tools'], format=lzma.FORMAT_ALONE)
        if name.endswith('existing'): write(tr/'out.txt', 'keep existing output')
    if name == 'restore-large-member':
        class Zeros:
            def read(self, size): return b'\0' * size
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode='wb', compresslevel=1) as gz:
            with tarfile.open(fileobj=gz, mode='w|') as tf:
                info = tarfile.TarInfo('out.txt'); info.size = 200 * 1024 * 1024; info.mode = 0o644
                tf.addfile(info, Zeros())
        response['tools'] = out.getvalue()
    if name in ('restore-tar-contiguous','restore-tar-global-pax','restore-tar-mtime','restore-tar-pax-mtime'):
        info = tarfile.TarInfo('out.txt'); info.size = 4; info.mode = 0o644
        if name.endswith('contiguous'): info.type = tarfile.CONTTYPE
        if name.endswith('-mtime'): info.mtime = 123456789
        if name.endswith('pax-mtime'): info.pax_headers = {'mtime':'123456789.125'}
        kwargs = {'pax_headers':{'comment':'global metadata'}} if name.endswith('global-pax') else {}
        response['tools'] = archive([(info,b'data')], **kwargs)
    if name == 'restore-tar-late-corrupt': response['tools'] = response['tools'][:1024] + b'x' * 512
    if name == 'restore-tar-signed-checksum':
        data = bytearray(response['tools']); data[265:297] = b'\xff' * 32; data[148:156] = b' ' * 8
        checksum = sum(b if b < 128 else b-256 for b in data[:512])
        assert checksum > 0
        data[148:156] = ('%06o\0 ' % checksum).encode(); response['tools'] = bytes(data)
    odd = {'restore-tar-repr-nbsp':'a\xa0b', 'restore-tar-repr-format':'a\u200db',
           'restore-tar-repr-lines':'a\u2028\u2029b', 'restore-tar-repr-private':'a\ue000b',
           'restore-tar-repr-astral':'a\U000e0001b'}
    if name in odd: response['tools'] = helpers['tar']([(odd[name],tarfile.REGTYPE,b'bad',0o644)])
    if name.startswith('restore-conflict-'):
        response['archive_status'] = 409
        response['body'] = b'[]' if name.endswith('empty-list') else b'["x"]'
    if name == 'restore-auth-refresh':
        config = Path(env['CCS_CONFIG']); home.chmod(0o700)
        write(home/'secret', 'synthetic-credential'); (home/'secret').chmod(0o600)
        data=json.loads(config.read_text()); data['auth'] = dict(type='client_credentials', token_url=base+'/token', client_id='test', secret_file=str(home/'secret'))
        write(config,json.dumps(data)); response['token_requests']=0
        # D8's lock is pre-created identically; a no-TTL token is not persisted.
        write(home/'token.lock', b''); (home/'token.lock').chmod(0o600)
    if name == 'codex-cwd-link-print': cwd.rmdir(); cwd.symlink_to(home/'other')
    if name in ('codex-target-link','codex-target-directory'):
        stamp = TARGET_TIME or int(time.time())
        for second in range(stamp-2, stamp+90):
            now = datetime.datetime.fromtimestamp(second, datetime.timezone.utc)
            dest = home/'.codex/sessions'/now.strftime('%Y/%m/%d')/('rollout-'+now.strftime('%Y-%m-%dT%H-%M-%S')+'-'+sid+'.jsonl')
            dest.parent.mkdir(parents=True,exist_ok=True)
            if name.endswith('link'): dest.symlink_to(home/'victim')
            else: dest.mkdir()
        write(home/'victim','keep existing file')
    if name in ('codex-username-home', 'codex-username-local'):
        user = pwd.getpwuid(os.getuid())
        literal = '~'+user.pw_name+'/'+os.path.relpath(home/'.codex',user.pw_dir)
        assert Path(os.path.abspath(home/literal)).is_relative_to(root)
        env['CODEX_HOME'] = literal
    if name in ('restore-tar-global-mtime', 'restore-tar-negative-mtime'):
        first=tarfile.TarInfo('out.txt'); first.size=4; first.mode=0o644
        second=tarfile.TarInfo('other.txt'); second.size=4; second.mode=0o644
        if name.endswith('global-mtime'):
            first.pax_headers={'mtime':'123456789.125'}
            response['tools']=archive([(first,b'data'),(second,b'more')],pax_headers={'mtime':'456.5'})
        else:
            first.mtime=-123
            response['tools']=archive([(first,b'data')],format=tarfile.GNU_FORMAT)
    if name == 'restore-tar-lzma-prefix':
        data=bytearray(response['tools']); data[:100]=b'a\0\x30'+b'\0'*97; data[148:156]=b' '*8
        data[148:156]=('%06o\0 ' % sum(data[:512])).encode(); response['tools']=bytes(data)
    if name == 'restore-tar-gzip-truncated': response['tools']=gzip.compress(response['tools'][:1024])[:-8]
    for path in [home, *home.rglob('*')]:
        os.utime(path, (FIXTURE_TIME,FIXTURE_TIME), follow_symlinks=False)
    return req,env,home,response,answers
