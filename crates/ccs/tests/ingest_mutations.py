"""Build deliberately broken isolated copies and require the committed oracle to fail."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[3]
# Each mutation changes production code, not the oracle or a fake API result.
MUTATIONS = [
    ('tombstone-ascii', 'statuses', 'json::dumps_compact(value, true, false)', 'json::dumps_compact(value, false, false)'),
    ('kinds-iterable', 'statuses', 'let kinds = match kinds {', 'let kinds = match kinds { Value::String(_) => return Err(util::invalid("not iterable")),'),
    ('numeric-version', 'diff', 'crate::config::number(get(&data, "version")) == Some(1.0)', 'integer(get(&data, "version")) == Some(1)'),
    ('mask-bypass', 'basics', 'lines.push(output);', 'lines.push(String::from_utf8_lossy(raw).into_owned());'),
    ('key-whitespace', 'basics', 'v[start..end].to_vec()', 'v[..].to_vec()'),
    ('cursor', 'basics', 'set(entry, "offset", next);', 'set(entry, "offset", number(999999));'),
    ('dev-reset', 'diff', 'integer(get(&entry, "dev")) != Some(st.dev())', 'false'),
    ('inode-reset', 'diff', 'integer(get(&entry, "inode")) != Some(st.ino())', 'false'),
    ('truncate-reset', 'diff', 'st.len() < integer(get(&entry, "offset")).unwrap_or(0)', 'false'),
    ('unknown-state', 'diff', 'let mut entry = get(self.state.files(), path).clone();', 'let mut entry = get(self.state.files(), path).clone(); remove(&mut entry, "unknown");'),
    ('segment-cap', 'segments', 'const MAX_SEGMENT: usize = 4 * 1024 * 1024;', 'const MAX_SEGMENT: usize = 8 * 1024 * 1024;'),
    ('oversize', 'segments', 'data.len() > MAX_SEGMENT', 'data.len() > 2 * MAX_SEGMENT'),
    ('resync', 'statuses', 'set(entry, "offset", get(&data, "expected_offset").clone());', 'set(entry, "offset", number(0));'),
    ('halve', 'statuses', 'limit = (chunk.len() / 2).max(1);', 'limit = chunk.len();'),
    ('422-tombstone', 'statuses', '"unmasked_secret",', '"wrong-reason",'),
    ('blob-mask', 'blobs', '("content", string(content)),', '("content", string(String::from_utf8_lossy(&raw))),'),
    ('blob-dedup', 'blobs', 'if util::is(get(&sent, name), &raw_sha) {', 'if false {'),
    ('gone', 'discovery', 'shipper.report_gone()?;', 'let _ = &shipper;'),
    ('subagents', 'discovery', 'if request.with_subagents {', 'if false {'),
    ('lock', 'concurrent', 'match lock.try_lock() {', 'match Ok::<(), std::fs::TryLockError>(()) {'),
    ('codex-capability', 'codex', 'if self.codex_ready == Some(false) {\n                return Ok(());', 'if false {\n                return Ok(());'),
    ('surrogate-offset', 'surrogates', '.mask_line(raw, position, &self.key)', '.mask_line(raw, position + 1, &self.key)'),
    ('depth-route', 'deviations', 'lines.push(output);', 'lines.push(output.replace("too-deep", "wrong-reason"));'),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--only', action='append')
    args = parser.parse_args()
    temporary = None
    if args.output:
        root = args.output.resolve(); root.mkdir(parents=True, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix='ccs-ingest-mutations-')
        root = Path(temporary.name)
    work = root / 'source'
    work.mkdir(exist_ok=True)
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
        shutil.copy2(REPO / name, work / name)
    shutil.copytree(REPO / 'crates', work / 'crates', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    source = work / 'crates/ccs/src/ingest.rs'
    original = source.read_text()
    env = dict(os.environ, CCS_BUILD_COMMIT=os.environ.get('CCS_BUILD_COMMIT') or subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(), CARGO_TARGET_DIR=str(root / 'target'))
    binary = root / 'target/debug/examples/ingest_probe'
    try:
        selected = [m for m in MUTATIONS if not args.only or m[0] in args.only]
        for name, case, old, new in [('positive-control', 'basics', '', ''), *selected]:
            if old:
                assert original.count(old) == 1, (name, 'mutation anchor not unique')
                source.write_text(original.replace(old, new))
            else:
                source.write_text(original)
            build = subprocess.run(['cargo', 'build', '--locked', '--example', 'ingest_probe'], cwd=work, env=env, capture_output=True)
            (root / (name + '-build.log')).write_bytes(build.stdout + build.stderr)
            assert build.returncode == 0, (name, 'did not compile; not a valid negative control')
            run = subprocess.run([sys.executable, str(REPO / 'crates/ccs/tests/ingest_oracle.py'), '--binary', str(binary), '--case', case], capture_output=True, timeout=120)
            output = run.stdout + run.stderr
            (root / (name + '.log')).write_bytes(output)
            if old:
                assert run.returncode != 0 and b'AssertionError' in output, (name, 'oracle did not reject the defect', output[-1500:])
                assert b'TimeoutExpired' not in output and b'FileNotFoundError' not in output, (name, 'environment failure')
                print('PASS negative control', name, 'rejected by', case, flush=True)
            else:
                assert run.returncode == 0, ('positive control failed', output[-2000:])
                print('PASS mutation positive control', flush=True)
    finally:
        source.write_text(original)
        if temporary:
            temporary.cleanup()


if __name__ == '__main__':
    main()
