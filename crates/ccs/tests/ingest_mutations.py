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
    ('canonical-request-path', 'review_paths', 'string(codex::absolute(Path::new(path)).to_string_lossy())', 'string(path)'),
    ('tombstone-ascii', 'statuses', 'json::dumps_compact(value, true, false)', 'json::dumps_compact(value, false, false)'),
    ('kinds-iterable', 'statuses', 'let kinds = match kinds {', 'let kinds = match kinds { Value::String(_) => return Err(util::invalid("not iterable")),'),
    ('numeric-version', 'diff', 'crate::config::number(get(&data, "version")) == Some(1.0)', 'integer(get(&data, "version")) == Some(1)'),
    ('mask-bypass', 'basics', 'lines.push(output);', 'lines.push(String::from_utf8_lossy(raw).into_owned());'),
    ('key-whitespace', 'basics', 'v[start..end].to_vec()', 'v[..].to_vec()'),
    ('cursor', 'basics', 'set(entry, "offset", next);', 'set(entry, "offset", number(999999));'),
    ('dev-reset', 'diff', 'integer(get(&entry, "dev")) != Some(st.dev())', 'false'),
    ('inode-reset', 'diff', 'integer(get(&entry, "inode")) != Some(st.ino())', 'false'),
    ('truncate-reset', 'diff', 'offset_cmp(&stored_offset, st.len())?.is_gt()', 'false'),
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
    ('MA-blob-cap', 'review_blobs', '.redact_text(&String::from_utf8_lossy(&raw), &self.key)', '.redact_text_capped(&String::from_utf8_lossy(&raw), &self.key, usize::MAX)'),
    ('MB-blob-generation', 'review_blobs', 'remove(&mut entry, "blobs");', ''),
    ('MC-budget-expiry', 'review_budgets', 'self.deadline.is_some_and(|d| Instant::now() > d)', 'false'),
    ('MD-file-budget', 'review_budgets', 'Some(20)', 'Some(200)'),
    ('MD-sweep-budget', 'review_budgets', 'Some(120)', 'Some(1200)'),
    ('ME-subagent-symlink', 'review_symlink', 'if sub.is_symlink() || !sub.is_dir() {', 'if !sub.is_dir() {'),
    ('MF-state-files', 'review_blobs', '!matches!(get(&data, "files"), Value::Object(_))', 'false'),
    ('MG-segment-checkpoint', 'review_checkpoint', 'set(self.state.files_mut(), path, entry.clone());\n            self.state.save()?;', 'set(self.state.files_mut(), path, entry.clone());'),
    ('response-integer-range', 'review_numbers', "python_integer(value).is_some_and(|s| !s.starts_with('-'))", 'integer(value).is_some()'),
    ('generation-coercion', 'review_numbers', 'fn increment_generation(value: &Value) -> Result<Value> {', "fn increment_generation(value: &Value) -> Result<Value> { if let Value::Number(n) = value { if n.contains('.') { return Ok(number(1)); } }"),
    ('response-materialization', 'review_responses', 'util::parse_json(s).ok()', 'json::from_str(s).ok()'),
    ('relative-subagent-key', 'review_paths', 'subagent_files(&path.with_extension(""))', 'subagent_files(&codex::absolute(path).with_extension(""))'),
    ('non-utf8-warning', 'review_names', 'if path.to_str().is_some() {', 'if true {'),
    ('malformed-blob-state', 'review_blobs', 'if !matches!(sent, Value::Object(_)) {', 'if false {'),
    ('surrogate-warning', 'review_warnings', 'output.contains("\\"reason\\":\\"surrogate\\"")', 'false'),
    ('422-warning', 'review_warnings', 'lines={} kinds={} -> tombstoned', 'indexes={} categories={} -> tombstoned'),
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
                reasons = {
                    'MA-blob-cap': b'MA-blob-value-cap',
                    'MB-blob-generation': b'MB-rotation-resends-unchanged-blob',
                    'MC-budget-expiry': b'MC-MD-budget-file',
                    'MD-file-budget': b'MC-MD-budget-file',
                    'MD-sweep-budget': b'MC-MD-budget-sweep',
                    'ME-subagent-symlink': b'ME-symlinked-subagents',
                    'MF-state-files': b'Rust panic while processing state',
                    'MG-segment-checkpoint': b'MG acknowledged cursor not checkpointed',
                    'generation-coercion': b'generation-coercion-2.5',
                    'response-integer-range': b'huge-next',
                    'response-materialization': b'deep-success-response',
                    'relative-subagent-key': b'relative-file-subagent-state',
                    'non-utf8-warning': b'non-UTF8 name needs exactly one WARN',
                    'malformed-blob-state': b'malformed-blob-state-[1]',
                    'surrogate-warning': b'surrogate-warning',
                    '422-warning': b'422-warning-detail',
                    'canonical-request-path': b'path-home-sweep/.',
                }
                assert reasons.get(name, b'AssertionError') in output, (name, 'failed for the wrong reason', output[-2000:])
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
