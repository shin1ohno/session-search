#!/usr/bin/env python3
"""Run CI's resume oracle against compiled, deliberately broken source copies.

The checkout remains unchanged. The caller owns the scratch directory, including
per-mutant build logs, oracle logs and JSON observations. A build failure never
counts as a killed mutant.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
MUTATIONS = [
    ('cwd-encoding', '&& util::encode_cwd(&c) == project', '&& true', ['local-recorded-mismatch']),
    ('cwd-realpath', 'p.as_os_str() == c.as_str()', 'p.is_dir()', ['local-cwd-link']),
    ('cwd-ambiguity', '1 => Ok(PathBuf::from(&found[0])),', '1.. => Ok(PathBuf::from(&found[0])),', ['local-collision']),
    ('restore-record', 'let rec = get(get(&restored, "sessions"), &format!("{project}/{sid}"));', 'let rec = get(get(&restored, "sessions"), "missing");', ['local-restored']),
    ('local-parent-link', '&& !symlink(parent)', '&& true', ['local-parent-link']),
    ('local-hint', 'hint.filter(|p| local_jsonl_ok(p, sid))', 'hint', ['remote-unsafe-hint']),
    ('session-id', '.filter(|sid| util::valid_session_id(sid))', '.filter(|_sid| true)', ['remote-invalid-id']),
    ('sha', 'want.len() != 64 || want != got', 'want.len() != 64', ['restore-sha', 'codex-sha']),
    ('force', '&& !req.force', '&& false', ['restore-existing']),
    ('rewrite', 'regex::escape(&orig)', 'regex::escape("no-such-project")', ['restore']),
    ('target-symlink', 'if symlink(p) {', 'if false {', ['restore-target-link']),
    ('tar-name', '!util::valid_tool_result_name(&name)', 'false', ['restore-tar-traversal']),
    ('tar-type', 'kind.is_file() || kind == tar::EntryType::Continuous || kind.is_gnu_sparse()', 'true', ['restore-tar-symlink']),
    ('tar-mode', 'mode |= 0o600;', 'mode |= 0o666;', ['restore-tool-mode']),
    ('bzip2-not-refused', 'if bzip2 || xz {', 'if xz {', ['restore-bzip2-tools', 'restore-bzip2-existing-tools']),
    ('xz-not-refused', 'if bzip2 || xz {', 'if bzip2 {', ['restore-xz-tools', 'restore-xz-existing-tools']),
    ('compression-panic', 'if bzip2 || xz {', 'if bzip2 || xz { panic!("unsupported archive");', ['restore-bzip2-tools', 'restore-xz-tools']),
    ('compression-early-directory', 'if bzip2 || xz {', 'ensure_dir(dest, 0o700)?; if bzip2 || xz {', ['restore-bzip2-tools', 'restore-xz-tools']),
    ('compression-early-write', 'if bzip2 || xz {', 'ensure_dir(dest, 0o700)?; fs::write(dest.join("out.txt"), b"bad").map_err(Error::Io)?; if bzip2 || xz {', ['restore-bzip2-existing-tools', 'restore-xz-existing-tools']),
    ('temporary-cleanup', 'fs::remove_file(&tmp).map_err(Error::Io)?;', 'let _ = &tmp;', ['restore-stale-tmp']),
    ('record-write', 'record_restore(sid, &project, cwd)?;', 'let _ = (sid, &project, cwd);', ['restore']),
    ('exec-cwd', 'std::env::set_current_dir(cwd).map_err(Error::Io)?;', 'let _ = cwd;', ['local']),
    ('exec-env', 'libc::execv(candidate.as_ptr(), pointers.as_ptr());', 'libc::unsetenv(c"CCS_RESUME_SENTINEL".as_ptr()); libc::execv(candidate.as_ptr(), pointers.as_ptr());', ['local']),
    ('fork-argv', 'args.push("--fork-session");', 'args.push("--fork");', ['local-fork']),
    ('codex-argv', 'if req.fork { "fork" } else { "resume" }', 'if req.fork { "resume" } else { "fork" }', ['codex-local-fork']),
    ('codex-settings', '|| is(kind, "turn_context")', '|| false', ['codex-restore']),
    ('codex-world', '|| is(kind, "world_state")', '|| false', ['codex-restore']),
    ('codex-display', '(rebuild || !has_display)', 'false', ['codex-paginated']),
    ('codex-index', 'own_start.unwrap_or(count)', 'count', ['codex-fork', 'codex-subagent']),
    ('codex-ordinal', 'set(&mut rec, "ordinal", number(ordinal));', 'set(&mut rec, "ordinal", number(ordinal + 1));', ['codex-restore']),
    ('codex-root-link', 'if symlink(check) {', 'if false {', ['codex-root-link']),
    ('closed-stderr', 'return Err(Error::Io(io::Error::from_raw_os_error(libc::EBADF)));', 'return Ok(());', ['restore-closed-stderr', 'remote-closed-stderr']),
    ('username-expand', 'if !bytes.starts_with(b"~") {', 'if true {', ['restore-username-to']),
    ('exit-status', 'Ok(e.exit_status())', 'Ok(ExitStatus::Success)', ['remote-view-only']),
]
# The ten mutations from the independent review, applied to the current source.
MUTATIONS += [
    ('review-record-encoding', '&& util::encode_cwd(c) == project', '&& true', ['local-restored-wrong-project']),
    ('review-print-tty', 'req.print || !io::stdin().is_terminal()', '!io::stdin().is_terminal()', ['restore-tty-print']),
    ('review-project-mode', 'ensure_dir(&pdir, 0o700)?;', 'ensure_dir(&pdir, 0o777)?;', ['restore-umask']),
    ('review-tools-mode', 'ensure_dir(dest, 0o700)?;', 'ensure_dir(dest, 0o777)?;', ['restore-umask']),
    ('review-uppercase-sha', 'strip(response.header("X-Archive-Sha256").unwrap_or("")).to_lowercase()', 'strip(response.header("X-Archive-Sha256").unwrap_or("")).to_owned()', ['restore-sha-uppercase']),
    ('review-restore-unreachable', 'Error::Unavailable(s) => Error::Unavailable(format!("server unreachable: {s}")),', 'Error::Unavailable(s) => Error::ResumePrecondition(format!("server unreachable: {s}")),', ['restore-archive-drop']),
    ('review-float-version', 'n.parse::<f64>() == Ok(1.0)', 'n == "1"', ['local-restored-float-version']),
    ('review-yes-answer', '"y" | "yes"', '"y"', ['restore-tty-yes-word']),
    ('review-codex-realpath', '.and_then(|c| directory(&c))', '.and_then(|c| c.is_dir().then_some(c))', ['codex-cwd-link-print']),
    ('review-codex-target', 'if st.file_type().is_symlink() || !st.is_file() {', 'if false {', ['codex-target-link', 'codex-target-directory']),
    ('surrogate-cwd-lossy', 'cwd_text(candidate)?', "Some(match candidate { Value::String(points) => points.iter().map(|&c| char::from_u32(c).unwrap_or('�')).collect::<String>(), _ => String::new() })", ['local-surrogate-collision']),
    ('raw-cwd-write', 'if path.to_str().is_none() {', 'if false {', ['restore-raw-cwd']),
    ('lzma-alone', '|| lzma;', ';', ['restore-lzma-alone']),
    ('tar-buffer-payload', 'io::copy(&mut entry, &mut f).map_err(Error::Io)?;', 'let mut data = Vec::new(); entry.read_to_end(&mut data).map_err(Error::Io)?; f.write_all(&data).map_err(Error::Io)?;', ['restore-large-member']),
    ('tar-contiguous', 'kind == tar::EntryType::Continuous', 'false', ['restore-tar-contiguous']),
    ('tar-global-pax', '*global = attributes;\n        return Ok(None);', 'return Err(refused("global pax refused"));', ['restore-tar-global-pax']),
    ('tar-signed-checksum', '&& i64::from(sum) != i64::from(signed)', '', ['restore-tar-signed-checksum']),
    ('tar-late-invalid', 'if self.seen {', 'if false {', ['restore-tar-late-corrupt']),
    ('exec-shell-fallback', 'libc::execv(candidate.as_ptr(), pointers.as_ptr());', 'libc::execvp(candidate.as_ptr(), pointers.as_ptr());', ['local-agent-no-shebang']),
    ('local-path-suffix', 'raw_path.rsplit(\'/\').next().unwrap_or("")', 'path.file_name().and_then(|s| s.to_str()).unwrap_or("")', ['local-trailing-slash']),
    ('archive-conflict-type', 'truthy(&data) && !matches!(data, Value::Object(_))', 'false', ['restore-conflict-list']),
    ('archive-read-exit', 'options.preserve_eof && error.kind() == std::io::ErrorKind::UnexpectedEof', 'false', ['restore-archive-truncated', 'restore-tools-truncated']),
    ('archive-auth-exit', 's.starts_with("token ")', 'false', ['restore-auth-refresh']),
    ('tar-mtime', 'f.set_modified(modified).map_err(Error::Io)?;', 'let _ = modified;', ['restore-tar-mtime', 'restore-tar-pax-mtime']),
    ('repr-printable', 'Some(c) if printable(point)', 'Some(c) if !c.is_control()', ['restore-tar-repr-nbsp', 'restore-tar-repr-format', 'restore-tar-repr-astral']),
    ('codex-home-expand', 'path.as_os_str().as_bytes().starts_with(b"~")', 'false', ['codex-username-home', 'codex-username-local']),
]

MUTATIONS += [
    ('api-timeout-is-internal', 'error.kind() == std::io::ErrorKind::UnexpectedEof', 'true', []),
    ('api-normal-body-lost', 'Ok(Response {\n        status,\n        headers,\n        body,\n    })', 'Ok(Response { status, headers, body: Vec::new() })', ['restore']),
    ('api-legacy-eof', 'preserve_eof: options.preserve_body_eof', 'preserve_eof: true', []),
    ('api-error-body', 'status >= 300 && read.is_err()', 'false', ['restore-error-truncated', 'restore-tools-error-truncated']),
    ('lzma-plain-header', '!plain_tar', 'true', ['restore-tar-lzma-prefix']),
    ('tar-negative-mtime', 'entry.header().as_old().mtime[0] == 0xff', 'false', ['restore-tar-negative-mtime']),
]
SOURCE_FILES = {'archive-read-exit':'api.rs', 'api-timeout-is-internal':'api.rs',
                'api-normal-body-lost':'api.rs', 'api-legacy-eof':'api.rs', 'api-error-body':'api.rs', 'codex-home-expand':'codex.rs'}
UNIT_TESTS = {'api-timeout-is-internal':'stalled_body', 'api-legacy-eof':'truncated_body'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--only', action='append')
    args = parser.parse_args()
    directory = args.directory.resolve(); directory.mkdir(parents=True, exist_ok=True)
    tree = directory / 'source'
    if not tree.exists():
        shutil.copytree(REPO, tree, ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
    shutil.copyfile(REPO / 'crates/ccs/examples/resume_probe.rs', tree / 'crates/ccs/examples/resume_probe.rs')
    originals = {name:(REPO / 'crates/ccs/src' / name).read_text() for name in ['resume.rs','api.rs','codex.rs']}
    for name, content in originals.items(): (tree / 'crates/ccs/src' / name).write_text(content)
    env = dict(os.environ, CCS_BUILD_COMMIT=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
               CARGO_TARGET_DIR=str(directory / 'target'))
    results = []
    for name, before, after, cases in MUTATIONS:
        if args.only and name not in args.only: continue
        for file, content in originals.items(): (tree / 'crates/ccs/src' / file).write_text(content)
        source_name = SOURCE_FILES.get(name,'resume.rs'); original = originals[source_name]
        target = tree / 'crates/ccs/src' / source_name
        assert before in original, (name, 'mutation anchor absent')
        changed = (after.join(original.rsplit(before, 1)) if name == 'review-restore-unreachable' else original.replace(before, after, 1))
        target.write_text(changed)
        build_log = directory / (name + '-build.log')
        with build_log.open('w') as log:
            built = subprocess.run(['cargo','build','--locked','--example','resume_probe'],cwd=tree,env=env,stdout=log,stderr=subprocess.STDOUT)
        if built.returncode:
            results.append(dict(mutation=name, status='build-failed', evidence=str(build_log)))
            print('BUILD FAILED',name,flush=True); continue
        oracle_log = directory / (name + '-oracle.log')
        command = [sys.executable,'-u',str(REPO / 'crates/ccs/tests/resume_oracle.py'),str(directory / 'target/debug/examples/resume_probe'),
                   '--evidence',str(directory / (name + '-observations.json'))]
        for case in cases: command += ['--case',case]
        if name in UNIT_TESTS:
            command = ['cargo','test','--locked','-p','ccs','--test','resume_http',UNIT_TESTS[name],'--','--exact']
        with oracle_log.open('w') as log:
            result = subprocess.run(command,cwd=tree if name in UNIT_TESTS else REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
        output = oracle_log.read_text()
        killed = ((result.returncode == 101 and 'test result: FAILED' in output) if name in UNIT_TESTS else (result.returncode == 1 and 'FAIL ' in output and 'resume function oracle:' in output))
        results.append(dict(mutation=name,status='killed' if killed else 'survived-or-harness-error',evidence=str(oracle_log)))
        print(results[-1]['status'],name,flush=True)
    for file, content in originals.items(): (tree / 'crates/ccs/src' / file).write_text(content)
    previous = json.loads((directory / 'results.json').read_text()) if args.only and (directory / 'results.json').exists() else []
    combined = {row['mutation']: row for row in previous}
    combined.update({row['mutation']: row for row in results})
    (directory / 'results.json').write_text(json.dumps(list(combined.values()),indent=2)+'\n')
    raise SystemExit(any(r['status'] != 'killed' for r in results))


if __name__ == '__main__': main()
