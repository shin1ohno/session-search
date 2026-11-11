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
    ('tar-type', '!entry.header().entry_type().is_file()', 'false', ['restore-tar-symlink']),
    ('tar-mode', 'mode |= 0o600;', 'mode |= 0o666;', ['restore-tool-mode']),
    ('bzip2-not-refused', 'if bzip2 || xz {', 'if xz {', ['restore-bzip2-tools', 'restore-bzip2-existing-tools']),
    ('xz-not-refused', 'if bzip2 || xz {', 'if bzip2 {', ['restore-xz-tools', 'restore-xz-existing-tools']),
    ('compression-panic', 'if bzip2 || xz {', 'if bzip2 || xz { panic!("unsupported archive");', ['restore-bzip2-tools', 'restore-xz-tools']),
    ('compression-early-directory', 'if bzip2 || xz {', 'util::ensure_dir(dest, 0o700)?; if bzip2 || xz {', ['restore-bzip2-tools', 'restore-xz-tools']),
    ('compression-early-write', 'if bzip2 || xz {', 'util::ensure_dir(dest, 0o700)?; fs::write(dest.join("out.txt"), b"bad").map_err(Error::Io)?; if bzip2 || xz {', ['restore-bzip2-existing-tools', 'restore-xz-existing-tools']),
    ('temporary-cleanup', 'fs::remove_file(&tmp).map_err(Error::Io)?;', 'let _ = &tmp;', ['restore-stale-tmp']),
    ('record-write', 'record_restore(sid, &project, cwd)?;', 'let _ = (sid, &project, cwd);', ['restore']),
    ('exec-cwd', 'std::env::set_current_dir(cwd).map_err(Error::Io)?;', 'let _ = cwd;', ['local']),
    ('exec-env', 'Command::new(agent).args(args).exec()', 'Command::new(agent).env_remove("CCS_RESUME_SENTINEL").args(args).exec()', ['local']),
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
    source = REPO / 'crates/ccs/src/resume.rs'; original = source.read_text()
    target = tree / 'crates/ccs/src/resume.rs'
    env = dict(os.environ, CCS_BUILD_COMMIT=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
               CARGO_TARGET_DIR=str(directory / 'target'))
    results = []
    for name, before, after, cases in MUTATIONS:
        if args.only and name not in args.only: continue
        assert before in original, (name, 'mutation anchor absent')
        changed = original.replace(before, after, 1)
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
        with oracle_log.open('w') as log:
            result = subprocess.run(command,cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
        output = oracle_log.read_text()
        killed = result.returncode == 1 and 'FAIL ' in output and 'resume function oracle:' in output
        results.append(dict(mutation=name,status='killed' if killed else 'survived-or-harness-error',evidence=str(oracle_log)))
        print(results[-1]['status'],name,flush=True)
    target.write_text(original)
    previous = json.loads((directory / 'results.json').read_text()) if args.only and (directory / 'results.json').exists() else []
    combined = {row['mutation']: row for row in previous}
    combined.update({row['mutation']: row for row in results})
    (directory / 'results.json').write_text(json.dumps(list(combined.values()),indent=2)+'\n')
    raise SystemExit(any(r['status'] != 'killed' for r in results))


if __name__ == '__main__': main()
