#!/usr/bin/env python3
"""Freeze this host's transcripts into a private temporary HOME for S3.

`create` copies ~/.claude/projects, ~/.codex/sessions, the ingest state and
the log into a new 0700 directory, keeping mtimes and symlinks, so both
implementations read identical bytes while live sessions keep writing.
`remove` deletes such a copy. Nothing is read from or written to the server.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import MARKER, writable_ancestor, write_report  # noqa: E402


def copy_tree(src: Path, dst: Path) -> tuple:
    if not src.is_dir():
        return 0, 0
    shutil.copytree(src, dst, symlinks=True, copy_function=shutil.copy2)
    files = size = 0
    for root, _, names in os.walk(dst):
        for name in names:
            p = Path(root) / name
            if not p.is_symlink():
                files += 1
                size += p.stat().st_size
    return files, size


def create(into: Path, source_home: Path) -> Path:
    into.mkdir(mode=0o700, parents=True, exist_ok=True)
    bad = writable_ancestor(into.resolve())
    if bad is not None:
        raise SystemExit("refusing: %s is writable by others (mode %o), so Rust would skip its token cache; "
                         "chmod it 0700 first" % (bad, os.stat(bad).st_mode & 0o7777))
    home = Path(tempfile.mkdtemp(prefix="home-", dir=into))
    os.chmod(home, 0o700)
    (home / MARKER).write_text("")
    report = {}
    report["projects_files"], report["projects_bytes"] = copy_tree(
        source_home / ".claude/projects", home / ".claude/projects")
    report["codex_files"], report["codex_bytes"] = copy_tree(
        source_home / ".codex/sessions", home / ".codex/sessions")
    state_dir = home / ".claude/session-search"
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    real_state = source_home / ".claude/session-search/state.json"
    if real_state.exists():
        shutil.copy2(real_state, home / "state.real.json")
    log = source_home / ".claude/session-search.log"
    if log.exists():
        shutil.copy2(log, home / ".claude/session-search.log")
    report["state_copied"] = real_state.exists()
    report["log_copied"] = log.exists()
    write_report(home / "snapshot-report.json", report)
    return home


def remove(home: Path) -> None:
    if not (home / MARKER).exists():
        raise SystemExit("refusing to remove a directory that is not a shadow snapshot")
    shutil.rmtree(home)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--into", type=Path, required=True)
    c.add_argument("--source-home", type=Path, default=Path.home())
    r = sub.add_parser("remove")
    r.add_argument("home", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "create":
        print(create(a.into, a.source_home))
    else:
        remove(a.home)
    return 0


if __name__ == "__main__":
    sys.exit(main())
