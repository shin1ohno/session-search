"""C9 offline fallback (§6.8): local JSONL only, rg pre-select, ≤200 newest candidates.

Used when the circuit breaker is open or with --offline. No archive, no other
hosts, no semantic search; the fixed banner makes the cap visible.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from . import extract, util

BANNER = "OFFLINE — local sessions only, ≤200 newest candidates per agent"
CANDIDATE_CAP = 200
RECENT_CAP = 50


def _run(argv, **kw):
    return subprocess.run(argv, **kw)


class FallbackUnavailable(Exception):
    pass


def rg_argv(query: str, root: str):
    return ["rg", "-l", "-F", "-i", "--glob", "*.jsonl", "--glob", "!**/subagents/**", "--", query, root]


def main_files(root: str):
    out = []
    try:
        pdirs = list(os.scandir(root))
    except OSError:
        return out
    for pd in pdirs:
        if not pd.is_dir(follow_symlinks=False):
            continue
        try:
            for e in os.scandir(pd.path):
                if e.is_file(follow_symlinks=False) and e.name.endswith(".jsonl"):
                    out.append(e.path)
        except OSError:
            continue
    return out


def _newest(paths, cap):
    def mt(p):
        try:
            return os.stat(p).st_mtime
        except OSError:
            return 0.0
    return sorted(paths, key=mt, reverse=True)[:cap]


def candidates(query: str, root: str | None = None, runner=None, which=None):
    """Paths to parse: rg -l pre-selection capped to the 200 newest by mtime."""
    runner = runner or _run
    which = which or shutil.which
    from . import codex

    native = list(codex.paths()) if root is None else []
    include_codex = root is None
    root = root or util.projects_dir()
    roots = [root] if os.path.isdir(root) else []
    if include_codex and os.path.isdir(codex.sessions_dir()):
        roots.append(codex.sessions_dir())
    if not roots:
        raise FallbackUnavailable("no local transcript directories exist")
    if len((query or "").strip()) < 2:
        return _newest(main_files(root) + native, RECENT_CAP)
    if not which("rg"):
        raise FallbackUnavailable("ripgrep (rg) is not installed; the offline fallback needs it")
    try:
        argv = rg_argv(query, roots[0]) + roots[1:]
        proc = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        raise FallbackUnavailable("rg failed: %s" % e.__class__.__name__)
    # rg exits 1 for "no match", 2 for errors (with partial output possible).
    if proc.returncode not in (0, 1):
        raise FallbackUnavailable("rg exited %d" % proc.returncode)
    paths = [line for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.endswith(".jsonl")]
    # Fixed context in native Codex rollouts can match every file. Keep an
    # independent budget so those false positives cannot evict Claude hits.
    claude = _newest([p for p in paths if not codex.is_path(p)], CANDIDATE_CAP)
    native = _newest([p for p in paths if codex.is_path(p)], CANDIDATE_CAP)
    return _newest(claude + native, None)


def search(query: str, include_headless: bool = False, cwd_prefix: str | None = None, since_epoch: float | None = None,
           exclude_session_id: str | None = None, root: str | None = None, runner=None, which=None):
    """-> list of extract.LocalSession, newest first, matching `query` on `text` only."""
    q = (query or "").strip()
    short = len(q) < 2
    out = []
    for path in candidates(q, root, runner=runner, which=which):
        s = extract.scan(path, None if short else q)
        if not short and s.hits == 0:
            continue
        if exclude_session_id and s.session_id == exclude_session_id:
            continue
        if not include_headless and not s.interactive:
            continue
        if cwd_prefix and not (s.cwd == cwd_prefix or s.cwd.startswith(cwd_prefix.rstrip(os.sep) + os.sep)):
            continue
        if since_epoch is not None and s.mtime < since_epoch:
            continue
        out.append(s)
    return out
