"""Codex rollout discovery and resume paths. No database writes or model calls."""

from __future__ import annotations

import json
import os
import re

from . import util

ROLLOUT_RE = re.compile(r"^rollout-[0-9T:-]+-([0-9a-f-]{36})\.jsonl$")


def home() -> str:
    return os.path.abspath(os.path.expanduser(os.environ.get("CODEX_HOME") or
                                           os.path.join(util.home(), ".codex")))


def sessions_dir() -> str:
    return os.path.join(home(), "sessions")


def paths():
    root = sessions_dir()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
        for name in files:
            p = os.path.join(directory, name)
            if ROLLOUT_RE.fullmatch(name) and not os.path.islink(p):
                yield p


def metadata(path: str) -> dict:
    try:
        with os.fdopen(util.open_regular(path, sessions_dir()), "rb") as fh:
            raw = fh.readline(4 * 1024 * 1024 + 1)
        if not raw.endswith(b"\n"):
            return {}
        rec = json.loads(raw)
        payload = rec.get("payload")
        if rec.get("type") == "session_meta" and isinstance(payload, dict):
            return payload
    except (OSError, ValueError, AttributeError, util.UnsafePath):
        pass
    return {}


def classify(path: str):
    p = os.path.abspath(path)
    if not p.startswith(os.path.abspath(sessions_dir()) + os.sep):
        return None
    m = ROLLOUT_RE.fullmatch(os.path.basename(p))
    if not m:
        return None
    meta = metadata(p)
    cwd = meta.get("cwd")
    if meta.get("id") != m.group(1) or not isinstance(cwd, str) or not cwd.startswith("/"):
        return None
    return {"kind": "main", "source": "codex", "session_id": m.group(1),
            "project_dir": "codex-" + util.encode_cwd(cwd)}


def find_local(sid: str, hint=None):
    def candidates():
        if isinstance(hint, str):
            yield hint
        yield from paths()

    for p in candidates():
        match = ROLLOUT_RE.fullmatch(os.path.basename(p))
        if not match or match.group(1) != sid:
            continue
        info = classify(p)
        if info and info["session_id"] == sid:
            return p
    return None


def is_path(path: str) -> bool:
    return os.path.abspath(path).startswith(os.path.abspath(sessions_dir()) + os.sep)
