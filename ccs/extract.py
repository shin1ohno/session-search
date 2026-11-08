"""Small local transcript extractor for the offline fallback (C9) and local resume.

Implements only the part of the C1 rules the client needs: the human-readable
`text` of user/assistant records, the session title and the resume cwd. It is a
deliberate re-implementation, not an import of the server parser (C1), so the
client package stays self-contained. It is lenient: unparsable lines and
unknown record or block types are skipped, never raised.
"""

from __future__ import annotations

import json
import os
import re

from . import util

_LEADING_TAGS = (
    "system-reminder", "command-name", "command-message", "command-args",
    "local-command-stdout", "local-command-stderr", "task-notification",
    "bash-stdout", "bash-stderr",
)
_LEADING_RE = re.compile(
    r"^\s*<(%s)>.*?</\1>\s*" % "|".join(re.escape(t) for t in _LEADING_TAGS), re.S
)


def strip_leading_blocks(text: str) -> str:
    prev = None
    while prev != text:
        prev = text
        text = _LEADING_RE.sub("", text, count=1)
    return text.strip()


def record_text(rec) -> str:
    """`text` per C1: text blocks plus string content, leading tag blocks stripped."""
    if not isinstance(rec, dict) or rec.get("type") not in ("user", "assistant"):
        return ""
    if rec.get("isMeta") is True or rec.get("isCompactSummary") is True:
        return ""
    msg = rec.get("message")
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    parts = []
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
    return strip_leading_blocks("\n".join(p for p in (strip_leading_blocks(x) for x in parts) if p))


class DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKey(k)
        out[k] = v
    return out


def loads_strict(text: str):
    """json.loads that rejects duplicate object keys.

    With duplicates, which value "the" cwd is depends on the parser (Python keeps
    the last one); a record that is ambiguous that way is dropped instead.
    """
    return json.loads(text, object_pairs_hook=_no_duplicates)


def iter_records(path: str):
    """Yield parsed records; skips unparsable lines and the partial trailing line.

    Only a regular file inside ~/.claude/projects is read (no symlink, FIFO or
    device): the fallback and local resume take these paths from rg and fzf.
    """
    from . import codex

    native = codex.is_path(path)
    root = codex.sessions_dir() if native else util.projects_dir()
    try:
        fh = os.fdopen(util.open_regular(path, root), "rb")
    except (OSError, util.UnsafePath):
        return
    entrypoint, cwd = None, None
    if native:
        from . import session_codex

        match = codex.ROLLOUT_RE.fullmatch(os.path.basename(path))
        index = session_codex.IndexState(match.group(1) if match else None)
    with fh:
        for position, raw in enumerate(fh):
            if not raw.endswith(b"\n"):
                break
            try:
                rec = loads_strict(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if isinstance(rec, dict):
                if native:
                    if not index.accept(rec):
                        continue
                    rec = session_codex.normalize(rec, position=position, entrypoint=entrypoint, cwd=cwd)
                    entrypoint, cwd = rec.get("entrypoint"), rec.get("cwd") or cwd
                yield rec


class LocalSession:
    def __init__(self, path: str):
        from . import codex

        self.path = path
        self.session_id = os.path.basename(path)[:-len(".jsonl")] if path.endswith(".jsonl") else ""
        self.project_dir = os.path.basename(os.path.dirname(path))
        self.agent = "codex" if codex.is_path(path) else "claude"
        if self.agent == "codex":
            match = codex.ROLLOUT_RE.fullmatch(os.path.basename(path))
            self.session_id = match.group(1) if match else ""
        self.title = ""
        self.cwd = ""
        self.cwd_candidates = []
        self.entrypoint = None
        self.hits = 0
        self.last_texts = []
        try:
            self.mtime = os.stat(path).st_mtime
        except OSError:
            self.mtime = 0.0

    @property
    def interactive(self) -> bool:
        from . import session_codex

        return self.entrypoint in ("cli", "claude-desktop") or self.entrypoint in session_codex.INTERACTIVE

    @property
    def resume_cwd(self) -> str:
        for c in self.cwd_candidates:
            if util.encode_cwd(c) == self.project_dir:
                return c
        return self.cwd


def scan(path: str, query: str | None = None, keep_last: int = 4) -> LocalSession:
    """One streaming pass: title, cwd candidates, entrypoint and query hits on `text`."""
    s = LocalSession(path)
    q = (query or "").casefold()
    titles = {"custom": None, "ai": None, "summary": None}
    first_human = None
    for rec in iter_records(path):
        rtype = rec.get("type")
        if not s.cwd and isinstance(rec.get("cwd"), str):
            s.cwd = rec["cwd"]
            s.cwd_candidates.append(rec["cwd"])
        if s.entrypoint is None and isinstance(rec.get("entrypoint"), str):
            s.entrypoint = rec["entrypoint"]
        rc = rec.get("relocatedCwd")
        if isinstance(rc, str) and rc not in s.cwd_candidates:
            s.cwd_candidates.append(rc)
        if rtype == "custom-title" and isinstance(rec.get("customTitle"), str):
            titles["custom"] = rec["customTitle"]
        elif rtype == "ai-title" and isinstance(rec.get("aiTitle"), str):
            titles["ai"] = rec["aiTitle"]
        elif rtype == "summary" and isinstance(rec.get("summary"), str):
            titles["summary"] = rec["summary"]
        text = record_text(rec)
        if not text:
            continue
        if first_human is None and rtype == "user":
            first_human = text
        if q and q in text.casefold():
            s.hits += 1
        s.last_texts.append((rtype, text))
        if len(s.last_texts) > keep_last:
            s.last_texts.pop(0)
    title = titles["custom"] or titles["ai"] or titles["summary"] or first_human or ""
    s.title = " ".join(title.split())[:120]
    return s
