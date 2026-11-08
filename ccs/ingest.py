"""C3 `ccs ingest` — diff, mask and ship transcript bytes (§6.3).

Diff rule, per file, keyed by absolute path in state.json:
  (dev, inode, size, offset, generation, session_key, last_ok)
  - inode change, or size below the stored offset -> generation + 1, offset 0;
  - only complete lines (up to the last \\n) are read; a partial trailing line
    waits for the next run;
  - a segment is at most 4 MiB of raw input, and the cursor moves only after a
    2xx from /ingest.
Server answers handled: 409 {expected_offset} (resync the cursor), 413 (halve
the segment and retry), 422 {lines, kinds} (tombstone those lines and resend).
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import time

from . import VERSION, api as api_mod, config as config_mod, util

MAX_SEGMENT = 4 * 1024 * 1024
MAX_BLOB = 4 * 1024 * 1024
HOOK_BUDGET = 20.0
SWEEP_BUDGET = 120.0
TOMBSTONE_TYPE = "session-search-tombstone"

_MAIN_RE = re.compile(r"^([^/]+)/([^/]+)\.jsonl$")
_SUB_RE = re.compile(r"^([^/]+)/([^/]+)/subagents/(agent-[^/]+)\.jsonl$")


class ShipError(Exception):
    pass


class BudgetExceeded(Exception):
    pass


def tombstone(reason: str, kinds, line_offset: int) -> dict:
    return {"type": TOMBSTONE_TYPE, "reason": reason, "kinds": list(kinds), "line_offset": int(line_offset)}


def _tomb_line(reason, kinds, line_offset) -> str:
    return json.dumps(tombstone(reason, kinds, line_offset), separators=(",", ":"))


def classify(path: str, projects: str | None = None):
    """-> dict(kind, project_dir, session_id, parent_session_id?, agent_id?) or None.

    The layout is read from the path as given (abspath), and the path must also
    resolve inside realpath(~/.claude/projects): a symlink that points elsewhere
    is never a transcript.
    """
    from . import codex

    if codex.is_path(path):
        return codex.classify(path)
    projects = projects or util.projects_dir()
    root = os.path.abspath(projects)
    p = os.path.abspath(path)
    if not p.startswith(root + os.sep) or not util.is_within(p, root):
        return None
    rel = p[len(root) + 1:].replace(os.sep, "/")
    m = _MAIN_RE.match(rel)
    if m:
        return {"kind": "main", "project_dir": m.group(1), "session_id": m.group(2)}
    m = _SUB_RE.match(rel)
    if m:
        # A subagent ships under its PARENT session's UUID (the server validates
        # ^[0-9a-f-]{36}$); agent_id tells the transcripts apart.
        return {"kind": "subagent", "project_dir": m.group(1), "session_id": m.group(2),
                "parent_session_id": m.group(2), "agent_id": m.group(3)[len("agent-"):]}
    return None


def discover(projects: str | None = None):
    """Every main and subagent JSONL under ~/.claude/projects, newest first."""
    from . import codex

    out = list(codex.paths()) if projects is None else []
    projects = projects or util.projects_dir()
    try:
        pdirs = list(os.scandir(projects))
    except OSError:
        return out
    for pd in pdirs:
        if not pd.is_dir(follow_symlinks=False):
            continue
        try:
            entries = list(os.scandir(pd.path))
        except OSError:
            continue
        for e in entries:
            if e.is_file(follow_symlinks=False) and e.name.endswith(".jsonl"):
                out.append(e.path)
            elif e.is_dir(follow_symlinks=False):
                out.extend(subagent_files(e.path))
    out.sort(key=_mtime, reverse=True)
    return out


def subagent_files(session_dir: str):
    """agent-*.jsonl regular files; a symlinked subagents/ dir or entry is skipped."""
    sub = os.path.join(session_dir, "subagents")
    if os.path.islink(sub) or not os.path.isdir(sub):
        return []
    try:
        entries = sorted(os.scandir(sub), key=lambda e: e.name)
    except OSError:
        return []
    return [e.path for e in entries
            if e.name.startswith("agent-") and e.name.endswith(".jsonl") and e.is_file(follow_symlinks=False)]


def _mtime(p):
    try:
        return os.stat(p).st_mtime
    except OSError:
        return 0.0


class State:
    def __init__(self, path: str | None = None):
        self.path = path or util.state_path()
        data = util.read_json(self.path, None)
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("files"), dict):
            data = {"version": 1, "files": {}}
        self.data = data

    @property
    def files(self) -> dict:
        return self.data["files"]

    def save(self) -> None:
        util.atomic_write(self.path, json.dumps(self.data, sort_keys=True, indent=1))


class Shipper:
    def __init__(self, config, api, redactor, key: bytes, state: State, budget: float | None = None,
                 clock=time.monotonic, max_segment: int = MAX_SEGMENT, projects: str | None = None):
        self.config = config
        self.api = api
        self.redactor = redactor
        self.key = key
        self.state = state
        self.clock = clock
        self.deadline = None if budget is None else clock() + budget
        self.max_segment = max_segment
        self.projects = projects or util.projects_dir()
        self.codex_ready = None
        self.codex_deferred_logged = False
        self.stats = {"files": 0, "segments": 0, "bytes": 0, "tombstones": 0, "resyncs": 0, "errors": 0,
                      "blobs": 0, "gone": 0}

    # --- helpers ----------------------------------------------------------
    def _check_budget(self):
        if self.deadline is not None and self.clock() > self.deadline:
            raise BudgetExceeded()

    def _mask_line(self, raw: bytes):
        text = raw.decode("utf-8", "replace")
        try:
            rec = json.loads(text)
        except ValueError:
            masked, counts = self.redactor.redact_text(text, self.key)
            return masked, counts
        masked, counts = self.redactor.redact_record(rec, self.key)
        return json.dumps(masked, ensure_ascii=False, separators=(",", ":")), counts

    def build_body(self, info: dict, path: str, entry: dict, offset: int, end_offset: int, lines) -> dict:
        f = {"session_id": info["session_id"], "project_dir": info["project_dir"],
             "jsonl_path": os.path.abspath(path), "kind": info["kind"]}
        if info.get("source"):
            f["source"] = info["source"]
        if info["kind"] == "subagent":
            f["parent_session_id"] = info["parent_session_id"]
            f["agent_id"] = info["agent_id"]
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        return {
            "client": {"host": self.config.host_label, "client_version": VERSION,
                       "redact_version": self.redactor.RULESET_VERSION},
            "file": f,
            "segment": {"generation": entry["generation"], "offset": offset, "end_offset": end_offset,
                        "sha256": hashlib.sha256(payload).hexdigest(), "lines": list(lines)},
        }

    # --- diff -------------------------------------------------------------
    def entry_for(self, path: str, st) -> dict:
        files = self.state.files
        entry = files.get(path)
        if entry is None:
            entry = {"dev": st.st_dev, "inode": st.st_ino, "size": 0, "offset": 0, "generation": 0,
                     "session_key": None, "last_ok": None}
            files[path] = entry
        elif (entry.get("dev"), entry.get("inode")) != (st.st_dev, st.st_ino) or st.st_size < entry.get("offset", 0):
            entry["generation"] = int(entry.get("generation", 0)) + 1
            entry["offset"] = 0
            entry["dev"], entry["inode"] = st.st_dev, st.st_ino
            entry.pop("blobs", None)
            util.log("INFO", "ingest: %s rewritten or truncated -> generation %d" % (path, entry["generation"]))
        return entry

    def _read_segment(self, fh, offset: int, size: int, limit: int):
        """-> (chunk, kind) with kind in {"lines", "partial", "oversize"}.

        "lines": chunk ends with \\n and holds one or more complete lines.
        "partial": nothing complete to send yet (trailing line without \\n).
        "oversize": chunk is ONE complete line longer than MAX_SEGMENT.
        """
        fh.seek(offset)
        want = min(limit, size - offset)
        data = fh.read(want)
        nl = data.rfind(b"\n")
        if nl >= 0:
            return data[:nl + 1], "lines"
        if offset + len(data) >= size:
            return b"", "partial"
        # First line is longer than `limit`: find its end.
        line = bytearray(data)
        while True:
            more = fh.read(min(1 << 20, size - fh.tell()))
            if not more:
                return b"", "partial"
            i = more.find(b"\n")
            if i >= 0:
                line.extend(more[:i + 1])
                break
            line.extend(more)
        if len(line) > MAX_SEGMENT:
            return bytes(line), "oversize"
        return bytes(line), "lines"

    def ship_file(self, path: str) -> str:
        info = classify(path, self.projects)
        if info is None:
            raise ShipError("not a transcript path under %s" % self.projects)
        if info.get("source") == "codex":
            # Fleet hosts update independently. An old server accepts native
            # lines as unknown records, so never advance a cursor against it.
            if self.codex_ready is None:
                response = self.api.get("/status")
                body = response.json()
                if response.status != 200 or not isinstance(body, dict):
                    raise ShipError("server capability check failed: HTTP %d" % response.status)
                sources = body.get("sources")
                self.codex_ready = isinstance(sources, list) and "codex" in sources
            if not self.codex_ready:
                if not self.codex_deferred_logged:
                    util.log("INFO", "ingest: server has no Codex parser; Codex cursors held until the server is updated")
                    self.codex_deferred_logged = True
                return "deferred"
        # O_NOFOLLOW + fstat S_ISREG + inside realpath(projects); raises UnsafePath.
        from . import codex

        root = codex.sessions_dir() if info.get("source") == "codex" else self.projects
        fd = util.open_regular(path, root)
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            return self._ship_open(path, info, fh, st)

    def _ship_open(self, path, info, fh, st) -> str:
        entry = self.entry_for(path, st)
        if entry["offset"] >= st.st_size:
            entry["size"] = st.st_size
            self._ship_blobs(path, info, entry)
            return "unchanged"
        self.stats["files"] += 1
        limit = self.max_segment
        resyncs = 0
        while entry["offset"] < st.st_size:
            self._check_budget()
            offset = entry["offset"]
            chunk, kind = self._read_segment(fh, offset, st.st_size, limit)
            if kind == "partial":
                break
            if kind == "oversize":
                # Never send a line above the 4 MiB segment cap; keep its place.
                lines, offs, forced = [_tomb_line("too_large", [], offset)], [offset], True
            else:
                lines, offs = self._mask_chunk(chunk, offset)
                forced = False
            outcome = self._send(info, path, entry, offset, offset + len(chunk), lines, offs)
            if outcome == "ok":
                limit = self.max_segment
                if forced:
                    self.stats["tombstones"] += 1
            elif outcome == "resync":
                resyncs += 1
                self.stats["resyncs"] += 1
                if resyncs > 3:
                    raise ShipError("offset resync did not converge")
                if entry["offset"] > st.st_size:
                    # The server is ahead of this file: it holds bytes we do
                    # not. Do not store an offset past EOF (that would read
                    # as a truncation and bump the generation next run).
                    expected = entry["offset"]
                    entry["offset"] = offset
                    raise ShipError("server expects offset %d beyond local size %d" % (expected, st.st_size))
            elif outcome == "too_large":
                if len(lines) > 1:
                    limit = max(1, len(chunk) // 2)
                else:
                    # One line the server will not take even alone: tombstone it.
                    tl = [_tomb_line("too_large", [], offset)]
                    if self._send(info, path, entry, offset, offset + len(chunk), tl, [offset]) != "ok":
                        raise ShipError("tombstone for an oversized line was refused")
                    self.stats["tombstones"] += 1
            self.state.save()
        entry["size"] = st.st_size
        self._ship_blobs(path, info, entry)
        return "shipped"

    def _mask_chunk(self, chunk: bytes, offset: int):
        lines, offs = [], []
        pos = 0
        kinds = {}
        for raw in chunk.split(b"\n")[:-1]:
            line_off = offset + pos
            pos += len(raw) + 1
            if not raw.strip():
                continue
            masked, counts = self._mask_line(raw)
            for k, v in (counts or {}).items():
                kinds[k] = kinds.get(k, 0) + v
            lines.append(masked)
            offs.append(line_off)
        if kinds:
            util.log("INFO", "ingest: masked %s" % ",".join("%s=%d" % kv for kv in sorted(kinds.items())))
        return lines, offs

    def _send(self, info, path, entry, offset, end_offset, lines, offs) -> str:
        """POST one segment; returns ok | resync | too_large. Raises ShipError / Unreachable."""
        lines = list(lines)
        for _attempt in range(3):
            self._check_budget()
            body = self.build_body(info, path, entry, offset, end_offset, lines)
            resp = self.api.post("/ingest", body, gzip_body=True)
            data = resp.json() if resp.body else None
            data = data if isinstance(data, dict) else {}
            if 200 <= resp.status < 300:
                sk = data.get("session_key")
                if isinstance(sk, str) and sk:
                    entry["session_key"] = sk
                nxt = data.get("next_offset", end_offset)
                entry["offset"] = nxt if isinstance(nxt, int) and nxt >= 0 else end_offset
                entry["last_ok"] = util.iso(util.now_utc())
                self.stats["segments"] += 1
                self.stats["bytes"] += end_offset - offset
                return "ok"
            if resp.status == 409:
                exp = data.get("expected_offset")
                if not isinstance(exp, int) or exp < 0:
                    raise ShipError("409 without a usable expected_offset")
                util.log("WARN", "ingest: %s resync offset %d -> %d" % (path, offset, exp))
                entry["offset"] = exp
                return "resync"
            if resp.status == 413:
                util.log("WARN", "ingest: %s segment at %d too large (%d lines)" % (path, offset, len(lines)))
                return "too_large"
            if resp.status == 422:
                idx = data.get("lines")
                kinds = data.get("kinds") or []
                if not isinstance(idx, list) or not idx:
                    raise ShipError("422 without line indexes")
                for i in idx:
                    if not isinstance(i, int) or not 0 <= i < len(lines):
                        raise ShipError("422 named a line outside the segment")
                    line_off = offs[i] if offs and i < len(offs) else offset
                    lines[i] = _tomb_line("unmasked_secret", kinds, line_off)
                    self.stats["tombstones"] += 1
                # Kinds and indexes only — never the line content.
                util.log("WARN", "ingest: %s 422 at offset %d lines=%s kinds=%s -> tombstoned"
                         % (path, offset, idx, ",".join(str(k) for k in kinds)))
                continue
            raise ShipError("/ingest answered HTTP %d%s" % (resp.status, _err_code(data)))
        raise ShipError("segment still rejected after tombstoning")

    # --- side files and gone files ---------------------------------------
    def _ship_blobs(self, path, info, entry):
        if info.get("source") == "codex" or info["kind"] != "main" or not entry.get("session_key"):
            return
        sdir = os.path.join(os.path.dirname(path), info["session_id"])
        tdir = os.path.join(sdir, "tool-results")
        if os.path.islink(sdir) or os.path.islink(tdir):
            util.log("WARN", "ingest: %s is a symlink; tool-results not shipped" % tdir)
            return
        try:
            names = sorted(os.listdir(tdir))
        except OSError:
            return
        sent = entry.setdefault("blobs", {})
        for name in names:
            fp = os.path.join(tdir, name)
            if not util.TOOL_RESULT_NAME_RE.match(name):
                util.log("WARN", "ingest: tool-results name %r does not match %s; not sent"
                         % (name[:80], util.TOOL_RESULT_NAME_RE.pattern))
                continue
            try:
                fd = util.open_regular(fp, self.projects)
            except util.UnsafePath as e:
                util.log("WARN", "ingest: skipped %s" % e)
                continue
            except OSError:
                continue
            with os.fdopen(fd, "rb") as fh:
                if os.fstat(fh.fileno()).st_size > MAX_BLOB:
                    continue
                raw = fh.read(MAX_BLOB + 1)
            if len(raw) > MAX_BLOB:
                continue
            raw_sha = hashlib.sha256(raw).hexdigest()
            if sent.get(name) == raw_sha:
                continue
            self._check_budget()
            content, _counts = self.redactor.redact_text(raw.decode("utf-8", "replace"), self.key)
            body = {"session_key": entry["session_key"], "name": name,
                    "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(), "content": content}
            resp = self.api.post("/blob", body, gzip_body=True)
            if 200 <= resp.status < 300:
                sent[name] = raw_sha
                self.stats["blobs"] += 1
            else:
                util.log("WARN", "ingest: /blob %s answered HTTP %d" % (name, resp.status))

    def report_gone(self):
        for path in list(self.state.files):
            if os.path.exists(path):
                continue
            entry = self.state.files[path]
            sk = entry.get("session_key")
            if sk:
                self._check_budget()
                resp = self.api.post("/state", {"session_key": sk, "jsonl_exists": False})
                if not (200 <= resp.status < 300 or resp.status == 404):
                    util.log("WARN", "ingest: /state for gone %s answered HTTP %d" % (path, resp.status))
                    continue
            del self.state.files[path]
            self.stats["gone"] += 1
        self.state.save()


def _err_code(data) -> str:
    e = data.get("error") if isinstance(data, dict) else None
    return " (%s)" % e if isinstance(e, str) and re.match(r"^[a-z_]{1,40}$", e) else ""


def load_redactor():
    """The cookbook places session_redact.py (owned by the server tree) into this package."""
    from . import session_redact  # noqa: WPS433 — imported lazily so the picker works without it

    return session_redact


class Lock:
    def __init__(self, path: str | None = None):
        self.path = path or util.lock_path()
        self.fh = None

    def acquire(self) -> bool:
        util.ensure_dir(os.path.dirname(self.path))
        self.fh = open(self.path, "a")
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                self.fh.close()
                self.fh = None
                return False
            raise
        return True

    def release(self):
        if self.fh:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None


def run(mode: str, file_path: str | None = None, with_subagents: bool = False, quiet: bool = False,
        redactor=None, api_factory=None) -> int:
    """Entry point for `ccs ingest`. mode: file | sweep | backfill."""
    def say(msg):
        if not quiet:
            print(msg)

    lock = Lock()
    if not lock.acquire():
        util.log("INFO", "ingest: another run holds the lock; exiting")
        return util.EXIT_OK
    try:
        try:
            cfg = config_mod.load()
        except config_mod.NotConfigured as e:
            util.log("INFO", "ingest: %s" % e)
            say("ccs: %s" % e)
            return util.EXIT_OK
        except config_mod.ConfigError as e:
            util.log("ERROR", "ingest: %s" % e)
            say("ccs: %s" % e)
            return util.EXIT_USAGE
        try:
            red = redactor or load_redactor()
        except ImportError:
            util.log("ERROR", "ingest: redactor module session_redact missing — fail closed, nothing shipped")
            say("ccs: redactor missing; nothing shipped")
            return util.EXIT_UNREACHABLE
        try:
            key = red.load_key(cfg.hmac_key_file)
        except Exception as e:  # noqa: BLE001 — KeyMissing, or any read failure: fail closed
            util.log("ERROR", "ingest: HMAC key unavailable (%s) — fail closed, cursor held" % e.__class__.__name__)
            say("ccs: HMAC key unavailable at %s; nothing shipped" % cfg.hmac_key_file)
            return util.EXIT_UNREACHABLE

        api = (api_factory or api_mod.Api)(cfg)
        state = State()
        if mode == "file":
            if classify(file_path) is None:
                util.log("WARN", "ingest: --file %s is not a transcript under %s" % (file_path, util.projects_dir()))
                say("ccs: %s is not a transcript under %s" % (file_path, util.projects_dir()))
                return util.EXIT_USAGE
            files = [os.path.abspath(file_path)]
            if with_subagents:
                files += subagent_files(os.path.join(os.path.dirname(file_path),
                                                     os.path.basename(file_path)[:-len(".jsonl")]))
            budget = HOOK_BUDGET
        elif mode == "sweep":
            files, budget = discover(), SWEEP_BUDGET
        else:
            files, budget = discover(), None
        sh = Shipper(cfg, api, red, key, state, budget=budget)
        code = util.EXIT_OK
        try:
            for path in files:
                try:
                    sh.ship_file(path)
                except FileNotFoundError:
                    continue
                except (ShipError, util.UnsafePath) as e:
                    sh.stats["errors"] += 1
                    util.log("WARN", "ingest: %s: %s" % (path, e))
                except (api_mod.AuthError, config_mod.ConfigError) as e:
                    util.log("ERROR", "ingest: auth: %s" % e)
                    code = util.EXIT_UNREACHABLE
                    break
            if mode == "sweep" and code == util.EXIT_OK:
                sh.report_gone()
        except BudgetExceeded:
            util.log("INFO", "ingest: %s budget of %ss used; the next run continues" % (mode, budget))
        except api_mod.Unreachable as e:
            util.log("WARN", "ingest: server unreachable (%s); cursor held" % e)
            code = util.EXIT_UNREACHABLE
        finally:
            state.save()
        util.log("INFO", "ingest: %s done %s" % (mode, json.dumps(sh.stats, sort_keys=True)))
        say("ccs ingest: %s" % json.dumps(sh.stats, sort_keys=True))
        return code
    finally:
        lock.release()
