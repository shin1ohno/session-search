"""Hermetic test helpers: a temporary $HOME, a fake redactor implementing the frozen
session_redact API, and a scripted fake HTTP server on 127.0.0.1.

All fixtures are synthetic. The fake token below is obviously fake (ghp_ + 36 A).
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import http.server
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest

# Both cookbooks place this canonical server module into the installed client.
# Exercise that exact file when testing the source package as well.
import importlib.util

_adapter = os.path.abspath(os.path.join(os.path.dirname(__file__), "../vendor/memory-mcp/session_codex.py"))
_spec = importlib.util.spec_from_file_location("ccs.session_codex", _adapter)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
sys.modules["ccs.session_codex"] = _module
import urllib.parse

PKG_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PKG_PARENT not in sys.path:
    sys.path.insert(0, PKG_PARENT)

FAKE_TOKEN = "ghp_" + "A" * 36
SID = "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3"
SID2 = "1c7d2e3f-4051-4b6c-9d7e-8f90a1b2c3d4"


class FakeRedactor:
    """Implements the frozen API of session_redact (common.md) for one kind."""

    RULESET_VERSION = "r1"

    class KeyMissing(Exception):
        pass

    _RE = re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")

    def load_key(self, path):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            raise self.KeyMissing(path)
        if not data:
            raise self.KeyMissing(path)
        return data

    def redact_text(self, text, key, version="r1"):
        counts = {}

        def sub(m):
            counts["github-token"] = counts.get("github-token", 0) + 1
            tag = hmac.new(key, m.group(0).encode(), hashlib.sha256).hexdigest()[:8]
            return "[REDACTED:github-token:%s]" % tag

        return self._RE.sub(sub, text), counts

    def redact_record(self, record, key, version="r1"):
        total = {}
        root = json.loads(json.dumps([record]))  # deep copy
        stack = [(root, 0)]
        while stack:
            container, k = stack.pop()
            v = container[k]
            if isinstance(v, str):
                container[k], c = self.redact_text(v, key)
                for kk, n in c.items():
                    total[kk] = total.get(kk, 0) + n
            elif isinstance(v, dict):
                stack.extend((v, kk) for kk in v)
            elif isinstance(v, list):
                stack.extend((v, i) for i in range(len(v)))
        return root[0], total

    def detect_record(self, record, version="r1"):
        return ["github-token"] if self._RE.search(json.dumps(record)) else []


class FakeServer:
    """Scripted server. `handler(req) -> (status, obj_or_bytes, headers)`; every request is recorded."""

    def __init__(self, handler=None):
        self.requests = []
        self.handler = handler or (lambda req: (200, {}, {}))
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = raw
                # Same rule as the real server (sessions_app._json_body): gzip is
                # recognised by its magic bytes, never by a Content-Encoding header.
                if raw[:2] == b"\x1f\x8b":
                    body = gzip.decompress(raw)
                u = urllib.parse.urlsplit(self.path)
                ctype = self.headers.get("Content-Type") or ""
                parsed = None
                if body and "json" in ctype:
                    parsed = json.loads(body.decode("utf-8"))
                elif body and "form" in ctype:
                    parsed = dict(urllib.parse.parse_qsl(body.decode()))
                req = {"method": self.command, "path": u.path, "query": dict(urllib.parse.parse_qsl(u.query)),
                       "headers": dict(self.headers), "raw": raw, "body": parsed}
                outer.requests.append(req)
                status, obj, headers = outer.handler(req)
                data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                try:
                    self.send_response(status)
                    for hk, hv in (headers or {}).items():
                        self.send_header(hk, hv)
                    if "Content-Type" not in (headers or {}):
                        self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (timeout tests)

            do_GET = do_POST = do_DELETE = _do

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.port

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def of(self, path):
        return [r for r in self.requests if r["path"].endswith(path)]


class HomeCase(unittest.TestCase):
    """Each test runs with HOME pointing at a fresh temp dir."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="ccs-test-"))
        self._env = dict(os.environ)
        os.environ["HOME"] = self.tmp
        for k in ("CCS_CONFIG", "FZF_PROMPT", "FZF_PORT", "CCS_PICK", "CCS_PICK_STATE", "CLAUDE_CODE_SESSION_ID",
                  "CODEX_HOME", "CODEX_THREAD_ID"):
            os.environ.pop(k, None)
        self.projects = os.path.join(self.tmp, ".claude", "projects")
        os.makedirs(self.projects)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_config(self, endpoint, auth=None, host="pro-dev"):
        cdir = os.path.join(self.tmp, ".config", "session-search")
        os.makedirs(cdir, exist_ok=True)
        with open(os.path.join(cdir, "hmac.key"), "wb") as fh:
            fh.write(b"test-hmac-key-not-secret")
        cfg = {"endpoint": endpoint, "host_label": host, "auth": auth or {"type": "tailnet"},
               "hmac_key_file": "~/.config/session-search/hmac.key"}
        with open(os.path.join(cdir, "config.json"), "w") as fh:
            json.dump(cfg, fh)
        return cfg

    def project(self, cwd="/work/demo"):
        enc = re.sub(r"[^A-Za-z0-9-]", "-", cwd)
        d = os.path.join(self.projects, enc)
        os.makedirs(d, exist_ok=True)
        return d

    def transcript(self, records, sid=SID, cwd="/work/demo", partial=None):
        d = self.project(cwd)
        p = os.path.join(d, sid + ".jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
            if partial is not None:
                fh.write(partial)
        return p


def read(path, mode="r"):
    with open(path, mode) as fh:
        return fh.read()


def user(text, cwd="/work/demo", entrypoint="cli", **extra):
    r = {"type": "user", "cwd": cwd, "entrypoint": entrypoint, "message": {"role": "user", "content": text}}
    r.update(extra)
    return r


def assistant(text, cwd="/work/demo"):
    return {"type": "assistant", "cwd": cwd, "message": {"role": "assistant",
                                                          "content": [{"type": "text", "text": text}]}}
