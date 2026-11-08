"""Persistent picker backend on a private unix socket (§6.6, latency target §9).

Starting `ccs _backend` per keystroke costs ~130 ms before any search happens:
interpreter start plus importing the HTTP stack. The parent `ccs` process stays
alive while fzf runs anyway, so it serves the callbacks itself over a unix
socket inside a 0700 directory, and fzf reaches it with `curl --unix-socket`,
which starts in a few milliseconds.

Paths (GET only; anything else is 404):

    /backend?q=Q&prompt=$FZF_PROMPT&port=$FZF_PORT      what `ccs _backend Q` prints
    /preview?key=K&q=Q&prompt=…&port=…                  what `ccs _preview K Q` prints
    /toggle?letter=L&prompt=…&port=…                    what `ccs _toggle L` prints

The per-keystroke state fzf exports to its children ($FZF_PROMPT, $FZF_PORT)
travels as query parameters; everything else comes from the picker's own env,
which is the env fzf was started with. Queries and rows are never logged.
"""

from __future__ import annotations

import http.server
import io
import os
import re
import secrets
import shlex
import socketserver
import threading
import time
import urllib.parse

from . import api as api_mod, picker, util

HOST = "ccs"  # the Host part of the URL; curl needs one, the socket ignores it
SOCK_NAME = "s"
MAX_SOCK_PATH = 100  # sun_path is 104 bytes on macOS, 108 on Linux
CURL_MAX_TIME = 5


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ccs-helper"
    sys_version = ""

    def log_message(self, *args):  # never log: the request line carries the query
        pass

    def _reply(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlsplit(self.path)
        params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        try:
            text = self.server.ccs_helper.dispatch(u.path, params)
        except Exception:  # noqa: BLE001 — curl -f then runs the per-process fallback
            self._reply(500)
            return
        if text is None:
            self._reply(404)
            return
        self._reply(200, text.encode("utf-8"))

    def _not_found(self):
        self._reply(404)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_found


class Helper:
    """Holds the imported modules, the Api (and its cached token) for the life of the picker."""

    def __init__(self, env, api_factory=None):
        self.env = dict(env)
        self._factory = api_factory or api_mod.Api
        self._api = None
        self._api_key = None
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self.path = None

    # --- lifecycle ------------------------------------------------------------
    def start(self, sock_dir: str) -> str:
        path = os.path.join(sock_dir, SOCK_NAME)
        if len(path.encode("utf-8")) > MAX_SOCK_PATH:
            raise OSError("socket path too long")
        old = os.umask(0o177)
        try:
            server = _Server(path, _Handler)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        server.ccs_helper = self
        self._server = server
        self.path = path
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        return path

    def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self.path:
            try:
                os.unlink(self.path)
            except OSError:
                pass

    # --- request handling ---------------------------------------------------------
    def api(self, cfg):
        key = (cfg.endpoint, cfg.auth_type, getattr(cfg, "client_id", None), getattr(cfg, "token_url", None))
        with self._lock:
            if self._api is None or self._api_key != key:
                self._api = self._factory(cfg)
                self._api_key = key
            else:
                self._api.config = cfg
            return self._api

    def env_for(self, params: dict) -> dict:
        env = dict(self.env)
        env["FZF_PROMPT"] = params.get("prompt", "")
        port = re.sub(r"[^0-9]", "", params.get("port", ""))
        if port:
            env["FZF_PORT"] = port
        else:
            env.pop("FZF_PORT", None)
        return env

    def schedule_fuse(self, q: str, env) -> None:
        """In-process twin of picker.schedule_fuse: a thread instead of a detached `ccs _fuse`."""
        seq = "%d-%s" % (time.time_ns(), secrets.token_hex(4))
        util.atomic_write(picker._seq_path(env), seq)
        t = threading.Thread(target=self._fuse, args=(seq, q, dict(env)), daemon=True)
        t.start()

    def _fuse(self, seq, q, env):
        try:
            picker.fuse(seq, q, env=env, api_factory=self.api)
        except Exception:  # noqa: BLE001 — lexical rows stay on screen, as with `ccs _fuse`
            pass

    def dispatch(self, path: str, params: dict):
        env = self.env_for(params)
        out = io.StringIO()
        if path == "/backend":
            picker.backend(params.get("q", ""), env=env, api_factory=self.api, out=out,
                           fuse_scheduler=self.schedule_fuse)
        elif path == "/preview":
            picker.preview(params.get("key", ""), params.get("q", ""), env=env, api_factory=self.api, out=out)
        elif path == "/toggle":
            letter = params.get("letter", "")
            if len(letter) != 1 or letter not in picker.TOGGLES:
                return None
            out.write(picker.toggle(letter, env) + "\n")
        else:
            return None
        return out.getvalue()


# --- fzf wiring -----------------------------------------------------------------------

def curl_cmd(sock: str, path: str, fields) -> str:
    """A shell command for fzf. `fields` are (name, shell word) pairs; the shell word is
    an fzf placeholder ({q}, {1}, which fzf substitutes shell-quoted) or a literal."""
    words = ["curl", "-fs", "--max-time", str(CURL_MAX_TIME), "--unix-socket", shlex.quote(sock), "-G"]
    for name, word in list(fields) + [("prompt", '"$FZF_PROMPT"'), ("port", '"$FZF_PORT"')]:
        words += ["--data-urlencode", "%s=%s" % (name, word)]
    return "%s http://%s%s" % (" ".join(words), HOST, path)
