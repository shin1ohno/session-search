"""The persistent picker helper (ccs.helper): same bytes as the per-process callbacks."""

import io
import json
import os
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import support
from support import SID, FakeServer, HomeCase

from ccs import api, helper, picker

HAVE_CURL = bool(shutil.which("curl"))

SESSIONS = {"sessions": [
    {"session_key": "sk_1", "session_id": SID, "host": "pro-dev", "title": "local one", "cwd": "/w",
     "updated_at": "2026-10-01T00:00:00Z", "hit_count": 3, "jsonl_exists": True, "archived": False,
     "archive_complete": False},
    {"session_key": "sk_2", "session_id": "other", "host": "mini", "title": "リモート セッション",
     "cwd": "/w", "updated_at": "2026-10-01T00:00:00Z", "hit_count": 1, "jsonl_exists": True,
     "archived": True, "archive_complete": True},
    {"session_key": "sk_3", "session_id": "me", "host": "pro-dev", "title": "self", "cwd": "/w",
     "updated_at": "2026-10-01T00:00:00Z", "jsonl_exists": True}], "took_ms": 3}

PREVIEW = {"session": {"title": "t <x>", "host": "mini", "cwd": "/w", "updated_at": "2026-10-01T00:00:00Z",
                       "archived": True, "archive_complete": True},
           "snippets": [{"ts": "2026-10-01T00:00:00Z", "role": "user", "fragment": "a <em>マージ</em> b"}]}


def handler(req):
    if req["path"].endswith("/search"):
        return 200, SESSIONS, {}
    if req["path"].endswith("/preview"):
        return 200, PREVIEW, {}
    return 404, {}, {}


def fzf_sub(cmd, **values):
    """Substitute fzf placeholders the way fzf does: each value single-quoted for the shell."""
    for name, value in values.items():
        cmd = cmd.replace("{%s}" % name, shlex.quote(value))
    return cmd


def bind_cmd(argv, prefix):
    """The shell command inside `change:reload(...)` / `--preview`."""
    for a in argv:
        if a.startswith(prefix):
            return a[len(prefix):-1] if prefix.endswith("(") else a[len(prefix):]
    raise AssertionError("no bind %r" % prefix)


def curl_raw(sock, path_qs):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock)
        s.sendall(("%s HTTP/1.0\r\nHost: ccs\r\n\r\n" % path_qs).encode())
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    finally:
        s.close()
    head = b"".join(chunks).split(b"\r\n", 1)[0].decode()
    return int(head.split()[1])


class _HelperCase(HomeCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeServer(handler)
        self.write_config(self.srv.base + "/memory/sessions/v1")
        self.sock_dir = tempfile.mkdtemp(prefix="ccs-h-", dir="/tmp")
        self.state = os.path.join(self.sock_dir, "prompt")
        self.env = dict(os.environ)
        self.env.update({"CCS_PICK": json.dumps({"flags": ""}), "CCS_PICK_STATE": self.state,
                         "CLAUDE_CODE_SESSION_ID": "me", "CCS_LAUNCHER": "/nonexistent/ccs"})
        self.h = helper.Helper(self.env)
        self.sock = self.h.start(self.sock_dir)
        self.argv = picker.fzf_argv("", set(), "/nonexistent/ccs", helper_sock=self.sock)

    def tearDown(self):
        self.h.close()
        self.srv.close()
        shutil.rmtree(self.sock_dir, ignore_errors=True)
        super().tearDown()

    def sh(self, cmd, prompt="ccs> "):
        env = dict(self.env, FZF_PROMPT=prompt)
        env.pop("FZF_PORT", None)
        p = subprocess.run(["/bin/sh", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        return p.returncode, p.stdout


class Paths(_HelperCase):
    def test_unknown_paths_and_methods_404(self):
        self.assertEqual(curl_raw(self.sock, "GET /nope"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /backend/x"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /toggle?letter=z"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /toggle?letter=sd"), 404)
        self.assertEqual(curl_raw(self.sock, "POST /backend?q=x"), 404)
        self.assertEqual(curl_raw(self.sock, "DELETE /preview?key=x"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /backend?q=xx"), 200)


    def test_handler_exception_is_500(self):
        with mock.patch.object(picker, "preview", side_effect=RuntimeError("boom")):
            self.assertEqual(curl_raw(self.sock, "GET /preview?key=k"), 500)


class RunWiring(HomeCase):
    def _run(self, which, runner):
        return picker.run("q", set(), {}, False, False, runner=runner, which=which,
                          resume_fn=lambda key, do_print, fork: 0)


    def test_removed_on_exception(self):
        seen = {}

        def runner(argv, **kw):
            seen["argv"] = argv
            raise OSError("fzf exploded")

        with self.assertRaises(OSError):
            self._run(lambda name: "/usr/bin/" + name, runner)
        sock = [a for a in seen["argv"] if "--unix-socket" in a][0].split("--unix-socket ", 1)[1].split(" ", 1)[0]
        self.assertFalse(os.path.exists(os.path.dirname(sock)))


if __name__ == "__main__":
    unittest.main()
