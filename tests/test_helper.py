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


@unittest.skipUnless(HAVE_CURL, "curl not on PATH")
class SameBytes(_HelperCase):
    def direct_backend(self, q, prompt="ccs> "):
        out = io.StringIO()
        picker.backend(q, env=dict(self.env, FZF_PROMPT=prompt), out=out)
        return out.getvalue().encode("utf-8")

    def test_backend_rows_identical(self):
        cmd = fzf_sub(bind_cmd(self.argv, "change:reload("), q="query")
        rc, got = self.sh(cmd)
        self.assertEqual(rc, 0)
        self.assertEqual(got, self.direct_backend("query"))
        self.assertEqual(len(got.decode().splitlines()), 2)  # self excluded, as with _backend

    def test_prompt_flags_reach_the_backend(self):
        rc, _ = self.sh(fzf_sub(bind_cmd(self.argv, "change:reload("), q="query"), prompt="ccs:da> ")
        body = self.srv.of("/search")[-1]["body"]
        self.assertEqual((body["deep"], body["include_headless"], body["mode"]), (True, True, "lexical"))

    def test_offline_banner_identical(self):
        os.remove(os.path.join(self.tmp, ".config", "session-search", "config.json"))
        cmd = fzf_sub(bind_cmd(self.argv, "change:reload("), q="nothing here")
        rc, got = self.sh(cmd)
        self.assertEqual(got, self.direct_backend("nothing here"))
        self.assertIn(b"\x1b[33m", got)

    def test_breaker_open_identical(self):
        b = api.Breaker()
        b.record_failure()
        b.record_failure()
        self.assertTrue(b.is_open())
        rc, got = self.sh(fzf_sub(bind_cmd(self.argv, "change:reload("), q="zz"))
        self.assertEqual(got, self.direct_backend("zz"))
        self.assertEqual(self.srv.of("/search"), [])

    def test_preview_identical(self):
        cmd = [a for a in self.argv if a.startswith("curl ") and "/preview" in a][0]
        rc, got = self.sh(fzf_sub(cmd, **{"1": "sk_2", "q": "マージ"}))
        out = io.StringIO()
        picker.preview("sk_2", "マージ", env=dict(self.env), out=out)
        self.assertEqual(rc, 0)
        self.assertEqual(got, out.getvalue().encode("utf-8"))
        self.assertEqual(self.srv.of("/preview")[-1]["query"], {"session_key": "sk_2", "q": "マージ"})

    def test_toggle_identical(self):
        bind = [a for a in self.argv if a.startswith("ctrl-s:")][0]
        cmd = bind[len("ctrl-s:transform-prompt("):bind.index(")+reload(")]
        rc, got = self.sh(cmd, prompt="ccs:d> ")
        self.assertEqual(got, b"ccs:sd> \n")
        self.assertEqual(support.read(self.state), "ccs:sd> ")

    def test_query_text_round_trips(self):
        cmd = bind_cmd(self.argv, "change:reload(")
        for text in ("it's", 'say "hi"', "マージ 認証", "a&b=c", "100% done", "  spaced  out ", "$HOME `id`",
                     "x+y #frag ?q", "back\\slash"):
            rc, _ = self.sh(fzf_sub(cmd, q=text))
            self.assertEqual(rc, 0, text)
            self.assertEqual(self.srv.of("/search")[-1]["body"]["q"], text.strip(), text)

    def test_helper_down_falls_back_to_the_process_command(self):
        self.h.close()
        cmd = fzf_sub(bind_cmd(self.argv, "change:reload("), q="query")
        rc, _ = self.sh(cmd)
        # curl fails, so the `|| ccs _backend` half runs (here a missing binary -> 127)
        self.assertEqual(rc, 127)


class Paths(_HelperCase):
    def test_unknown_paths_and_methods_404(self):
        self.assertEqual(curl_raw(self.sock, "GET /nope"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /backend/x"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /toggle?letter=z"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /toggle?letter=sd"), 404)
        self.assertEqual(curl_raw(self.sock, "POST /backend?q=x"), 404)
        self.assertEqual(curl_raw(self.sock, "DELETE /preview?key=x"), 404)
        self.assertEqual(curl_raw(self.sock, "GET /backend?q=xx"), 200)

    def test_permissions(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.sock).st_mode), 0o600)
        self.assertTrue(stat.S_ISSOCK(os.stat(self.sock).st_mode))

    def test_handler_exception_is_500(self):
        with mock.patch.object(picker, "preview", side_effect=RuntimeError("boom")):
            self.assertEqual(curl_raw(self.sock, "GET /preview?key=k"), 500)


class RunWiring(HomeCase):
    def _run(self, which, runner):
        return picker.run("q", set(), {}, False, False, runner=runner, which=which,
                          resume_fn=lambda key, do_print, fork: 0)

    def test_socket_dir_0700_and_removed_after(self):
        seen = {}

        def runner(argv, **kw):
            sock = [a for a in argv if "--unix-socket" in a][0].split("--unix-socket ", 1)[1].split(" ", 1)[0]
            seen["sock"] = sock
            seen["dir_mode"] = stat.S_IMODE(os.stat(os.path.dirname(sock)).st_mode)
            seen["sock_mode"] = stat.S_IMODE(os.stat(sock).st_mode)
            return subprocess.CompletedProcess(argv, 130, stdout=b"")

        self.assertEqual(self._run(lambda name: "/usr/bin/" + name, runner), 0)
        self.assertEqual((seen["dir_mode"], seen["sock_mode"]), (0o700, 0o600))
        self.assertFalse(os.path.exists(seen["sock"]))
        self.assertFalse(os.path.exists(os.path.dirname(seen["sock"])))

    def test_removed_on_exception(self):
        seen = {}

        def runner(argv, **kw):
            seen["argv"] = argv
            raise OSError("fzf exploded")

        with self.assertRaises(OSError):
            self._run(lambda name: "/usr/bin/" + name, runner)
        sock = [a for a in seen["argv"] if "--unix-socket" in a][0].split("--unix-socket ", 1)[1].split(" ", 1)[0]
        self.assertFalse(os.path.exists(os.path.dirname(sock)))

    def test_removed_on_sigterm(self):
        seen = {}

        def runner(argv, **kw):
            seen["argv"] = argv
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("signal did not unwind")  # pragma: no cover

        before = signal.getsignal(signal.SIGTERM)
        self.assertEqual(self._run(lambda name: "/usr/bin/" + name, runner), 128 + signal.SIGTERM)
        sock = [a for a in seen["argv"] if "--unix-socket" in a][0].split("--unix-socket ", 1)[1].split(" ", 1)[0]
        self.assertFalse(os.path.exists(os.path.dirname(sock)))
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_no_curl_keeps_the_process_wiring(self):
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 130, stdout=b"")

        self._run(lambda name: "/usr/bin/fzf" if name == "fzf" else None, runner)
        self.assertEqual(calls[0], picker.fzf_argv("q", set(), picker.launcher()))
        self.assertNotIn("curl", "\n".join(calls[0]))

    def test_bind_failure_keeps_the_process_wiring(self):
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 130, stdout=b"")

        with mock.patch.object(helper.Helper, "start", side_effect=OSError("EADDRINUSE")):
            self._run(lambda name: "/usr/bin/" + name, runner)
        self.assertNotIn("curl", "\n".join(calls[0]))

    def test_long_tmpdir_moves_the_socket_to_tmp(self):
        long_dir = os.path.join(self.tmp, "x" * 120)
        os.makedirs(long_dir)
        h, sock_dir = picker.start_helper(dict(os.environ), long_dir, which=lambda n: "/usr/bin/curl")
        try:
            self.assertIsNotNone(h)
            self.assertTrue(sock_dir.startswith("/tmp/ccs-"))
            self.assertEqual(stat.S_IMODE(os.stat(sock_dir).st_mode), 0o700)
        finally:
            h.close()
            shutil.rmtree(sock_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
