"""Exercise the callbacks fzf actually receives from a live CLI process."""
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import stat
import subprocess
import sys
import time
import unittest

from contract.harness import ClientCase, FakeServer, SID

SESSIONS = {"sessions": [
    {"session_key": "sk_1", "session_id": SID, "host": "pro-dev", "title": "local one", "cwd": "/w",
     "updated_at": "2026-10-01T00:00:00Z", "hit_count": 3, "jsonl_exists": True, "archived": False},
    {"session_key": "sk_2", "session_id": "other", "host": "mini", "title": "リモート セッション", "cwd": "/w",
     "updated_at": "2026-10-01T00:00:00Z", "hit_count": 1, "archived": True, "archive_complete": True},
    {"session_key": "sk_3", "session_id": "me", "host": "pro-dev", "title": "self"}]}
PREVIEW = {"session": {"title": "t <x>", "host": "mini", "cwd": "/w", "updated_at": "2026-10-01T00:00:00Z",
                       "archived": True, "archive_complete": True},
           "snippets": [{"ts": "2026-10-01T00:00:00Z", "role": "user", "fragment": "a <em>マージ</em> b"}]}


class HelperBase(ClientCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeServer(lambda req: (200, PREVIEW if req["path"].endswith("/preview") else SESSIONS, {}))
        self.addCleanup(self.srv.close)
        self.write_config(self.srv.base)
        self.env["CLAUDE_CODE_SESSION_ID"] = "me"

    def start_picker(self, prefix=(), env=None):
        capture = Path(self.tmp) / "fzf-live.json"
        self.release = Path(self.tmp) / "fzf-release"
        self.fake("fzf", "import json, os, sys, time\nfrom pathlib import Path\n"
                  "p = Path(os.environ['HOME'])\n"
                  "data = {'argv': sys.argv[1:], 'env': {k: os.environ[k] for k in ('CCS_PICK', 'CCS_PICK_STATE', 'CCS_LAUNCHER', 'FZF_API_KEY')}}\n"
                  "(p / 'fzf-live.tmp').write_text(json.dumps(data))\n"
                  "(p / 'fzf-live.tmp').replace(p / 'fzf-live.json')\n"
                  "while not (p / 'fzf-release').exists(): time.sleep(0.01)\n"
                  "raise SystemExit(130)\n")
        self.child_env = dict(self.env, **(env or {}))
        self.proc = subprocess.Popen(list(prefix) + self.command + ["query"], env=self.child_env, cwd=self.tmp,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(self.finish_picker)
        deadline = time.monotonic() + 10
        while not capture.exists() and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.fail("picker exited before fzf: " + repr(self.proc.communicate()))
            time.sleep(0.01)
        self.assertTrue(capture.exists(), "fzf did not start")
        data = json.loads(capture.read_text())
        self.argv = data["argv"]
        self.child_env.update(data["env"])
        self.sock = None
        for arg in self.argv:
            if "CCS_HELPER_SOCKET=" in arg:
                command = arg.split("(", 1)[-1]
                self.sock = shlex.split(command)[0].split("=", 1)[1]
                break
            if "--unix-socket" in arg:
                words = shlex.split(arg.split("(", 1)[-1])
                self.sock = words[words.index("--unix-socket") + 1]
                break
        if self.sock is None:
            directory = Path(data["env"]["CCS_PICK_STATE"]).parent
            sockets = [p for p in directory.iterdir() if stat.S_ISSOCK(p.stat().st_mode)]
            self.sock = str(sockets[0]) if sockets else None

    def finish_picker(self):
        self.release.touch()
        try:
            out, err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            out, err = self.proc.communicate(timeout=5)
            self.fail("picker did not exit: " + repr((out, err)))
        if not hasattr(self, "picker_output"):
            self.picker_output = (out, err)
        return self.proc.returncode

    def callback(self, prefix, **values):
        arg = next(a for a in self.argv if a.startswith(prefix))
        command = arg[len(prefix):-1]
        for key, value in values.items():
            command = command.replace("{" + key + "}", shlex.quote(value))
        return command

    def invoke(self, command, prompt="ccs> "):
        return subprocess.run(["/bin/sh", "-c", command], env=dict(self.child_env, FZF_PROMPT=prompt),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def backend_command(self, query):
        return self.callback("change:reload(", q=query)


class SameBytes(HelperBase):
    def setUp(self):
        super().setUp()
        self.start_picker()

    def test_backend_rows_identical(self):
        result = self.invoke(self.backend_command("query"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.rows("query").encode())
        self.assertEqual(len(result.stdout.decode().splitlines()), 2)

    def test_prompt_flags_reach_the_backend(self):
        self.assertEqual(self.invoke(self.backend_command("query"), "ccs:da> ").returncode, 0)
        body = self.srv.of("/search")[-1]["body"]
        self.assertEqual((body["deep"], body["include_headless"], body["mode"]), (True, True, "lexical"))

    def test_offline_banner_identical(self):
        (Path(self.tmp) / ".config/session-search/config.json").unlink()
        result = self.invoke(self.backend_command("nothing here"))
        self.assertEqual(result.stdout, self.rows("nothing here").encode())
        self.assertIn(b"\x1b[33m", result.stdout)

    def test_breaker_open_identical(self):
        self.write_breaker(2, time.time() + 60)
        result = self.invoke(self.backend_command("zz"))
        self.assertEqual(result.stdout, self.rows("zz").encode())
        self.assertEqual(self.srv.of("/search"), [])

    def test_preview_identical(self):
        command = self.argv[self.argv.index("--preview") + 1]
        command = command.replace("{1}", shlex.quote("sk_2")).replace("{q}", shlex.quote("マージ"))
        result = self.invoke(command)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, self.good("_preview", "sk_2", "マージ").stdout.encode())
        self.assertEqual(self.srv.of("/preview")[-1]["query"], {"session_key": "sk_2", "q": "マージ"})

    def test_toggle_identical(self):
        bind = next(a for a in self.argv if a.startswith("ctrl-s:"))
        command = bind[len("ctrl-s:transform-prompt("):bind.index(")+reload(")]
        result = self.invoke(command, "ccs:d> ")
        self.assertEqual(result.stdout, b"ccs:sd> \n")
        self.assertEqual(Path(self.child_env["CCS_PICK_STATE"]).read_text(), "ccs:sd> ")

    def test_query_text_round_trips(self):
        for query in ("it's", 'say "hi"', "マージ 認証", "a&b=c", "100% done", "  spaced  out ",
                      "$HOME `id`", "x+y #frag ?q", "back\\slash"):
            self.assertEqual(self.invoke(self.backend_command(query)).returncode, 0)
            self.assertEqual(self.srv.of("/search")[-1]["body"]["q"], query.strip())

    def test_helper_down_falls_back_to_the_process_command(self):
        self.assertIsNotNone(self.sock)
        os.unlink(self.sock)
        result = self.invoke(self.backend_command("query"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.rows("query").encode())

    def raw_helper(self, request):
        import socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(self.sock)
            connection.sendall((request + " HTTP/1.0\r\nHost: ccs\r\n\r\n").encode())
            chunks = []
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                chunks.append(data)
        return int(b"".join(chunks).split(b" ", 2)[1])

    def test_unknown_paths_methods_and_invalid_toggle_are_404(self):
        for request in ("GET /nope", "GET /backend/x", "GET /toggle?letter=z", "GET /toggle?letter=sd",
                        "POST /backend?q=x", "DELETE /preview?key=x", "HEAD /backend"):
            self.assertEqual(self.raw_helper(request), 404)
        self.assertEqual(self.raw_helper("GET /backend?q=xx"), 200)

    def test_handler_exception_is_500(self):
        self.srv.handler = lambda req: (200, [1], {})
        self.assertEqual(self.raw_helper("GET /preview?key=key"), 500)

    def test_permissions(self):
        self.assertIsNotNone(self.sock)
        self.assertEqual(stat.S_IMODE(os.stat(self.sock).st_mode), 0o600)
        self.assertTrue(stat.S_ISSOCK(os.stat(self.sock).st_mode))


class RunWiring(HelperBase):
    def test_socket_dir_0700_and_removed_after(self):
        self.start_picker()
        self.assertIsNotNone(self.sock)
        directory = Path(self.sock).parent
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(self.finish_picker(), 0)
        self.assertFalse(directory.exists())

    def test_removed_on_sigterm(self):
        self.start_picker()
        directory = Path(self.sock).parent
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.finish_picker(), 143)
        self.assertFalse(directory.exists())

    def test_removed_on_sighup(self):
        self.start_picker()
        directory = Path(self.sock).parent
        self.proc.send_signal(signal.SIGHUP)
        self.assertEqual(self.finish_picker(), 129)
        self.assertFalse(directory.exists())

    def test_removed_on_sigint(self):
        self.start_picker()
        directory = Path(self.sock).parent
        self.proc.send_signal(signal.SIGINT)
        status = self.finish_picker()
        self.assertEqual(status if status >= 0 else 128 - status, 130)
        self.assertFalse(directory.exists())

    @unittest.skipUnless(os.environ.get("CCS_RUST_CLIENT") == "1", "Rust D7 helper without curl")
    def test_helper_runs_without_curl(self):
        (self.bin / "curl").unlink(missing_ok=True)
        self.start_picker()
        self.assertIsNotNone(self.sock, "D7 lost the persistent helper without curl")
        self.assertNotIn("curl", "\n".join(self.argv))
        result = self.invoke(self.backend_command("query"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.rows("query").encode())

    @unittest.skipUnless(sys.platform == "linux" and platform.machine() in ("x86_64", "aarch64"),
                         "bind fault injection requires the Linux syscall ABI")
    def test_bind_failure_keeps_the_process_wiring(self):
        prefix = [sys.executable, str(Path(__file__).with_name("deny_bind.py"))]
        # Prove that failure is our injected errno, not a launcher/environment failure.
        probe = subprocess.run(prefix + [sys.executable, "-c", "import socket,errno\n"
                               "s=socket.socket(socket.AF_UNIX)\n"
                               "try: s.bind('unused')\n"
                               "except OSError as e: assert e.errno==errno.EADDRINUSE\n"
                               "else: raise AssertionError('bind unexpectedly worked')\n"
                               "finally: s.close()"], env=self.env, cwd=self.tmp, capture_output=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.start_picker(prefix=prefix)
        self.assertIsNone(self.sock)
        result = self.invoke(self.backend_command("query"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.rows("query").encode())

    def test_long_tmpdir_moves_the_socket_to_tmp(self):
        long_dir = Path(self.tmp) / ("x" * 120)
        long_dir.mkdir()
        self.start_picker(env={"TMPDIR": str(long_dir)})
        self.assertIsNotNone(self.sock)
        self.assertTrue(str(Path(self.sock).parent).startswith("/tmp/ccs-"))
        self.assertEqual(stat.S_IMODE(Path(self.sock).parent.stat().st_mode), 0o700)
