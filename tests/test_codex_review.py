"""Regression paths reported in PR #1102, using real JSONL and search calls."""

import hashlib
import datetime
import io
import json
import os
import fcntl
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
import unittest
import uuid
from unittest import mock

import support
from support import SID, SID2, FakeRedactor, FakeServer, HomeCase, user
from ccs import cli, codex, extract, fallback, ingest, picker, resume, util
from ccs.api import Response


def native(kind, payload):
    return {"type": kind, "timestamp": "2026-10-25T00:00:00Z", "payload": payload}


def message(text):
    return native("response_item", {"type": "message", "role": "user",
                                    "content": [{"type": "input_text", "text": text}]})


class ReviewPaths(HomeCase):
    def setUp(self):
        super().setUp()
        self.cwd = os.path.join(self.tmp, "project")
        os.makedirs(self.cwd)
        self.rg = mock.patch.object(fallback, "_run", side_effect=lambda argv, **kw:
                                   subprocess.run(argv, env=self._env, **kw))
        self.rg.start()
        self.addCleanup(self.rg.stop)

    def header(self, sid=SID, **extra):
        return native("session_meta", dict(id=sid, cwd=self.cwd, source="cli", **extra))

    def write_native(self, rows, sid=SID):
        directory = os.path.join(codex.sessions_dir(), "2026", "10", "25")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "rollout-2026-10-25T00-00-00-" + sid + ".jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return path

    def restore(self, rows, sid=SID):
        data = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode()
        class Api:
            def get(self, *a, **kw):
                return Response(200, {"X-Archive-Sha256": hashlib.sha256(data).hexdigest()}, data)
        resume.restore_codex(Api(), {"session_id": sid}, self.cwd, False, "sk_test", io.StringIO())
        return codex.find_local(sid)


    def test_find_local_reads_only_the_matching_header_and_uses_hint_lazily(self):
        target = self.write_native([self.header(), message("needle")])
        other = self.write_native([self.header(SID2), message("other")], sid=SID2)
        with mock.patch.object(codex, "metadata", wraps=codex.metadata) as read:
            self.assertEqual(codex.find_local(SID, hint=other), target)
            self.assertEqual(read.call_count, 1)
        with mock.patch.object(codex, "paths", side_effect=AssertionError("unnecessary walk")):
            self.assertEqual(codex.find_local(SID, hint=target), target)


    def check_resume_cli(self, subagent):
        stamp = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)
        sid = str(uuid.UUID(hex=f"{int(stamp.timestamp() * 1000):012x}" + "71118111111111111111"))
        header = self.header(sid, forked_from_id=SID2, session_id=sid,
                             timestamp="2026-09-01T00:00:00Z", originator="ccs_test", cli_version="0.162.1",
                             model_provider="probe", history_mode="paginated")
        rows = [header, self.header(SID2), message("inherited parent context"),
                native("event_msg", {"type": "thread_settings_applied", "thread_id": sid}),
                message("CCS_RESUME_USER_SENTINEL\u2028Unicode text"),
                native("response_item", {"type": "message", "role": "assistant", "content":
                                          [{"type": "output_text", "text": "CCS_RESUME_ASSISTANT_SENTINEL"}]})]
        if subagent:
            header["payload"].update(subagent_history_start_ordinal=4,
                                      source={"subagent": {"thread_spawn": {"parent_thread_id": SID2,
                                              "depth": 1, "agent_path": "/root/test", "agent_nickname": "Test",
                                              "agent_role": None}}})
        self.restore(rows, sid)
        for name in ("state_5.sqlite", "session_index.jsonl"):
            self.assertFalse(os.path.exists(os.path.join(codex.home(), name)))
        with open(os.path.join(codex.home(), "config.toml"), "w") as f:
            f.write('model_provider = "probe"\nmodel = "probe-model"\n'
                    '[model_providers.probe]\nname = "Probe"\nbase_url = "http://127.0.0.1:9/v1"\n'
                    'wire_api = "responses"\nenv_key = "CCS_PROBE_KEY"\n')
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 140, 0, 0))
        def terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        env = dict(os.environ, TERM="xterm-256color", CODEX_HOME=codex.home(), CCS_PROBE_KEY="local-test-only")
        for name in ("CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_MANAGED_PACKAGE_ROOT", "CODEX_PERMISSION_PROFILE"):
            env.pop(name, None)
        p = subprocess.Popen([os.environ["CCS_TEST_CODEX"], "--no-daemon", "resume", sid,
                              "--no-alt-screen", "-C", self.cwd],
                             stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=terminal)
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and p.poll() is None:
                if not select.select([master], [], [], 0.2)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                output.extend(chunk)
                if b"\x1b[6n" in chunk:
                    os.write(master, b"\x1b[1;1R")
                if b"\x1b[?u" in chunk:
                    os.write(master, b"\x1b[?0u")
                if b"trust" in chunk.lower():
                    os.write(master, b"\r")
                if b"CCS_RESUME_ASSISTANT_SENTINEL" in output:
                    break
            plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output.decode("utf-8", "replace"))
            self.assertIn("CCS_RESUME_USER_SENTINEL", plain)
            self.assertIn("CCS_RESUME_ASSISTANT_SENTINEL", plain)
            self.assertNotIn("No saved session found", plain)
        finally:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
            os.close(master)


if __name__ == "__main__":
    unittest.main()
