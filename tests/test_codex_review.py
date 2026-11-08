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

    def test_fork_archive_accepts_ancestor_metadata_and_keeps_child_identity(self):
        rows = [self.header(forked_from_id=SID2), self.header(SID2), message("parent context"),
                native("event_msg", {"type": "thread_settings_applied", "thread_id": SID}),
                message("child question")]
        path = self.restore(rows)
        with open(path) as f:
            restored = [json.loads(line) for line in f]
        self.assertEqual([r["payload"]["id"] for r in restored if r["type"] == "session_meta"], [SID])
        self.assertIn("parent context", json.dumps(restored))
        self.assertEqual(extract.scan(path).title, "child question")
        self.assertEqual(codex.metadata(path)["cwd"], self.cwd)

    def test_subagent_archive_rebases_its_inherited_prefix_after_conversion(self):
        header = self.header(forked_from_id=SID2, subagent_history_start_ordinal=4)
        header["payload"]["source"] = {"subagent": {}}
        rows = [header, self.header(SID2), message("parent context"),
                native("turn_context", {"cwd": "/old"}), message("child work")]
        for ordinal, row in enumerate(rows):
            row["ordinal"] = ordinal
        path = self.restore(rows)
        self.assertEqual(extract.scan(path).title, "child work")
        self.assertFalse(extract.scan(path).interactive)

    def test_jsonl_unicode_separators_roundtrip(self):
        text = "before\u2028middle\u2029more\u0085end\x1c\x1d\x1e"
        path = self.restore([self.header(), message(text)])
        with open(path, "rb") as f:
            records = [json.loads(raw) for raw in f.read().split(b"\n") if raw]
        messages = [r["payload"] for r in records if r["type"] == "response_item"]
        self.assertEqual(messages[0]["content"][0]["text"], text)

    def test_subagent_boundary_is_rebased_without_optional_parent_link(self):
        header = self.header(subagent_history_start_ordinal=5)
        header["payload"]["source"] = {"subagent": {}}
        rows = [header, self.header(SID2), message("parent context"),
                native("turn_context", {"cwd": "/parent"}), native("world_state", {}), message("child question")]
        path = self.restore(rows)
        self.assertEqual(extract.scan(path).title, "child question")
        self.assertFalse(extract.scan(path).interactive)

    def test_old_and_unknown_sources_remain_in_default_offline_results(self):
        for source in (None, "future_source", {"custom": "desktop"}):
            header = self.header()
            header["payload"]["source"] = source
            path = self.write_native([header, message("needle")])
            self.assertEqual(extract.scan(path).entrypoint, "codex-unknown")
            self.assertEqual([s.path for s in fallback.search("needle")], [path])
        del header["payload"]["source"]
        self.write_native([header, message("needle")])
        self.assertTrue(extract.scan(path).interactive)

    def test_structured_search_excludes_current_session_online_and_offline(self):
        srv = FakeServer(lambda req: (200, {"sessions": [
            {"session_id": SID, "session_key": "sk_current"},
            {"session_id": SID2, "session_key": "sk_past"}]}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.write_native([self.header(), message("needle")])
        self.transcript([user("needle")], sid=SID2)
        for variable in ("CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID"):
            with mock.patch.dict(os.environ, {variable: SID}):
                _, ns = cli.parse(["search", "needle", "--limit", "1"])
                out = io.StringIO()
                self.assertEqual(cli.cmd_search(ns, out), 0)
                self.assertEqual([r["session_id"] for r in json.loads(out.getvalue())["sessions"]], [SID2])
                _, ns = cli.parse(["search", "needle", "--offline"])
                out = io.StringIO()
                self.assertEqual(cli.cmd_search(ns, out), 0)
                self.assertEqual([r["session_id"] for r in json.loads(out.getvalue())["sessions"]], [SID2])

    def test_find_local_reads_only_the_matching_header_and_uses_hint_lazily(self):
        target = self.write_native([self.header(), message("needle")])
        other = self.write_native([self.header(SID2), message("other")], sid=SID2)
        with mock.patch.object(codex, "metadata", wraps=codex.metadata) as read:
            self.assertEqual(codex.find_local(SID, hint=other), target)
            self.assertEqual(read.call_count, 1)
        with mock.patch.object(codex, "paths", side_effect=AssertionError("unnecessary walk")):
            self.assertEqual(codex.find_local(SID, hint=target), target)

    def test_old_server_defers_many_rollouts_with_one_info_and_no_errors(self):
        self.write_native([self.header(), message("first")])
        self.write_native([self.header(SID2), message("second")], sid=SID2)
        srv = FakeServer(lambda req: (200, {"parser_version": "p1"}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        out = io.StringIO()
        with mock.patch.object(util, "log") as log, mock.patch("sys.stdout", out):
            self.assertEqual(ingest.run("sweep", redactor=FakeRedactor()), 0)
        deferred = [c for c in log.call_args_list if "cursors held" in c.args[1]]
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].args[0], "INFO")
        self.assertFalse(any(c.args[0] in ("WARN", "ERROR") for c in log.call_args_list))
        self.assertEqual(ingest.State().files, {})
        self.assertEqual(len(srv.of("/status")), 1)
        self.assertIn('"errors": 0', out.getvalue())

    def test_codex_context_matches_cannot_evict_older_claude_conversation(self):
        for index in range(fallback.CANDIDATE_CAP + 1):
            sid = "%08d-0000-0000-0000-000000000000" % index
            header = self.header(sid)
            header["payload"]["base_instructions"] = "commit instructions repeated everywhere"
            self.write_native([header, message("unrelated")], sid=sid)
        old = self.transcript([user("the commit we discussed")], sid=SID2)
        os.utime(old, (100, 100))
        self.assertEqual([s.path for s in fallback.search("commit")], [old])

    def test_missing_directories_are_reported_for_empty_and_nonempty_queries(self):
        os.rmdir(self.projects)
        for q in ("", "needle"):
            with self.assertRaises(fallback.FallbackUnavailable):
                fallback.search(q)
            rows = picker.offline_rows(q, set(), {}, "host", env={})
            self.assertIn("no local transcript directories", rows[1])

    @unittest.skipUnless(os.environ.get("CCS_TEST_CODEX"), "set CCS_TEST_CODEX to a native Codex binary")
    def test_resume_cli_finds_restored_fork_without_an_index_database(self):
        self.check_resume_cli(False)

    @unittest.skipUnless(os.environ.get("CCS_TEST_CODEX"), "set CCS_TEST_CODEX to a native Codex binary")
    def test_resume_cli_finds_restored_subagent_without_an_index_database(self):
        self.check_resume_cli(True)

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
