import contextlib
import hashlib
import io
import json
import os
import selectors
import subprocess
import time
import unittest

import support
from support import SID, FAKE_TOKEN, FakeRedactor, FakeServer, HomeCase
from ccs import cli, codex, extract, fallback, ingest, resume, util


def native(kind, payload):
    return {"type": kind, "timestamp": "2026-10-25T00:00:00Z", "payload": payload}


class CodexClient(HomeCase):
    def setUp(self):
        super().setUp()
        self.cwd = os.path.join(self.tmp, "work")
        os.makedirs(self.cwd)
        self.path = os.path.join(codex.sessions_dir(), "2026", "10", "25",
                                 "rollout-2026-10-25T00-00-00-" + SID + ".jsonl")
        os.makedirs(os.path.dirname(self.path))
        self.rows = [native("session_meta", {"id": SID, "cwd": self.cwd, "source": "vscode"}),
                     native("response_item", {"type": "message", "role": "user", "content":
                                               [{"type": "input_text", "text": "Codex history search"}]}),
                     native("response_item", {"type": "message", "role": "assistant", "content":
                                               [{"type": "output_text", "text": "Found the regression"}]})]
        self.write_rows()

    def write_rows(self):
        with open(self.path, "w") as f:
            for r in self.rows:
                f.write(json.dumps(r) + "\n")

    def test_discover_extract_and_offline_search(self):
        self.assertIn(self.path, ingest.discover())
        info = ingest.classify(self.path)
        self.assertEqual(info["source"], "codex")
        self.assertTrue(info["project_dir"].startswith("codex-"))
        s = extract.scan(self.path, "regression")
        self.assertEqual(s.session_id, SID)
        self.assertEqual(s.agent, "codex")
        self.assertTrue(s.interactive)
        self.assertEqual(s.hits, 1)
        self.assertEqual(s.title, "Codex history search")
        found = fallback.search("regression")
        self.assertEqual([s.path for s in found], [self.path])

    def test_unsafe_and_mismatched_rollout_rejected(self):
        alias = self.path.replace("00-00-00-", "00-00-01-")
        os.symlink(self.path, alias)
        self.assertIsNone(ingest.classify(alias))
        self.rows[0]["payload"]["id"] = "bad-id"
        self.write_rows()
        self.assertIsNone(ingest.classify(self.path))

    def test_codex_only_host_and_offline_host_filter(self):
        os.rmdir(self.projects)
        self.assertEqual([s.path for s in fallback.search("regression")], [self.path])
        self.write_config("http://127.0.0.1:1", host="pro-dev")
        _, ns = cli.parse(["search", "regression", "--offline", "--host", "mini"])
        out = io.StringIO()
        self.assertEqual(cli.cmd_search(ns, out), 0)
        self.assertEqual(json.loads(out.getvalue())["sessions"], [])

    def test_local_resume_and_fork_select_codex(self):
        for fork in (False, True):
            calls = []
            code = resume.resume("local:" + self.path, fork=fork,
                                 execvp=lambda f, a: calls.append((f, a)), chdir=lambda d: None)
            self.assertEqual(code, 0)
            self.assertEqual(calls, [("codex", ["codex", "fork" if fork else "resume", SID])])
        out = io.StringIO()
        self.assertEqual(resume.resume("local:" + self.path, do_print=True, out=out), 0)
        self.assertIn("codex resume " + SID, out.getvalue())

    def test_ingest_masks_native_records_and_retries_no_bytes(self):
        self.rows.append(native("response_item", {"type": "message", "role": "user", "content":
                                                  [{"type": "input_text", "text": FAKE_TOKEN}]}))
        self.write_rows()
        def handler(req):
            if req["path"].endswith("/status"):
                return 200, {"sources": ["claude", "codex"]}, {}
            segment = req["body"]["segment"]
            return 200, {"session_key": "sk_native", "next_offset": segment["end_offset"]}, {}
        srv = FakeServer(handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.assertEqual(ingest.run("sweep", redactor=FakeRedactor(), quiet=True), 0)
        bodies = [r["body"] for r in srv.of("/ingest")]
        self.assertEqual(len(bodies), 1)
        self.assertEqual(json.loads(bodies[0]["segment"]["lines"][0])["type"], "session_meta")
        self.assertNotIn(FAKE_TOKEN, json.dumps(bodies))
        self.assertIn("REDACTED", json.dumps(bodies))
        self.assertEqual(ingest.run("sweep", redactor=FakeRedactor(), quiet=True), 0)
        self.assertEqual(len(srv.of("/ingest")), 1)

    def test_old_server_holds_codex_cursor(self):
        srv = FakeServer(lambda req: (200, {"parser_version": "p1"}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.assertEqual(ingest.run("sweep", redactor=FakeRedactor(), quiet=True), 0)
        self.assertEqual(srv.of("/ingest"), [])
        self.assertNotIn(self.path, ingest.State().files)

    def test_structured_search_and_preview(self):
        def handler(req):
            row = {"session_key": "sk_native", "session_id": SID, "entrypoint": "codex-vscode"}
            if req["path"].endswith("/search"):
                return 200, {"sessions": [row]}, {}
            return 200, {"session": row, "snippets": [{"fragment": "matching text"}]}, {}
        srv = FakeServer(handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        command, ns = cli.parse(["search", "history", "--semantic", "--all", "--limit", "3"])
        self.assertEqual(command, "search")
        out = io.StringIO()
        self.assertEqual(cli.cmd_search(ns, out), 0)
        self.assertEqual(json.loads(out.getvalue())["sessions"][0]["agent"], "codex")
        body = srv.of("/search")[0]["body"]
        self.assertEqual((body["mode"], body["include_headless"], body["limit"]), ("hybrid", True, 3))
        out = io.StringIO()
        self.assertEqual(cli.cmd_preview("sk_native", "history", out), 0)
        self.assertEqual(json.loads(out.getvalue())["session"]["agent"], "codex")

    def test_restore_native_archive_is_local_and_hash_checked(self):
        self.rows.append(native("turn_context", {"cwd": "/remote", "approval_policy": "never",
                                                 "sandbox_policy": {"type": "danger-full-access"}}))
        archive = ("\n".join(json.dumps(r) for r in self.rows) + "\n").encode()
        meta = {"session_id": SID, "entrypoint": "codex-vscode"}
        class Api:
            def get(self, *a, **kw):
                from ccs.api import Response
                return Response(200, {"X-Archive-Sha256": hashlib.sha256(archive).hexdigest()}, archive)
        # A separate local CODEX_HOME models a restore onto another host.
        os.environ["CODEX_HOME"] = os.path.join(self.tmp, "restored-codex")
        resume.restore_codex(Api(), meta, self.cwd, False, "sk_native", io.StringIO())
        restored = codex.find_local(SID)
        self.assertIsNotNone(restored)
        self.assertEqual(codex.metadata(restored)["cwd"], self.cwd)
        with open(restored) as f:
            records = [json.loads(line) for line in f]
        self.assertFalse(any(r["type"] == "turn_context" for r in records))
        self.assertEqual(records[0]["payload"]["history_mode"], "legacy")
        self.assertEqual(extract.scan(restored).title, "Codex history search")
        class CorruptApi:
            def get(self, *a, **kw):
                from ccs.api import Response
                return Response(200, {"X-Archive-Sha256": "0" * 64}, archive)
        with self.assertRaises(resume.ResumeError):
            resume.restore_codex(CorruptApi(), meta, self.cwd, True, "sk_native")
        # A symlinked date directory must never redirect a later restore.
        day = os.path.dirname(restored)
        outside = os.path.join(self.tmp, "outside-codex")
        os.rename(day, outside)
        os.symlink(outside, day)
        with self.assertRaises(resume.ResumeError):
            resume.restore_codex(Api(), meta, self.cwd, True, "sk_native")

    @unittest.skipUnless(os.environ.get("CCS_TEST_CODEX"), "set CCS_TEST_CODEX to a native Codex binary")
    def test_restored_paginated_history_is_readable_by_codex(self):
        self.rows[0]["payload"].update(timestamp="2026-10-25T00:00:00Z", originator="ccs_test",
                                        cli_version="0.162.1", model_provider="openai", history_mode="paginated")
        # Migration can leave legacy display events before newer items whose
        # display data exists only in SQLite. Both halves must survive import.
        self.rows.extend([native("event_msg", {"type": "user_message", "message": "Codex history search",
                                               "images": [], "local_images": [], "text_elements": []}),
                          native("event_msg", {"type": "agent_message", "message": "Found the regression"}),
                          native("response_item", {"type": "message", "role": "user", "content":
                                                    [{"type": "input_text", "text": "A later question"}]}),
                          native("response_item", {"type": "message", "role": "assistant", "content":
                                                    [{"type": "output_text", "text": "A later reply"}]})])
        archive = ("\n".join(json.dumps(r) for r in self.rows) + "\n").encode()
        class Api:
            def get(self, *a, **kw):
                from ccs.api import Response
                return Response(200, {"X-Archive-Sha256": hashlib.sha256(archive).hexdigest()}, archive)
        os.environ["CODEX_HOME"] = os.path.join(self.tmp, "imported-codex")
        resume.restore_codex(Api(), {"session_id": SID}, self.cwd, False, "sk_native", io.StringIO())
        p = subprocess.Popen([os.environ["CCS_TEST_CODEX"], "--no-daemon", "app-server", "--listen", "stdio://"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, env=dict(os.environ))
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        def send(obj):
            p.stdin.write(json.dumps(obj) + "\n")
            p.stdin.flush()
        def call(i, method, params):
            send({"id": i, "method": method, "params": params})
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if sel.select(timeout=0.2):
                    line = p.stdout.readline()
                    if not line:
                        self.fail("Codex app-server exited before answering")
                    obj = json.loads(line)
                    if obj.get("id") == i:
                        self.assertNotIn("error", obj)
                        return obj["result"]
            self.fail("Codex app-server did not answer " + method)
        try:
            call(1, "initialize", {"clientInfo": {"name": "ccs_test", "version": "1"}})
            send({"method": "initialized"})
            thread = call(2, "thread/read", {"threadId": SID, "includeTurns": True})["thread"]
            self.assertEqual(thread["cwd"], self.cwd)
            self.assertEqual(thread["historyMode"], "legacy")
            messages = [i for t in thread["turns"] for i in t["items"]
                        if i["type"] in ("userMessage", "agentMessage")]
            self.assertEqual(len(messages), 4)
        finally:
            p.terminate()
            try:
                p.wait(timeout=1)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)
            p.stdin.close()
            p.stdout.close()
            sel.close()


if __name__ == "__main__":
    unittest.main()
