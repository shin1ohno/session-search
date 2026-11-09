import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import unittest

from contract.harness import ClientCase, FakeServer, SID, FAKE_TOKEN


def native(kind, payload):
    return {"type": kind, "timestamp": "2026-10-25T00:00:00Z", "payload": payload}


class CodexBase(ClientCase):
    def setUp(self):
        super().setUp()
        self.cwd = str(Path(self.tmp) / "work")
        Path(self.cwd).mkdir()

    def restore_native(self, rows, sid=SID, sha=None, force=False, expected_code=0):
        archive = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode()
        meta = {"session_id": sid, "entrypoint": "codex-vscode", "host": "mini",
                "archived": True, "archive_complete": True}
        def handler(req):
            if req["path"].endswith("/preview"):
                return 200, {"session": meta}, {}
            return 200, archive, {"X-Archive-Sha256": sha or hashlib.sha256(archive).hexdigest()}
        srv = FakeServer(handler)
        try:
            self.write_config(srv.base)
            result = self.run_ccs("resume", "sk_native", "--to", self.cwd, *(["--force"] if force else []))
            self.assertEqual(result.returncode, expected_code, result.stderr)
        finally:
            srv.close()
        if expected_code:
            return result
        paths = list((Path(self.env["CODEX_HOME"]) / "sessions").rglob("*" + sid + ".jsonl"))
        self.assertEqual(len(paths), 1)
        return str(paths[0])


class CodexClient(CodexBase):
    def setUp(self):
        super().setUp()
        self.rows_data = [native("session_meta", {"id": SID, "cwd": self.cwd, "source": "vscode"}),
                         native("response_item", {"type": "message", "role": "user", "content":
                                                   [{"type": "input_text", "text": "Codex history search"}]}),
                         native("response_item", {"type": "message", "role": "assistant", "content":
                                                   [{"type": "output_text", "text": "Found the regression"}]})]
        self.path = self.write_native(self.rows_data)

    def test_discover_extract_and_offline_search(self):
        (row,) = self.local_search("regression")["sessions"]
        self.assertEqual(row["session_key"], "local:" + self.path)
        self.assertEqual(row["session_id"], SID)
        self.assertEqual(row["agent"], "codex")
        self.assertEqual(row["hit_count"], 1)
        self.assertEqual(row["title"], "Codex history search")
        self.assertEqual(row["entrypoint"], "codex-vscode")

    def test_unsafe_and_mismatched_rollout_rejected(self):
        alias = self.path.replace("00-00-00-", "00-00-01-")
        os.symlink(self.path, alias)
        self.assertEqual(self.run_ccs("preview", "local:" + alias).returncode, 3)
        self.rows_data[0]["payload"]["id"] = "bad-id"
        self.write_native(self.rows_data)
        self.assertEqual(self.run_ccs("preview", "local:" + self.path).returncode, 3)
        self.assertEqual(self.local_search("regression")["sessions"], [])

    def test_codex_only_host_and_offline_host_filter(self):
        os.rmdir(self.projects)
        self.assertEqual(self.local_search("regression")["sessions"][0]["session_key"], "local:" + self.path)
        self.write_config("http://127.0.0.1:9", host="pro-dev")
        self.assertEqual(self.local_search("regression", "--host", "mini")["sessions"], [])

    def test_local_resume_and_fork_select_codex(self):
        for fork in (False, True):
            self.reset_execs()
            self.good("resume", "local:" + self.path, *(["--fork"] if fork else []))
            self.assertEqual(self.execs(), [{"argv": ["codex", "fork" if fork else "resume", SID], "cwd": self.cwd}])
        self.assertIn("codex resume " + SID, self.good("resume", "local:" + self.path, "--print").stdout)

    def test_ingest_masks_native_records_and_retries_no_bytes(self):
        self.rows_data.append(native("response_item", {"type": "message", "role": "user", "content":
                                                       [{"type": "input_text", "text": FAKE_TOKEN}]}))
        self.write_native(self.rows_data)
        def handler(req):
            if req["path"].endswith("/status"):
                return 200, {"sources": ["claude", "codex"]}, {}
            return 200, {"session_key": "sk_native", "next_offset": req["body"]["segment"]["end_offset"]}, {}
        srv = FakeServer(handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.good("ingest", "--sweep", "--quiet")
        (request,) = srv.of("/ingest")
        body = request["body"]
        self.assertEqual(body["file"]["source"], "codex")
        self.assertTrue(body["file"]["project_dir"].startswith("codex-"))
        self.assertEqual(json.loads(body["segment"]["lines"][0])["type"], "session_meta")
        self.assertNotIn(FAKE_TOKEN, json.dumps(body))
        self.assertIn("REDACTED", json.dumps(body))
        self.good("ingest", "--sweep", "--quiet")
        self.assertEqual(len(srv.of("/ingest")), 1)

    def test_old_server_holds_codex_cursor(self):
        srv = FakeServer(lambda req: (200, {"parser_version": "p1"}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.good("ingest", "--sweep", "--quiet")
        self.assertEqual(srv.of("/ingest"), [])
        self.assertNotIn(self.path, self.files())

    def test_structured_search_and_preview(self):
        def handler(req):
            row = {"session_key": "sk_native", "session_id": SID, "entrypoint": "codex-vscode"}
            return (200, {"sessions": [row]}, {}) if req["path"].endswith("/search") else (
                200, {"session": row, "snippets": [{"fragment": "matching text"}]}, {})
        srv = FakeServer(handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        result = self.good("search", "history", "--semantic", "--all", "--limit", "3")
        self.assertEqual(json.loads(result.stdout)["sessions"][0]["agent"], "codex")
        body = srv.of("/search")[0]["body"]
        self.assertEqual((body["mode"], body["include_headless"], body["limit"]), ("hybrid", True, 3))
        self.assertEqual(json.loads(self.good("preview", "sk_native", "history").stdout)["session"]["agent"], "codex")

    def test_restore_native_archive_is_local_and_hash_checked(self):
        self.rows_data.append(native("turn_context", {"cwd": "/remote", "approval_policy": "never",
                                                      "sandbox_policy": {"type": "danger-full-access"}}))
        self.env["CODEX_HOME"] = str(Path(self.tmp) / "restored-codex")
        restored = self.restore_native(self.rows_data)
        records = [json.loads(line) for line in Path(restored).read_text().split("\n") if line]
        self.assertEqual(records[0]["payload"]["cwd"], self.cwd)
        self.assertEqual(records[0]["payload"]["history_mode"], "legacy")
        self.assertFalse(any(r["type"] == "turn_context" for r in records))
        preview = json.loads(self.good("preview", "local:" + restored).stdout)
        self.assertEqual(preview["session"]["title"], "Codex history search")
        result = self.restore_native(self.rows_data, sha="0" * 64, force=True, expected_code=4)
        self.assertIn("sha256 mismatch", result.stderr)
        day = Path(restored).parent
        outside = Path(self.tmp) / "outside-codex"
        day.rename(outside)
        day.symlink_to(outside)
        self.restore_native(self.rows_data, force=True, expected_code=4)

    @unittest.skipUnless(os.environ.get("CCS_TEST_CODEX"), "set CCS_TEST_CODEX to a native Codex binary")
    def test_restored_paginated_history_is_readable_by_codex(self):
        self.rows_data[0]["payload"].update(timestamp="2026-10-25T00:00:00Z", originator="ccs_test",
                                        cli_version="0.162.1", model_provider="openai", history_mode="paginated")
        # Migration can leave legacy display events before newer items whose
        # display data exists only in SQLite. Both halves must survive import.
        self.rows_data.extend([native("event_msg", {"type": "user_message", "message": "Codex history search",
                                               "images": [], "local_images": [], "text_elements": []}),
                          native("event_msg", {"type": "agent_message", "message": "Found the regression"}),
                          native("response_item", {"type": "message", "role": "user", "content":
                                                    [{"type": "input_text", "text": "A later question"}]}),
                          native("response_item", {"type": "message", "role": "assistant", "content":
                                                    [{"type": "output_text", "text": "A later reply"}]})])
        self.env["CODEX_HOME"] = os.path.join(self.tmp, "imported-codex")
        self.restore_native(self.rows_data)
        p = subprocess.Popen([os.environ["CCS_TEST_CODEX"], "--no-daemon", "app-server", "--listen", "stdio://"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, env=self.env)
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
