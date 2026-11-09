import json
from pathlib import Path
import shlex

from contract.harness import ClientCase, FakeServer, SID, user


class Parsing(ClientCase):
    def test_usage_errors_exit_2(self):
        for args in (["ingest"], ["ingest", "--sweep", "--backfill"], ["ingest", "--sweep", "--with-subagents"],
                     ["--since", "seven days"], ["--since", "0d"], ["--host", "Bad_Host"], ["resume"],
                     ["--no-such-flag"], ["_toggle", "x"], ["search", "q", "--limit", "0"],
                     ["search", "q", "--limit", "51"]):
            self.assertEqual(self.run_ccs(*args).returncode, 2, args)

    def test_help_exits_0(self):
        self.assertIn("ccs", self.good("--help").stdout)

    def test_resume_precondition_exit_4(self):
        result = self.run_ccs("resume", "local:/nonexistent/x.jsonl")
        self.assertEqual(result.returncode, 4)
        self.assertIn("refusing session_id", result.stderr)
        result = self.run_ccs("resume", "local:%s/-x/%s.jsonl" % (self.projects, SID))
        self.assertEqual(result.returncode, 4)
        self.assertIn("no longer exists", result.stderr)

    def test_unreachable_exit_3(self):
        self.write_config("http://127.0.0.1:9/memory/sessions/v1")
        for args in (("resume", "sk_abc"), ("purge", "sk_abc"), ("status",)):
            self.assertEqual(self.run_ccs(*args).returncode, 3)

    def test_purge_ok(self):
        payload = {"deleted_docs": 3, "deleted_objects": 2, "note": "日本語"}
        srv = FakeServer(lambda req: (200, payload, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base + "/memory/sessions/v1")
        self.assertEqual(self.good("purge", "sk_abc").stdout, json.dumps(payload, sort_keys=True) + "\n")
        (request,) = srv.requests
        self.assertEqual((request["method"], request["path"], request["query"]),
                         ("DELETE", "/memory/sessions/v1/session", {"session_key": "sk_abc"}))


class FzfCallbacks(ClientCase):
    def test_toggle_round_trip_via_prompt(self):
        state = str(Path(self.tmp) / "prompt")
        for letter, before, after in (("s", "ccs> ", "ccs:s> "), ("d", "ccs:s> ", "ccs:sd> "),
                                      ("s", "ccs:sd> ", "ccs:d> ")):
            got = self.good("_toggle", letter, env={"FZF_PROMPT": before, "CCS_PICK_STATE": state})
            self.assertEqual(got.stdout, after + "\n")
            self.assertEqual(Path(state).read_text(), after)
        self.assertEqual(self.good("_toggle", "s", env={"CCS_PICK_STATE": state}).stdout, "ccs:sd> \n")

    def test_rows_mark_view_only_and_exclude_self(self):
        payload = {"sessions": [
            {"session_key": "sk_1", "session_id": SID, "host": "pro-dev", "title": "local one", "cwd": "/w",
             "updated_at": "2026-10-01T00:00:00Z", "hit_count": 3, "jsonl_exists": True, "archived": False},
            {"session_key": "sk_2", "session_id": "other", "host": "mini", "title": "remote\tunarchived", "cwd": "/w",
             "updated_at": "2026-10-01T00:00:00Z", "hit_count": 1, "jsonl_exists": True, "archived": False},
            {"session_key": "sk_3", "session_id": "me", "host": "pro-dev", "title": "self"}]}
        srv = FakeServer(lambda req: (200, payload, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        rows = self.rows("query", env={"CLAUDE_CODE_SESSION_ID": "me"}).splitlines()
        self.assertEqual(len(rows), 2)
        k1, r1 = rows[0].split("\t")
        k2, r2 = rows[1].split("\t")
        self.assertEqual((k1, k2), ("sk_1", "sk_2"))
        self.assertTrue(r1.startswith("  "))
        self.assertTrue(r2.startswith("· "))
        self.assertIn(" │ local one │ 3", r1)
        self.assertEqual(srv.requests[0]["body"]["q"], "query")


class PickerRun(ClientCase):
    def test_cancel_is_exit_0(self):
        self.make_fzf(exit_code=130)
        self.good("q")
        self.assertEqual(self.execs(), [])

    def test_enter_resumes_and_ctrl_y_prints(self):
        cwd = str(Path(self.tmp) / "work dir")
        Path(cwd).mkdir()
        path = self.transcript([user("x", cwd=cwd)], cwd=cwd)
        row = "local:" + path + "\t  local\n"
        self.make_fzf("\n" + row, 0)
        self.good("q")
        self.assertEqual(self.execs(), [{"argv": ["claude", "--resume", SID], "cwd": cwd}])
        args = json.loads((Path(self.tmp) / "fzf.json").read_text())
        self.assertEqual(json.loads(args["pick"])["flags"], "")
        self.reset_execs()
        self.make_fzf("ctrl-y\n" + row, 0)
        result = self.good("q")
        self.assertEqual(result.stdout.strip(), "cd %s && claude --resume %s" % (shlex.quote(cwd), SID))
        self.assertEqual(self.execs(), [])

    def test_banner_row_selection_is_ignored(self):
        self.make_fzf("\n-\tOFFLINE\n", 0)
        self.good("q")
        self.assertEqual(self.execs(), [])

    def test_missing_fzf_exit_3(self):
        result = self.run_ccs("q")
        self.assertEqual(result.returncode, 3)
        self.assertTrue(result.stderr.startswith("ccs: "))


class OutputContract(ClientCase):
    def test_json_spaces_unicode_order_and_abbreviation(self):
        payload = {"sessions": [], "degraded": False, "note": "日本語"}
        srv = FakeServer(lambda req: (200, payload, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        out = self.good("search", "query", "--sem").stdout
        self.assertEqual(out, json.dumps(payload, ensure_ascii=False) + "\n")
        self.assertEqual(srv.of("/search")[0]["body"]["mode"], "hybrid")

    def test_status_order_and_sorted_server_json(self):
        payload = {"z": "日本語", "a": 1}
        srv = FakeServer(lambda req: (200, payload, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        out = self.good("status").stdout
        self.assertIn("server:     HTTP 200 " + json.dumps(payload, sort_keys=True), out)
        self.assertLess(out.index("config:"), out.index("server:"))
