import contextlib
import io
import json
import os
import subprocess
import unittest

import support
from support import SID, FakeServer, HomeCase

from ccs import cli, picker, util


def quiet_main(argv):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        return cli.main(argv), err.getvalue()


class Parsing(HomeCase):
    def test_picker_flags(self):
        cmd, ns = cli.parse(["foo", "bar", "--deep", "--semantic", "--all", "--sidechain", "--here",
                             "--host", "pro-dev", "--host", "mini", "--since", "7d", "--offline", "--print",
                             "--fork"])
        self.assertEqual(cmd, "pick")
        self.assertEqual(ns.query, ["foo", "bar"])
        self.assertTrue(ns.deep and ns.semantic and getattr(ns, "all") and ns.sidechain and ns.here)
        self.assertEqual(ns.host, ["pro-dev", "mini"])
        self.assertEqual(ns.since_seconds, 7 * 86400)
        self.assertTrue(ns.offline and ns.do_print and ns.fork)
        flags, opts = cli.pick_options(ns)
        self.assertEqual(flags, {"s", "d", "a"})
        self.assertEqual(opts["hosts"], ["pro-dev", "mini"])
        self.assertEqual(opts["cwd_prefix"], os.getcwd())
        self.assertTrue(opts["since"].endswith("Z"))

    def test_subcommands(self):
        cmd, ns = cli.parse(["resume", "sk_abc", "--print", "--fork", "--to", "/tmp", "--force"])
        self.assertEqual((cmd, ns.session_key, ns.do_print, ns.fork, ns.to, ns.force),
                         ("resume", "sk_abc", True, True, "/tmp", True))
        cmd, ns = cli.parse(["ingest", "--file", "/x.jsonl", "--with-subagents", "--quiet"])
        self.assertEqual((ns.file, ns.with_subagents, ns.quiet), ("/x.jsonl", True, True))
        self.assertTrue(cli.parse(["ingest", "--sweep"])[1].sweep)
        self.assertTrue(cli.parse(["ingest", "--backfill"])[1].backfill)
        self.assertEqual(cli.parse(["purge", "sk_x"])[1].session_key, "sk_x")
        self.assertEqual(cli.parse(["_preview", "sk_x", "q"])[1].key, "sk_x")
        self.assertEqual(cli.parse(["_backend"])[1].q, "")
        self.assertEqual(cli.parse(["--", "status"])[1].query, ["status"])

    def test_usage_errors_exit_2(self):
        for argv in (["ingest"], ["ingest", "--sweep", "--backfill"], ["ingest", "--sweep", "--with-subagents"],
                     ["--since", "seven days"], ["--since", "0d"], ["--host", "Bad_Host"], ["resume"],
                     ["--no-such-flag"], ["_toggle", "x"]):
            code, _ = quiet_main(argv)
            self.assertEqual(code, util.EXIT_USAGE, argv)

    def test_help_exits_0(self):
        code, _ = quiet_main(["--help"])
        self.assertEqual(code, 0)

    def test_resume_precondition_exit_4(self):
        code, err = quiet_main(["resume", "local:/nonexistent/x.jsonl"])
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("refusing session_id", err)
        code, err = quiet_main(["resume", "local:%s/-x/%s.jsonl" % (self.projects, SID)])
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("no longer exists", err)

    def test_unreachable_exit_3(self):
        self.write_config("http://127.0.0.1:9/memory/sessions/v1")
        self.assertEqual(quiet_main(["resume", "sk_abc"])[0], util.EXIT_UNREACHABLE)
        self.assertEqual(quiet_main(["purge", "sk_abc"])[0], util.EXIT_UNREACHABLE)
        self.assertEqual(quiet_main(["status"])[0], util.EXIT_UNREACHABLE)

    def test_purge_ok(self):
        srv = FakeServer(lambda req: (200, {"deleted_docs": 3, "deleted_objects": 2}, {}))
        try:
            self.write_config(srv.base + "/memory/sessions/v1")
            self.assertEqual(quiet_main(["purge", "sk_abc"])[0], 0)
            (r,) = srv.requests
            self.assertEqual((r["method"], r["path"], r["query"]),
                             ("DELETE", "/memory/sessions/v1/session", {"session_key": "sk_abc"}))
        finally:
            srv.close()


class FzfArgv(HomeCase):
    def test_argv_assembly(self):
        argv = picker.fzf_argv("hello", {"d"}, "/home/u/.local/bin/ccs")
        self.assertEqual(argv[:6], ["fzf", "--disabled", "--ansi", "--layout=reverse", "--delimiter=\t",
                                    "--with-nth=2.."])
        joined = "\n".join(argv)
        self.assertIn("start:reload(/home/u/.local/bin/ccs _backend {q})", argv)
        self.assertIn("change:reload(/home/u/.local/bin/ccs _backend {q})", argv)
        for letter, key in (("s", "ctrl-s"), ("d", "ctrl-d"), ("a", "ctrl-a")):
            self.assertIn("%s:transform-prompt(/home/u/.local/bin/ccs _toggle %s)+reload(/home/u/.local/bin/ccs "
                          "_backend {q})" % (key, letter), argv)
        i = argv.index("--preview")
        self.assertEqual(argv[i + 1], "/home/u/.local/bin/ccs _preview {1} {q}")
        self.assertEqual(argv[argv.index("--preview-window") + 1], "down,45%,wrap")
        self.assertIn("--expect=ctrl-y", argv)
        self.assertEqual(argv[argv.index("--prompt") + 1], "ccs:d> ")
        self.assertEqual(argv[argv.index("--query") + 1], "hello")
        self.assertNotIn("--header", joined)

    def test_offline_banner_header_and_quoting(self):
        argv = picker.fzf_argv("", set(), "/path with space/ccs", banner="B")
        self.assertEqual(argv[argv.index("--header") + 1], "B")
        self.assertIn("start:reload('/path with space/ccs' _backend {q})", argv)

    def test_toggle_round_trip_via_prompt(self):
        state = os.path.join(self.tmp, "prompt")
        env = {"FZF_PROMPT": "ccs> ", "CCS_PICK_STATE": state}
        self.assertEqual(picker.toggle("s", env), "ccs:s> ")
        env["FZF_PROMPT"] = "ccs:s> "
        self.assertEqual(picker.toggle("d", env), "ccs:sd> ")
        env["FZF_PROMPT"] = "ccs:sd> "
        self.assertEqual(picker.toggle("s", env), "ccs:d> ")
        # an fzf without $FZF_PROMPT falls back to the state file
        self.assertEqual(picker.current_flags({"CCS_PICK_STATE": state}), {"d"})

    def test_search_body(self):
        b = picker.search_body("x", {"d", "a"}, {"sidechain": True, "hosts": ["mini"], "cwd_prefix": "/w",
                                                 "since": "2026-01-01T00:00:00Z"})
        self.assertEqual(b, {"q": "", "mode": "lexical", "deep": True, "include_headless": True,
                             "include_sidechain": True, "limit": 50, "hosts": ["mini"], "cwd_prefix": "/w",
                             "since": "2026-01-01T00:00:00Z"})
        self.assertEqual(picker.search_body("ab", {"s"}, {})["mode"], "hybrid")

    def test_rows_mark_view_only_and_exclude_self(self):
        srv = FakeServer(lambda req: (200, {"sessions": [
            {"session_key": "sk_1", "session_id": SID, "host": "pro-dev", "title": "local one", "cwd": "/w",
             "updated_at": "2026-10-01T00:00:00Z", "hit_count": 3, "jsonl_exists": True, "archived": False,
             "archive_complete": False},
            {"session_key": "sk_2", "session_id": "other", "host": "mini", "title": "remote\tunarchived",
             "cwd": "/w", "updated_at": "2026-10-01T00:00:00Z", "hit_count": 1, "jsonl_exists": True,
             "archived": False, "archive_complete": False},
            {"session_key": "sk_3", "session_id": "me", "host": "pro-dev", "title": "self", "cwd": "/w",
             "updated_at": "2026-10-01T00:00:00Z", "jsonl_exists": True}], "took_ms": 3}, {}))
        try:
            self.write_config(srv.base + "/memory/sessions/v1")
            out = io.StringIO()
            picker.backend("query", env={"CLAUDE_CODE_SESSION_ID": "me"}, out=out)
            rows = out.getvalue().splitlines()
            self.assertEqual(len(rows), 2)
            k1, r1 = rows[0].split("\t")
            k2, r2 = rows[1].split("\t")
            self.assertEqual((k1, k2), ("sk_1", "sk_2"))
            self.assertTrue(r1.startswith("  "))
            self.assertTrue(r2.startswith("· "))  # other host, not archived -> view-only
            self.assertIn(" │ local one │ 3", r1)
            self.assertNotIn("\t", r2)
            body = srv.requests[0]["body"]
            self.assertEqual(body["q"], "query")
        finally:
            srv.close()


class PickerRun(HomeCase):
    def _run(self, stdout, code=0, do_print=False):
        calls = []

        def runner(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, code, stdout=stdout.encode())

        resumed = []
        rc = picker.run("q", set(), {}, do_print, False, runner=runner, which=lambda _: "/usr/bin/fzf",
                        resume_fn=lambda key, do_print, fork: resumed.append((key, do_print)) or 0)
        return rc, calls, resumed

    def test_cancel_is_exit_0(self):
        rc, _, resumed = self._run("", code=130)
        self.assertEqual((rc, resumed), (0, []))

    def test_enter_resumes_and_ctrl_y_prints(self):
        rc, calls, resumed = self._run("\nsk_9\t  1d host ~/w │ t\n")
        self.assertEqual((rc, resumed), (0, [("sk_9", False)]))
        env = calls[0][1]["env"]
        self.assertEqual(json.loads(env["CCS_PICK"])["flags"], "")
        rc, _, resumed = self._run("ctrl-y\nsk_9\t  1d host ~/w │ t\n")
        self.assertEqual(resumed, [("sk_9", True)])

    def test_banner_row_selection_is_ignored(self):
        rc, _, resumed = self._run("\n-\tOFFLINE\n")
        self.assertEqual((rc, resumed), (0, []))

    def test_missing_fzf_exit_3(self):
        with contextlib.redirect_stderr(io.StringIO()):
            rc = picker.run("q", set(), {}, False, False, which=lambda _: None)
        self.assertEqual(rc, util.EXIT_UNREACHABLE)


if __name__ == "__main__":
    unittest.main()
