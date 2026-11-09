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


    def test_search_body(self):
        b = picker.search_body("x", {"d", "a"}, {"sidechain": True, "hosts": ["mini"], "cwd_prefix": "/w",
                                                 "since": "2026-01-01T00:00:00Z"})
        self.assertEqual(b, {"q": "", "mode": "lexical", "deep": True, "include_headless": True,
                             "include_sidechain": True, "limit": 50, "hosts": ["mini"], "cwd_prefix": "/w",
                             "since": "2026-01-01T00:00:00Z"})
        self.assertEqual(picker.search_body("ab", {"s"}, {})["mode"], "hybrid")


if __name__ == "__main__":
    unittest.main()
