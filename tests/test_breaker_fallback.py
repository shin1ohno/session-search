import io
import json
import os
import shutil
import subprocess
import unittest

import support
from support import SID, SID2, FakeServer, HomeCase, assistant, user

from ccs import api as api_mod, extract, fallback, picker, util


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class BreakerTiming(HomeCase):
    def test_opens_after_two_failures_for_60s(self):
        c = Clock()
        b = api_mod.Breaker(clock=c)
        self.assertFalse(b.is_open())
        b.record_failure()
        self.assertFalse(b.is_open())  # one failure is not enough
        b.record_failure()
        self.assertTrue(b.is_open())
        c.t += 59.9
        self.assertTrue(b.is_open())
        c.t += 0.2
        self.assertFalse(b.is_open())  # closed again after 60 s

    def test_success_resets_and_state_is_shared_via_file(self):
        c = Clock()
        api_mod.Breaker(clock=c).record_failure()
        api_mod.Breaker(clock=c).record_success()
        api_mod.Breaker(clock=c).record_failure()
        self.assertFalse(api_mod.Breaker(clock=c).is_open())  # success broke the streak
        api_mod.Breaker(clock=c).record_failure()
        self.assertTrue(api_mod.Breaker(clock=c).is_open())
        self.assertTrue(os.path.exists(util.breaker_path()))

    def test_backend_timeout_counts_as_failure_and_falls_back(self):
        import time as _t

        def slow(req):
            _t.sleep(1.2)  # beyond the 800 ms keystroke budget
            return 200, {"sessions": []}, {}

        srv = FakeServer(slow)
        try:
            self.write_config(srv.base + "/memory/sessions/v1")
            self.transcript([user("hello world")])
            out = io.StringIO()
            picker.backend("hello", env=dict(os.environ), out=out)
            self.assertIn(fallback.BANNER, out.getvalue())
            self.assertEqual(api_mod.Breaker().state()["failures"], 1)
        finally:
            srv.close()


class Fallback(HomeCase):
    def setUp(self):
        super().setUp()
        # Version-manager shims (mise) resolve rg through the real $HOME; run rg
        # with the original environment so only the transcript tree is fake.
        real_env = dict(self._env)
        self._orig_run = fallback._run
        fallback._run = lambda argv, **kw: subprocess.run(argv, env=real_env, **kw)

    def tearDown(self):
        fallback._run = self._orig_run
        super().tearDown()

    def test_rg_argv(self):
        self.assertEqual(fallback.rg_argv("q", "/r"),
                         ["rg", "-l", "-F", "-i", "--glob", "*.jsonl", "--glob", "!**/subagents/**", "--", "q", "/r"])

    def test_candidates_capped_at_200_newest(self):
        paths = []
        d = self.project()
        for i in range(250):
            p = os.path.join(d, "%08d-0000-0000-0000-000000000000.jsonl" % i)
            with open(p, "w") as fh:
                fh.write("{}\n")
            os.utime(p, (1000 + i, 1000 + i))
            paths.append(p)

        def runner(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, stdout="\n".join(paths).encode())

        got = fallback.candidates("needle", runner=runner, which=lambda _: "/usr/bin/rg")
        self.assertEqual(len(got), 200)
        self.assertEqual(got[0], paths[-1])  # newest first
        self.assertNotIn(paths[0], got)

    @unittest.skipUnless(shutil.which("rg"), "ripgrep not installed")
    def test_matches_text_only_and_banner_row_first(self):
        self.transcript([user("the needle is here"), assistant("reply")], sid=SID)
        # needle appears only in an attachment record -> not a text hit
        self.transcript([user("nothing"), {"type": "attachment", "content": "needle"}], sid=SID2)
        rows = picker.offline_rows("needle", set(), {}, "pro-dev", env={})
        self.assertIn(fallback.BANNER, rows[0])
        self.assertTrue(rows[0].startswith("-\t"))
        body = rows[1:]
        self.assertEqual(len(body), 1)
        self.assertTrue(body[0].startswith("local:"))
        self.assertIn(SID, body[0])

    @unittest.skipUnless(shutil.which("rg"), "ripgrep not installed")
    def test_headless_hidden_unless_all(self):
        self.transcript([user("needle", entrypoint="sdk-cli")])
        self.assertEqual(len(picker.offline_rows("needle", set(), {}, "h", env={})), 1)
        self.assertEqual(len(picker.offline_rows("needle", {"a"}, {}, "h", env={})), 2)

    def test_missing_rg_is_reported_not_raised(self):
        rows = []
        orig = fallback.shutil.which
        fallback.shutil.which = lambda _: None
        try:
            rows = picker.offline_rows("needle", set(), {}, "h", env={})
        finally:
            fallback.shutil.which = orig
        self.assertIn("ripgrep", rows[1])

    def test_extractor_strips_leading_blocks_and_meta(self):
        r = user("<system-reminder>ignore</system-reminder>  real text")
        self.assertEqual(extract.record_text(r), "real text")
        self.assertEqual(extract.record_text(dict(user("x"), isMeta=True)), "")

    def test_title_and_resume_cwd(self):
        p = self.transcript([user("first ask", cwd="/old/place", relocatedCwd="/work/demo"),
                             {"type": "ai-title", "aiTitle": "Demo title"}], cwd="/work/demo")
        s = extract.scan(p)
        self.assertEqual(s.title, "Demo title")
        self.assertEqual(s.resume_cwd, "/work/demo")


if __name__ == "__main__":
    unittest.main()
