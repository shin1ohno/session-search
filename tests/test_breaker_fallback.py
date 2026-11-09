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
