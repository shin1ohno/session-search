import contextlib
import hashlib
import io
import json
import os
import tarfile
import unittest

import support
from support import SID, FakeServer, HomeCase, user

from ccs import resume, util

ORIG_PROJ = "-old-host-work-demo"


def make_tar(members):
    """members: list of (name, bytes) or (name, TarInfo-mutator)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data, kind in members:
            ti = tarfile.TarInfo(name)
            if kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = "/etc/passwd"
                tf.addfile(ti)
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class RestoreBase(HomeCase):
    def setUp(self):
        super().setUp()
        self.cwd = os.path.join(self.tmp, "work", "demo")
        os.makedirs(self.cwd)
        self.archive = (json.dumps(user("hi", cwd="/old/work/demo")) + "\n" + json.dumps(
            {"type": "user", "toolUseResult": {"path": "/home/old/.claude/projects/%s/%s/tool-results/toolu_1.txt"
                                                        % (ORIG_PROJ, SID)}}) + "\n").encode()
        self.sha = hashlib.sha256(self.archive).hexdigest()
        self.tar = make_tar([("toolu_1.txt", b"masked output", "file")])
        self.meta = {"session_key": "sk_r", "session_id": SID, "host": "mini", "project_dir": ORIG_PROJ,
                     "resume_cwd": "/does/not/exist/here", "jsonl_path": "/x/y.jsonl", "jsonl_exists": True,
                     "archived": True, "archive_complete": True}
        self.srv = FakeServer(self.handler)
        self.write_config(self.srv.base + "/memory/sessions/v1", host="pro-dev")
        self.execs = []

    def tearDown(self):
        self.srv.close()
        super().tearDown()

    def handler(self, req):
        if req["path"].endswith("/preview"):
            return 200, {"session": self.meta, "snippets": []}, {}
        if req["path"].endswith("/archive"):
            return 200, self.archive, {"X-Archive-Sha256": self.sha, "Content-Type": "application/x-ndjson"}
        if req["path"].endswith("/archive/tool-results"):
            return 200, self.tar, {"Content-Type": "application/x-tar"}
        return 404, {}, {}

    def go(self, **kw):
        kw.setdefault("to_dir", self.cwd)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = resume.resume("sk_r", execvp=lambda f, a: self.execs.append(a),
                                 chdir=lambda d: self.execs.append(("chdir", d)), out=io.StringIO(), **kw)
        return code, err.getvalue()

    def target(self):
        return os.path.join(self.projects, util.encode_cwd(self.cwd), SID + ".jsonl")


class LossyEncoding(RestoreBase):
    """encode() is lossy (/a/b and /a-b both give -a-b): a matching name proves nothing alone."""

    def colliding_dirs(self):
        # self.cwd = <tmp>/work/demo ; <tmp>/work-demo encodes to the same project dir
        other = os.path.join(self.tmp, "work-demo")
        os.makedirs(other)
        self.assertEqual(util.encode_cwd(other), util.encode_cwd(self.cwd))
        return other


    def go_local_key(self, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = resume.resume("local:" + path, execvp=lambda f, a: self.execs.append(a),
                                 chdir=lambda d: self.execs.append(("chdir", d)), out=io.StringIO())
        return code, err.getvalue()


    def test_duplicate_keys_make_the_record_unreadable(self):
        d = self.project(self.cwd)
        p = os.path.join(d, SID + ".jsonl")
        with open(p, "w") as fh:
            fh.write('{"type":"user","cwd":"%s","cwd":"/elsewhere","message":{"content":"x"}}\n' % self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, archived=False)
        self.assertEqual(self.go(to_dir=None)[0], util.EXIT_RESUME)
        self.assertEqual(self.execs, [])


class Rewrite(HomeCase):
    def test_rewrite_only_matches_this_session(self):
        text = '"/h/.claude/projects/%s/%s/tool-results/a" "/h/.claude/projects/%s/other/tool-results/b"' % (
            ORIG_PROJ, SID, ORIG_PROJ)
        out = resume.rewrite_tool_result_paths(text, ORIG_PROJ, SID, "/new/dir")
        self.assertIn('"/new/dir/a"', out)
        self.assertIn("/other/tool-results/b", out)


if __name__ == "__main__":
    unittest.main()
