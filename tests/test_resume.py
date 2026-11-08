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


class Restore(HomeCase):
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

    def test_restore_then_exec(self):
        code, err = self.go()
        self.assertEqual(code, 0, err)
        self.assertIn(resume.RESTORED_NOTE, err)
        self.assertEqual(self.execs, [("chdir", self.cwd), ["claude", "--resume", SID]])
        body = support.read(self.target())
        new_tr = os.path.join(self.projects, util.encode_cwd(self.cwd), SID, "tool-results") + "/"
        self.assertIn(new_tr + "toolu_1.txt", body)
        self.assertNotIn(ORIG_PROJ, body)
        self.assertEqual(support.read(new_tr + "toolu_1.txt", "rb"), b"masked output")
        self.assertFalse(os.path.exists(self.target() + ".tmp"))

    def test_project_dir_is_local_encoding_not_server_value(self):
        self.meta["project_dir"] = "../../../evil"
        code, _ = self.go()
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.target()))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil")))

    def test_bad_session_id_refused(self):
        for bad in ("../../etc/passwd", "ABCDEF00-0000-0000-0000-000000000000", SID + "x", ""):
            self.meta["session_id"] = bad
            code, err = self.go()
            self.assertEqual(code, util.EXIT_RESUME, bad)
            self.assertIn("refusing session_id", err)
        self.assertEqual(self.execs, [])

    def test_sha_mismatch_restores_nothing(self):
        self.sha = "0" * 64
        code, err = self.go()
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("sha256 mismatch", err)
        self.assertFalse(os.path.exists(self.target()))
        self.assertFalse(os.path.exists(self.target() + ".tmp"))

    def test_traversal_member_names_refused(self):
        for members in ([("../escape.txt", b"x", "file")], [("/abs.txt", b"x", "file")],
                        [("sub/inner.txt", b"x", "file")], [("link.txt", b"", "sym")], [("d", b"", "dir")],
                        [(".hidden", b"x", "file")]):
            self.tar = make_tar(members)
            code, err = self.go()
            self.assertEqual(code, util.EXIT_RESUME, members)
            self.assertIn("unsafe member", err)
            self.assertFalse(os.path.exists(self.target()))
        self.assertFalse(os.path.exists(os.path.join(self.projects, "escape.txt")))

    def test_existing_different_file_needs_force(self):
        os.makedirs(os.path.dirname(self.target()))
        with open(self.target(), "w") as fh:
            fh.write("{}\n")
        code, err = self.go()
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("--force", err)
        self.assertEqual(support.read(self.target()), "{}\n")
        code, _ = self.go(force=True)
        self.assertEqual(code, 0)
        self.assertNotEqual(support.read(self.target()), "{}\n")

    def test_identical_existing_file_is_fine(self):
        self.assertEqual(self.go()[0], 0)
        self.assertEqual(self.go()[0], 0)

    def test_not_archived_is_view_only(self):
        self.meta["archived"] = False
        code, err = self.go()
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("view-only", err)

    def test_incomplete_archive_is_view_only(self):
        self.meta["archive_complete"] = False
        code, err = self.go()
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("archive incomplete", err)

    def test_local_session_exec_uses_cwd_from_the_jsonl(self):
        p = self.transcript([user("x", cwd=self.cwd)], cwd=self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, resume_cwd=self.cwd)
        self.assertEqual(self.go(fork=True, to_dir=None)[0], 0)
        self.assertEqual(self.execs, [("chdir", self.cwd), ["claude", "--resume", SID, "--fork-session"]])

    def test_local_session_with_vanished_cwd_fails(self):
        gone = os.path.join(self.tmp, "gone", "dir")
        os.makedirs(gone)
        self.transcript([user("x", cwd=gone)], cwd=gone)
        os.rmdir(gone)
        self.meta.update(host="pro-dev", jsonl_path=None, archived=False)
        code, err = self.go(to_dir=None)
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("exists on this host", err)
        self.assertEqual(self.execs, [])

    def test_print_command(self):
        p = self.transcript([user("x", cwd=self.cwd)], cwd=self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, resume_cwd=self.cwd)
        out = io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            code = resume.resume("sk_r", do_print=True, execvp=lambda *a: self.fail("exec"), out=out)
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "cd %s && claude --resume %s" % (self.cwd, SID))

    def test_rewrite_only_matches_this_session(self):
        text = '"/h/.claude/projects/%s/%s/tool-results/a" "/h/.claude/projects/%s/other/tool-results/b"' % (
            ORIG_PROJ, SID, ORIG_PROJ)
        out = resume.rewrite_tool_result_paths(text, ORIG_PROJ, SID, "/new/dir")
        self.assertIn('"/new/dir/a"', out)
        self.assertIn("/other/tool-results/b", out)


class UntrustedCwd(Restore):
    """The server never chooses the directory claude starts in (its .claude/ hooks would run)."""

    def planted(self):
        d = os.path.join(self.tmp, "planted")
        os.makedirs(os.path.join(d, ".claude"), exist_ok=True)
        with open(os.path.join(d, ".claude", "settings.json"), "w") as fh:
            fh.write('{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "touch planted-ran"}]}]}}')
        return d

    def test_local_resume_ignores_server_resume_cwd(self):
        p = self.transcript([user("x", cwd=self.cwd)], cwd=self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, resume_cwd=self.planted())
        self.assertEqual(self.go(to_dir=None)[0], 0)
        self.assertEqual(self.execs[0], ("chdir", self.cwd))

    def test_jsonl_recorded_cwd_must_encode_to_its_directory(self):
        planted = self.planted()
        d = self.project(self.cwd)  # the demo project dir, but the record claims the planted cwd
        with open(os.path.join(d, SID + ".jsonl"), "w") as fh:
            fh.write(json.dumps(user("x", cwd=planted)) + "\n")
        self.meta.update(host="pro-dev", jsonl_path=os.path.join(d, SID + ".jsonl"), archived=False)
        code, err = self.go(to_dir=None)
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertEqual(self.execs, [])

    def test_traversal_and_symlink_jsonl_path_rejected(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        evil = os.path.join(outside, SID + ".jsonl")
        with open(evil, "w") as fh:
            fh.write(json.dumps(user("x", cwd=self.planted())) + "\n")
        d = self.project("/elsewhere/proj")
        link = os.path.join(d, SID + ".jsonl")
        os.symlink(evil, link)
        for hint in (evil, os.path.join(self.projects, "..", "outside", SID + ".jsonl"), link):
            self.assertFalse(resume.local_jsonl_ok(hint, SID), hint)
            self.meta.update(host="pro-dev", jsonl_path=hint, archived=False)
            code, _ = self.go(to_dir=None)
            self.assertEqual(code, util.EXIT_RESUME, hint)
        self.assertEqual(self.execs, [])
        self.assertEqual(self.go_local(link)[0], util.EXIT_RESUME)
        self.assertEqual(self.execs, [])

    def go_local(self, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = resume.resume("local:" + path, execvp=lambda f, a: self.execs.append(a),
                                 chdir=lambda d: self.execs.append(("chdir", d)), out=io.StringIO())
        return code, err.getvalue()

    def restore_with(self, answers, isatty=True, do_print=False):
        asked = []

        def ask(prompt):
            asked.append(prompt)
            return answers.pop(0) if answers else ""

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = resume.resume("sk_r", do_print=do_print, execvp=lambda f, a: self.execs.append(a),
                                 chdir=lambda d: self.execs.append(("chdir", d)), ask=ask, isatty=isatty,
                                 out=io.StringIO())
        return code, asked, err.getvalue()

    def test_restore_without_to_needs_a_tty(self):
        self.meta["resume_cwd"] = self.planted()
        for kw in ({"isatty": False}, {"isatty": True, "do_print": True}):
            code, asked, err = self.restore_with([], **kw)
            self.assertEqual(code, util.EXIT_RESUME)
            self.assertIn("--to DIR", err)
            self.assertEqual(asked, [])
        self.assertEqual(self.execs, [])

    def test_restore_defaults_to_current_dir_unless_confirmed(self):
        planted = self.planted()
        self.meta["resume_cwd"] = planted
        code, asked, err = self.restore_with(["", ""])  # decline, then accept the default
        self.assertEqual(code, 0, err)
        self.assertIn(planted, err)  # the path is shown before asking
        self.assertEqual(self.execs[0], ("chdir", os.getcwd()))
        self.execs.clear()
        code, asked, err = self.restore_with(["y"])  # explicit confirmation
        self.assertEqual(code, 0, err)
        self.assertEqual(self.execs[0], ("chdir", os.path.realpath(planted)))


class LossyEncoding(Restore):
    """encode() is lossy (/a/b and /a-b both give -a-b): a matching name proves nothing alone."""

    def colliding_dirs(self):
        # self.cwd = <tmp>/work/demo ; <tmp>/work-demo encodes to the same project dir
        other = os.path.join(self.tmp, "work-demo")
        os.makedirs(other)
        self.assertEqual(util.encode_cwd(other), util.encode_cwd(self.cwd))
        return other

    def test_restored_session_resumes_only_in_the_recorded_dir(self):
        other = self.colliding_dirs()
        # The archive (server-controlled) claims the colliding directory as its cwd.
        self.archive = (json.dumps(user("hi", cwd=other)) + "\n").encode()
        self.sha = hashlib.sha256(self.archive).hexdigest()
        self.assertEqual(self.go()[0], 0)
        self.assertEqual(self.execs[0], ("chdir", self.cwd))
        rec = json.loads(support.read(util.restored_path()))
        entry = rec["sessions"]["%s/%s" % (util.encode_cwd(self.cwd), SID)]
        self.assertEqual(entry["cwd"], self.cwd)
        self.assertEqual(oct(os.stat(util.restored_path()).st_mode & 0o777), "0o600")
        # Later resume of the now-local copy: the JSONL's cwd fields are ignored.
        self.execs.clear()
        self.meta.update(host="pro-dev", jsonl_path=self.target())
        self.assertEqual(self.go(to_dir=None)[0], 0)
        self.assertEqual(self.execs[0], ("chdir", self.cwd))
        self.execs.clear()
        code, _ = self.go_local_key(self.target())
        self.assertEqual(code, 0)
        self.assertEqual(self.execs[0], ("chdir", self.cwd))

    def go_local_key(self, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = resume.resume("local:" + path, execvp=lambda f, a: self.execs.append(a),
                                 chdir=lambda d: self.execs.append(("chdir", d)), out=io.StringIO())
        return code, err.getvalue()

    def test_two_colliding_local_candidates_are_refused(self):
        other = self.colliding_dirs()
        p = self.transcript([user("x", cwd=self.cwd, relocatedCwd=other)], cwd=self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, archived=False)
        code, err = self.go(to_dir=None)
        self.assertEqual(code, util.EXIT_RESUME)
        self.assertIn("--to DIR", err)
        self.assertEqual(self.execs, [])
        # --to settles it when it encodes to the transcript's directory
        self.assertEqual(self.go(to_dir=other)[0], 0)
        self.assertEqual(self.execs[0], ("chdir", other))
        self.execs.clear()
        self.assertEqual(self.go(to_dir=self.tmp)[0], util.EXIT_RESUME)
        self.assertEqual(self.execs, [])

    def test_symlinked_candidate_is_not_its_own_realpath(self):
        real = os.path.join(self.tmp, "real-target")
        os.makedirs(real)
        linkdir = os.path.join(self.tmp, "lnk")
        os.symlink(real, linkdir)
        p = self.transcript([user("x", cwd=linkdir)], cwd=linkdir)
        self.meta.update(host="pro-dev", jsonl_path=p, archived=False)
        self.assertEqual(self.go(to_dir=None)[0], util.EXIT_RESUME)
        self.assertEqual(self.execs, [])

    def test_duplicate_keys_make_the_record_unreadable(self):
        d = self.project(self.cwd)
        p = os.path.join(d, SID + ".jsonl")
        with open(p, "w") as fh:
            fh.write('{"type":"user","cwd":"%s","cwd":"/elsewhere","message":{"content":"x"}}\n' % self.cwd)
        self.meta.update(host="pro-dev", jsonl_path=p, archived=False)
        self.assertEqual(self.go(to_dir=None)[0], util.EXIT_RESUME)
        self.assertEqual(self.execs, [])


class RestoreWithoutDataFilter(Restore):
    """Same cases on a Python whose tarfile predates the `data` filter (manual validation path)."""

    def setUp(self):
        super().setUp()
        self._saved = getattr(tarfile, "data_filter", None)
        if self._saved is not None:
            del tarfile.data_filter

    def tearDown(self):
        if self._saved is not None:
            tarfile.data_filter = self._saved
        super().tearDown()


if __name__ == "__main__":
    unittest.main()
