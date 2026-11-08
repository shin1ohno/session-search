import fcntl
import hashlib
import json
import os
import unittest

import support
from support import FAKE_TOKEN, SID, FakeRedactor, FakeServer, HomeCase, assistant, user

from ccs import api as api_mod, config as config_mod, ingest, util


def ok_handler(req):
    if req["path"].endswith("/ingest"):
        seg = req["body"]["segment"]
        return 200, {"session_key": "sk_test", "indexed": len(seg["lines"]), "next_offset": seg["end_offset"],
                     "archive": "written"}, {}
    return 200, {"stored": True}, {}


class IngestCase(HomeCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeServer(ok_handler)
        self.write_config(self.srv.base + "/memory/sessions/v1")

    def tearDown(self):
        self.srv.close()
        super().tearDown()

    def shipper(self, **kw):
        cfg = config_mod.load()
        red = FakeRedactor()
        return ingest.Shipper(cfg, api_mod.Api(cfg, timeout=5), red, red.load_key(cfg.hmac_key_file),
                              ingest.State(), **kw)

    def ingests(self):
        return self.srv.of("/ingest")


class AdapterShape(IngestCase):
    def test_ingest_request_body_matches_7_2(self):
        p = self.transcript([user("token " + FAKE_TOKEN), assistant("ok")])
        self.shipper().ship_file(p)
        (req,) = self.ingests()
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["path"], "/memory/sessions/v1/ingest")
        # gzip on the wire, but no Content-Encoding: the aiohttp proxies would
        # decompress it and stall the request (found on the first real backfill).
        self.assertIsNone(req["headers"].get("Content-Encoding"))
        self.assertEqual(req["raw"][:2], b"\x1f\x8b")
        b = req["body"]
        self.assertEqual(set(b), {"client", "file", "segment"})
        self.assertEqual(set(b["client"]), {"host", "client_version", "redact_version"})
        self.assertEqual(b["client"]["host"], "pro-dev")
        self.assertEqual(b["client"]["redact_version"], "r1")
        self.assertEqual(set(b["file"]), {"session_id", "project_dir", "jsonl_path", "kind"})
        self.assertEqual(b["file"]["session_id"], SID)
        self.assertEqual(b["file"]["project_dir"], "-work-demo")
        self.assertEqual(b["file"]["jsonl_path"], os.path.abspath(p))
        self.assertEqual(b["file"]["kind"], "main")
        seg = b["segment"]
        self.assertEqual(set(seg), {"generation", "offset", "end_offset", "sha256", "lines"})
        self.assertEqual((seg["generation"], seg["offset"], seg["end_offset"]), (0, 0, os.path.getsize(p)))
        self.assertEqual(len(seg["lines"]), 2)
        self.assertNotIn(FAKE_TOKEN, json.dumps(b))
        self.assertIn("[REDACTED:github-token:", seg["lines"][0])
        payload = ("\n".join(seg["lines"]) + "\n").encode()
        self.assertEqual(seg["sha256"], hashlib.sha256(payload).hexdigest())
        # each line is a JSON record, structure unchanged
        self.assertEqual(json.loads(seg["lines"][1])["type"], "assistant")

    def test_subagent_fields(self):
        d = self.project()
        sub = os.path.join(d, SID, "subagents")
        os.makedirs(sub)
        p = os.path.join(sub, "agent-a1b2.jsonl")
        with open(p, "w") as fh:
            fh.write(json.dumps(assistant("sub")) + "\n")
        self.shipper().ship_file(p)
        f = self.ingests()[0]["body"]["file"]
        self.assertEqual(f["kind"], "subagent")
        self.assertEqual(f["parent_session_id"], SID)
        self.assertEqual(f["agent_id"], "a1b2")
        self.assertEqual(f["session_id"], SID)

    def test_tombstone_format(self):
        t = ingest.tombstone("unmasked_secret", ["aws-key"], 123)
        self.assertEqual(t, {"type": "session-search-tombstone", "reason": "unmasked_secret",
                             "kinds": ["aws-key"], "line_offset": 123})


class DiffRule(IngestCase):
    def test_partial_trailing_line_waits(self):
        p = self.transcript([user("one")], partial='{"type":"user","mess')
        full = len(json.dumps(user("one"))) + 1
        sh = self.shipper()
        sh.ship_file(p)
        sh.state.save()
        self.assertEqual(self.ingests()[0]["body"]["segment"]["end_offset"], full)
        self.assertEqual(ingest.State().files[p]["offset"], full)
        with open(p, "a") as fh:
            fh.write('sage":{"content":"x"}}\n')
        self.shipper().ship_file(p)
        second = self.ingests()[1]["body"]["segment"]
        self.assertEqual(second["offset"], full)
        self.assertEqual(second["end_offset"], os.path.getsize(p))

    def test_unchanged_file_sends_nothing(self):
        p = self.transcript([user("one")])
        sh = self.shipper()
        sh.ship_file(p)
        self.assertEqual(sh.ship_file(p), "unchanged")
        self.assertEqual(len(self.ingests()), 1)

    def test_inode_change_bumps_generation(self):
        p = self.transcript([user("one"), user("two")])
        sh = self.shipper()
        sh.ship_file(p)
        tmp = p + ".new"
        with open(tmp, "w") as fh:
            fh.write(json.dumps(user("rewritten")) + "\n" + json.dumps(user("again")) + "\n"
                     + json.dumps(user("and more lines")) + "\n")
        os.replace(tmp, p)
        sh.ship_file(p)
        seg = self.ingests()[1]["body"]["segment"]
        self.assertEqual((seg["generation"], seg["offset"]), (1, 0))

    def test_shrink_bumps_generation(self):
        p = self.transcript([user("one"), user("two"), user("three")])
        sh = self.shipper()
        sh.ship_file(p)
        with open(p, "w") as fh:  # same inode, smaller
            fh.write(json.dumps(user("x")) + "\n")
        sh.ship_file(p)
        seg = self.ingests()[1]["body"]["segment"]
        self.assertEqual((seg["generation"], seg["offset"]), (1, 0))

    def test_segments_are_capped_and_contiguous(self):
        p = self.transcript([user("message number %d " % i + "x" * 40) for i in range(12)])
        self.shipper(max_segment=300).ship_file(p)
        segs = [r["body"]["segment"] for r in self.ingests()]
        self.assertGreater(len(segs), 2)
        self.assertEqual(segs[0]["offset"], 0)
        for a, b in zip(segs, segs[1:]):
            self.assertEqual(a["end_offset"], b["offset"])
        self.assertEqual(segs[-1]["end_offset"], os.path.getsize(p))
        for s in segs:
            self.assertLessEqual(s["end_offset"] - s["offset"], 300)

    def test_cursor_does_not_move_without_2xx(self):
        self.srv.handler = lambda req: (500, {"error": "boom"}, {})
        p = self.transcript([user("one")])
        sh = self.shipper()
        with self.assertRaises(ingest.ShipError):
            sh.ship_file(p)
        self.assertEqual(sh.state.files[p]["offset"], 0)


class ServerAnswers(IngestCase):
    def test_409_resyncs_to_expected_offset(self):
        p = self.transcript([user("one"), user("two")])
        first_len = len(json.dumps(user("one"))) + 1
        calls = []

        def h(req):
            calls.append(1)
            if len(calls) == 1:
                return 409, {"expected_offset": first_len}, {}
            return ok_handler(req)

        self.srv.handler = h
        sh = self.shipper()
        sh.ship_file(p)
        segs = [r["body"]["segment"] for r in self.ingests()]
        self.assertEqual(segs[1]["offset"], first_len)
        self.assertEqual(sh.state.files[p]["offset"], os.path.getsize(p))

    def test_413_halves_the_segment(self):
        p = self.transcript([user("line %d " % i + "y" * 30) for i in range(8)])
        calls = []

        def h(req):
            calls.append(1)
            if len(calls) == 1:
                return 413, {"error": "too_large"}, {}
            return ok_handler(req)

        self.srv.handler = h
        self.shipper().ship_file(p)
        segs = [r["body"]["segment"] for r in self.ingests()]
        self.assertEqual(segs[0]["offset"], segs[1]["offset"])
        self.assertLess(len(segs[1]["lines"]), len(segs[0]["lines"]))
        self.assertLessEqual(segs[1]["end_offset"] - segs[1]["offset"], (segs[0]["end_offset"]) // 2)
        self.assertEqual(segs[-1]["end_offset"], os.path.getsize(p))

    def test_422_tombstones_named_lines_and_resends(self):
        recs = [user("fine"), user("flagged"), user("also fine")]
        p = self.transcript(recs)
        line1_off = len(json.dumps(recs[0])) + 1
        calls = []

        def h(req):
            calls.append(1)
            if len(calls) == 1:
                return 422, {"error": "unmasked_secret", "lines": [1], "kinds": ["aws-key"]}, {}
            return ok_handler(req)

        self.srv.handler = h
        sh = self.shipper()
        sh.ship_file(p)
        first, second = [r["body"]["segment"] for r in self.ingests()]
        self.assertEqual(first["lines"][0], second["lines"][0])
        self.assertEqual(json.loads(second["lines"][1]),
                         {"type": "session-search-tombstone", "reason": "unmasked_secret", "kinds": ["aws-key"],
                          "line_offset": line1_off})
        self.assertEqual((second["offset"], second["end_offset"]), (first["offset"], first["end_offset"]))
        self.assertEqual(sh.state.files[p]["offset"], os.path.getsize(p))
        with open(util.log_path()) as fh:
            log = fh.read()
        self.assertNotIn("flagged", log)  # rejections log kinds and indexes only


class RunLevel(IngestCase):
    def test_fail_closed_without_key(self):
        os.unlink(os.path.join(self.tmp, ".config", "session-search", "hmac.key"))
        p = self.transcript([user("one")])
        code = ingest.run("file", file_path=p, quiet=True, redactor=FakeRedactor())
        self.assertEqual(code, util.EXIT_UNREACHABLE)
        self.assertEqual(self.srv.requests, [])
        self.assertNotIn(p, ingest.State().files)

    def test_unreachable_holds_cursor(self):
        p = self.transcript([user("one")])
        self.srv.close()
        self.write_config("http://127.0.0.1:9/memory/sessions/v1")
        code = ingest.run("file", file_path=p, quiet=True, redactor=FakeRedactor())
        self.assertEqual(code, util.EXIT_UNREACHABLE)
        self.assertEqual(ingest.State().files[p]["offset"], 0)
        self.srv = FakeServer(ok_handler)  # for tearDown

    def test_lost_lock_exits_zero(self):
        p = self.transcript([user("one")])
        util.ensure_dir(util.state_dir())
        with open(util.lock_path(), "a") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            code = ingest.run("file", file_path=p, quiet=True, redactor=FakeRedactor())
        self.assertEqual(code, util.EXIT_OK)
        self.assertEqual(self.srv.requests, [])

    def test_not_configured_exits_zero(self):
        os.unlink(os.path.join(self.tmp, ".config", "session-search", "config.json"))
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), util.EXIT_OK)

    def test_file_outside_projects_is_usage_error(self):
        other = os.path.join(self.tmp, "x.jsonl")
        open(other, "w").close()
        self.assertEqual(ingest.run("file", file_path=other, quiet=True, redactor=FakeRedactor()), util.EXIT_USAGE)

    def test_with_subagents_ships_both(self):
        p = self.transcript([user("main")])
        sub = os.path.join(os.path.dirname(p), SID, "subagents")
        os.makedirs(sub)
        with open(os.path.join(sub, "agent-zz.jsonl"), "w") as fh:
            fh.write(json.dumps(assistant("sub")) + "\n")
        self.assertEqual(ingest.run("file", file_path=p, with_subagents=True, quiet=True, redactor=FakeRedactor()), 0)
        kinds = sorted(r["body"]["file"]["kind"] for r in self.ingests())
        self.assertEqual(kinds, ["main", "subagent"])

    def test_sweep_reports_gone_files(self):
        p = self.transcript([user("one")])
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), 0)
        os.unlink(p)
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), 0)
        (st,) = self.srv.of("/state")
        self.assertEqual(st["body"], {"session_key": "sk_test", "jsonl_exists": False})
        self.assertNotIn(p, ingest.State().files)

    def test_tool_results_blob_sent_once_masked(self):
        p = self.transcript([user("one")])
        tr = os.path.join(os.path.dirname(p), SID, "tool-results")
        os.makedirs(tr)
        with open(os.path.join(tr, "toolu_01.txt"), "w") as fh:
            fh.write("output with " + FAKE_TOKEN)
        with open(os.path.join(tr, ".hidden"), "w") as fh:
            fh.write("skip me")
        sh = self.shipper()
        sh.ship_file(p)
        with open(p, "a") as fh:
            fh.write(json.dumps(user("two")) + "\n")
        sh.ship_file(p)
        (blob,) = self.srv.of("/blob")
        self.assertIn("'.hidden' does not match", support.read(util.log_path()))
        b = blob["body"]
        self.assertEqual(set(b), {"session_key", "name", "sha256", "content"})
        self.assertEqual(b["name"], "toolu_01.txt")
        self.assertNotIn(FAKE_TOKEN, b["content"])
        self.assertEqual(b["sha256"], hashlib.sha256(b["content"].encode()).hexdigest())


class NoSymlinksOrSpecialFiles(IngestCase):
    """Only regular files inside realpath(~/.claude/projects) are ever read or shipped."""

    def outside_secret(self):
        p = os.path.join(self.tmp, "outside-secret.txt")
        with open(p, "w") as fh:
            fh.write('{"type":"user","message":{"content":"OUTSIDE-SECRET-CONTENT"}}\n')
        return p

    def shipped_text(self):
        return json.dumps([r["body"] for r in self.srv.requests if r["body"] is not None])

    def test_symlinked_jsonl_is_not_read(self):
        d = self.project()
        os.symlink(self.outside_secret(), os.path.join(d, "%s.jsonl" % support.SID2))
        self.transcript([user("legit")])
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), 0)
        self.assertNotIn("OUTSIDE-SECRET-CONTENT", self.shipped_text())
        self.assertEqual(len(self.ingests()), 1)
        link = os.path.join(d, "%s.jsonl" % support.SID2)
        self.assertEqual(ingest.run("file", file_path=link, quiet=True, redactor=FakeRedactor()), util.EXIT_USAGE)
        with self.assertRaises(util.UnsafePath):
            # even when called directly with a path that classifies, open_regular refuses the link
            os.close(util.open_regular(link))
        self.assertEqual(len(self.ingests()), 1)

    def test_fifo_jsonl_is_not_opened_for_reading(self):
        d = self.project()
        fifo = os.path.join(d, "%s.jsonl" % support.SID2)
        os.mkfifo(fifo)
        self.transcript([user("legit")])
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), 0)  # does not hang
        self.assertEqual(ingest.run("file", file_path=fifo, quiet=True, redactor=FakeRedactor()), 0)
        self.assertEqual([r["body"]["file"]["session_id"] for r in self.ingests()], [SID])
        self.assertNotIn(fifo, ingest.State().files)

    def test_symlinked_tool_results_dir_is_not_shipped(self):
        p = self.transcript([user("one")])
        outside = os.path.join(self.tmp, "outside-dir")
        os.makedirs(outside)
        with open(os.path.join(outside, "toolu_9.txt"), "w") as fh:
            fh.write("OUTSIDE-SECRET-CONTENT")
        os.makedirs(os.path.join(os.path.dirname(p), SID))
        os.symlink(outside, os.path.join(os.path.dirname(p), SID, "tool-results"))
        self.shipper().ship_file(p)
        self.assertEqual(self.srv.of("/blob"), [])
        self.assertNotIn("OUTSIDE-SECRET-CONTENT", self.shipped_text())

    def test_symlinked_tool_result_file_is_not_shipped(self):
        p = self.transcript([user("one")])
        tr = os.path.join(os.path.dirname(p), SID, "tool-results")
        os.makedirs(tr)
        os.symlink(self.outside_secret(), os.path.join(tr, "toolu_7.txt"))
        os.mkfifo(os.path.join(tr, "toolu_8.txt"))
        self.shipper().ship_file(p)
        self.assertEqual(self.srv.of("/blob"), [])

    def test_symlinked_subagents_dir_is_not_walked(self):
        p = self.transcript([user("main")])
        outside = os.path.join(self.tmp, "outside-sub")
        os.makedirs(outside)
        with open(os.path.join(outside, "agent-x.jsonl"), "w") as fh:
            fh.write('{"type":"user","message":{"content":"OUTSIDE-SECRET-CONTENT"}}\n')
        os.makedirs(os.path.join(os.path.dirname(p), SID))
        os.symlink(outside, os.path.join(os.path.dirname(p), SID, "subagents"))
        self.assertEqual(ingest.run("sweep", quiet=True, redactor=FakeRedactor()), 0)
        self.assertEqual(ingest.run("file", file_path=p, with_subagents=True, quiet=True,
                                    redactor=FakeRedactor()), 0)
        self.assertNotIn("OUTSIDE-SECRET-CONTENT", self.shipped_text())


if __name__ == "__main__":
    unittest.main()
