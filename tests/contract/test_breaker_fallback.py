import json
import time

from contract.harness import ClientCase, FakeServer, SID, SID2, assistant, user


class BreakerTiming(ClientCase):
    def test_success_resets_and_state_is_shared_via_file(self):
        status = [500]
        srv = FakeServer(lambda req: (status[0], {"sessions": []}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.rows("needle")
        self.assertEqual(json.loads(self.breaker_path.read_text())["failures"], 1)
        status[0] = 200
        self.rows("needle")
        self.assertEqual(json.loads(self.breaker_path.read_text())["failures"], 0)
        status[0] = 500
        self.rows("needle")
        self.rows("needle")
        state = json.loads(self.breaker_path.read_text())
        self.assertEqual(state["failures"], 2)
        self.assertGreater(state["open_until"], time.time())
        count = len(srv.requests)
        self.rows("needle")
        self.assertEqual(len(srv.requests), count)

    def test_backend_timeout_counts_as_failure_and_falls_back(self):
        def slow(req):
            time.sleep(1.2)
            return 200, {"sessions": []}, {}
        srv = FakeServer(slow)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.transcript([user("hello world")])
        out = self.rows("hello")
        self.assertIn("OFFLINE", out)
        self.assertEqual(json.loads(self.breaker_path.read_text())["failures"], 1)


class Fallback(ClientCase):
    def test_matches_text_only_and_banner_row_first(self):
        self.transcript([user("the needle is here"), assistant("reply")], sid=SID)
        self.transcript([user("nothing"), {"type": "attachment", "content": "needle"}], sid=SID2)
        rows = self.rows("needle").splitlines()
        self.assertTrue(rows[0].startswith("-\t"))
        self.assertIn("OFFLINE", rows[0])
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1].startswith("local:"))
        self.assertIn(SID, rows[1])

    def test_headless_hidden_unless_all(self):
        self.transcript([user("needle", entrypoint="sdk-cli")])
        self.assertEqual(len(self.rows("needle").splitlines()), 1)
        self.assertEqual(len(self.rows("needle", env={"FZF_PROMPT": "ccs:a> "}).splitlines()), 2)

    def test_missing_rg_is_reported_not_raised(self):
        (self.bin / "rg").unlink(missing_ok=True)
        self.assertIn("ripgrep", self.rows("needle"))
