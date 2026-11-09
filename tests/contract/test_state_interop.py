"""Alternate independent writers/readers; CCS_INTEROP_PEER enables Rust in S2."""
import fcntl
import json
import os
from pathlib import Path
import shlex
import time

from contract.harness import ClientCase, FakeServer, SID, user
from contract.test_ingest import ok_handler
from contract.test_resume import RestoreBase


class StateInterop(ClientCase):
    def peer(self):
        return shlex.split(self._env["CCS_INTEROP_PEER"]) if self._env.get("CCS_INTEROP_PEER") else self.command

    def test_state_cursor_survives_alternating_writers(self):
        srv = FakeServer(ok_handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        path = self.transcript([user("first")])
        self.good("ingest", "--file", path)
        initial = json.loads(self.state_path.read_text())
        initial["future_top"] = {"keep": True}
        initial["files"][path]["future_entry"] = ["keep"]
        self.state_path.write_text(json.dumps(initial))
        previous = os.path.getsize(path)
        for command in (self.peer(), self.command):
            with open(path, "a") as f:
                f.write(json.dumps(user("next")) + "\n")
            self.good("ingest", "--file", path, command=command)
            current = json.loads(self.state_path.read_text())
            entry = current["files"][path]
            self.assertEqual(current["version"], 1)
            self.assertEqual(current["future_top"], {"keep": True})
            self.assertEqual(entry["future_entry"], ["keep"])
            self.assertEqual(entry["generation"], 0)
            self.assertEqual((entry["dev"], entry["inode"]), (os.stat(path).st_dev, os.stat(path).st_ino))
            self.assertEqual(entry["offset"], os.path.getsize(path))
            self.assertEqual(srv.of("/ingest")[-1]["body"]["segment"]["offset"], previous)
            previous = entry["offset"]
            self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.state_path.read_text(), json.dumps(current, sort_keys=True, indent=1))

    def test_breaker_is_shared_and_success_resets_it(self):
        status = [500]
        srv = FakeServer(lambda req: (status[0], {"sessions": []}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        for command in (self.command, self.peer()):
            self.good("_backend", "query", command=command)
        state = json.loads(self.breaker_path.read_text())
        self.assertEqual(state["failures"], 2)
        self.assertIsInstance(state["open_until"], (int, float))
        self.assertGreater(state["open_until"], time.time())
        before = len(srv.requests)
        self.good("_backend", "query")
        self.assertEqual(len(srv.requests), before)
        self.write_breaker(2, time.time() - 1)
        status[0] = 200
        self.good("_backend", "query", command=self.peer())
        self.assertEqual(json.loads(self.breaker_path.read_text()), {"failures": 0, "open_until": 0})
        self.assertEqual(self.breaker_path.stat().st_mode & 0o777, 0o600)

    def test_peer_respects_flock_without_advancing_cursor(self):
        srv = FakeServer(ok_handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        path = self.transcript([user("first")])
        with (self.state_dir / "lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.good("ingest", "--file", path, command=self.peer())
            self.good("ingest", "--file", path)
        self.assertEqual(srv.requests, [])
        self.assertEqual(self.files(), {})


class RestoredInterop(RestoreBase):
    def test_restored_file_written_by_one_is_used_by_the_other(self):
        peer = shlex.split(self._env["CCS_INTEROP_PEER"]) if self._env.get("CCS_INTEROP_PEER") else self.command
        for writer, reader in ((self.command, peer), (peer, self.command)):
            self.good("resume", "sk_r", "--to", self.cwd, "--force", command=writer)
            state = json.loads(self.restored_path.read_text())
            self.assertEqual(state["version"], 1)
            self.assertEqual(self.restored_path.stat().st_mode & 0o777, 0o600)
            self.reset_execs()
            self.good("resume", "local:" + self.target(), command=reader)
            self.assertEqual(self.execs(), [{"argv": ["claude", "--resume", SID], "cwd": self.cwd}])
