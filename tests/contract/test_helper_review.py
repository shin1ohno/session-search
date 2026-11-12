"""Receiver observations for the picker review's cache and socket boundaries."""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import unittest

from contract.test_helper import HelperBase, SESSIONS
from contract.test_auth import synthetic, headers


class HelperReview(HelperBase):
    def test_fragmented_callback_request_waits_for_the_rest(self):
        self.start_picker()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(self.sock)
            client.sendall(b"GET /backend?q=fragment")
            # The accepted worker must remain blocked for the missing line end.
            with self.assertRaises(socket.timeout, msg="helper closed an incomplete request"):
                client.recv(1)
            client.sendall(b" HTTP/1.0\r\nHost: ccs\r\n\r\n")
            client.settimeout(5)
            body = b""
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                body += chunk
        self.assertTrue(body.startswith(b"HTTP/1.0 200"), body)
        self.assertEqual(self.srv.of("/search")[-1]["body"]["q"], "fragment")


@unittest.skipUnless(os.environ.get("CCS_RUST_CLIENT") == "1", "Rust pooled rejection and callback extension")
class RustHelperReview(HelperBase):
    def auth(self):
        directory = Path(self.tmp) / ".config/session-search"
        secret = directory / "client.secret"
        secret.write_text("synthetic-client-secret")
        secret.chmod(0o600)
        path = directory / "config.json"
        config = json.loads(path.read_text())
        config["auth"] = {"type": "client_credentials", "client_id": "review", "secret_file": str(secret),
                          "token_url": self.srv.base + "/token"}
        path.write_text(json.dumps(config))
        return directory / "token.json"

    def rejected_then_enter(self, restore_cache):
        cache = self.auth()
        rejected, saved, issued, later = [], [], [], []
        def handler(request):
            if request["path"] == "/token":
                issued.append(synthetic(len(issued) + 1))
                return 200, {"access_token": issued[-1], "expires_in": 3600}, {}
            bearer = headers(request).get("authorization")
            if request["path"] == "/search":
                rejected.append(bearer)
                saved.append(cache.read_bytes())
                return 401, {}, {}
            later.append(bearer)
            return 404, {}, {}
        self.srv.handler = handler
        self.start_picker()
        self.invoke(self.backend_command("query"))
        self.assertEqual(len(rejected), 2)
        retained = cache.exists()
        if restore_cache:
            cache.write_bytes(saved[-1])
            cache.chmod(0o600)
        (Path(self.tmp) / "fzf-select").write_text("\nsk_remote\trow\n")
        self.finish_picker()
        self.assertTrue(later, "resume never reached the preview receiver")
        self.assertFalse(set(later) & set(rejected), "resume resent a pooled-401 rejected bearer")
        self.assertFalse(retained, "pooled 401 left its bearer in token.json")

    def test_pooled_rejection_survives_enter(self):
        self.rejected_then_enter(False)

    def test_pooled_rejection_survives_restored_disk_cache_and_enter(self):
        self.rejected_then_enter(True)

    def test_slow_grant_finishes_after_first_waiter_deadline(self):
        self.auth()
        completed = threading.Event()
        grants = []
        def handler(request):
            if request["path"] == "/token":
                grants.append(1)
                time.sleep(1.3)
                completed.set()
                return 200, {"access_token": synthetic(1), "expires_in": 3600}, {}
            return 200, SESSIONS, {}
        self.srv.handler = handler
        self.start_picker()
        self.invoke(self.backend_command("first"))
        self.assertTrue(completed.wait(3))
        time.sleep(.15)
        result = self.invoke(self.backend_command("second"))
        self.assertIn(b"sk_1\t", result.stdout)
        self.assertEqual(len(grants), 1, "grant incorrectly inherited the lexical deadline")
        self.assertEqual(len(self.srv.of("/search")), 1)

    def test_truncated_helper_body_falls_back_to_normal_request(self):
        path = Path(self.tmp) / "truncated.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen()
            def reply():
                connection, _ = server.accept()
                with connection:
                    connection.recv(65536)
                    connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 99\r\n\r\ntruncated")
            thread = threading.Thread(target=reply)
            thread.start()
            try:
                result = self.run_ccs("_backend", "query", env={"CCS_HELPER_SOCKET": str(path)})
            finally:
                thread.join(5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sk_1\t", result.stdout)
        self.assertEqual(len(self.srv.of("/search")), 1)
