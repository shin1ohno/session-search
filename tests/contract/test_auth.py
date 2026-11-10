"""Authentication through the real CLI, with Python as the HTTP oracle.

Disk-cache cases in test_auth_cache are the intentional Rust extension.
Only synthetic, unsigned bearer values are used here.
"""
import base64
from pathlib import Path
import urllib.parse
import time

from .harness import ClientCase, FakeServer


def headers(request):
    return {key.lower(): value for key, value in request["headers"].items()}


def synthetic(index=0):
    # Deliberately not a JWT that any issuer would accept.
    return "eyJtest.payload%d.signature" % index


class AuthContract(ClientCase):
    def setup_auth(self, handler=None, client="test-client", secret="test-secret", audience="memory"):
        self.issued = []
        self.api_handler = handler or (lambda req: (200, {"ok": True}, {}))

        def dispatch(req):
            if req["path"] == "/token":
                time.sleep(getattr(self, "grant_delay", 0))
                token = synthetic(len(self.issued))
                self.issued.append(token)
                return 200, {"access_token": token, "expires_in": 3599}, {}
            return self.api_handler(req)

        self.server = FakeServer(dispatch)
        self.addCleanup(self.server.close)
        self.write_config(self.server.base + "/api", auth={
            "type": "client_credentials", "token_url": self.server.base + "/token",
            "client_id": client, "secret_file": "~/.config/session-search/client.secret",
            "audience": audience,
        })
        self.cdir = Path(self.tmp) / ".config/session-search"
        self.cdir.parent.chmod(0o700)
        self.cdir.chmod(0o700)
        (self.cdir / "client.secret").write_text(secret)
        (self.cdir / "client.secret").chmod(0o600)
        self.cache = self.cdir / "token.json"
        return self.server

    def assert_clean(self, result):
        output = result.stdout + result.stderr
        self.assertFalse(any(t in output for t in self.issued), "bearer in stdout/stderr")
        for path in Path(self.tmp).rglob("*"):
            if path.is_file() and not path.is_symlink() and path != self.cache:
                data = path.read_bytes() if path.stat().st_size else b""
                self.assertFalse(any(t.encode() in data for t in self.issued), "bearer outside token.json")
        self.assertFalse(list(self.cdir.glob(".token.*")), "temporary bearer copy remains")

    def test_basic_percent_encoding_form_user_agent_and_destination(self):
        self.setup_auth(client="client: +é", secret="secret: +é", audience="read + write")
        result = self.good("status")
        token_request = self.server.of("/token")[0]
        basic = headers(token_request)["authorization"]
        expected = base64.b64encode((urllib.parse.quote("client: +é", safe="") + ":" +
                                    urllib.parse.quote("secret: +é", safe="")).encode()).decode()
        self.assertTrue(basic == "Basic " + expected, "client-secret Basic encoding mismatch")
        self.assertEqual(token_request["method"], "POST")
        self.assertEqual(token_request["body"], {"grant_type": "client_credentials", "audience": "read + write"})
        self.assertEqual(headers(token_request)["accept"], "application/json")
        api_request = self.server.of("/status")[0]
        self.assertTrue(headers(api_request)["authorization"] == "Bearer " + self.issued[0])
        self.assertTrue(headers(api_request)["user-agent"].startswith("ccs/"))
        self.assertFalse("Basic " in headers(api_request)["authorization"])
        self.assert_clean(result)

    def test_401_refreshes_once(self):
        count = [0]
        def handler(req):
            count[0] += 1
            return (401 if count[0] == 1 else 200), {}, {}
        self.setup_auth(handler)
        result = self.good("status")
        self.assertEqual(len(self.server.of("/token")), 2)
        self.assertEqual(count[0], 2)
        values = [headers(req)["authorization"] for req in self.server.of("/status")]
        self.assertTrue(values[0] != values[1], "rejected bearer sent twice")
        self.assert_clean(result)

    def test_two_401_responses_stop_after_one_retry(self):
        self.setup_auth(lambda req: (401, {}, {}))
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.server.of("/token")), 2)
        self.assertEqual(len(self.server.of("/status")), 2)
        self.assert_clean(result)

    def test_token_redirect_is_not_followed(self):
        self.setup_auth()
        target = FakeServer()
        self.addCleanup(target.close)
        self.server.handler = lambda req: (302, {}, {"Location": target.base + "/capture"})
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(target.requests, [])
        self.assertEqual(len(self.server.requests), 1)
        self.assert_clean(result)

    def test_api_redirect_is_not_followed(self):
        target = FakeServer()
        self.addCleanup(target.close)
        self.setup_auth(lambda req: (302, {}, {"Location": target.base + "/capture"}))
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(target.requests, [])
        self.assertEqual(len(self.server.of("/status")), 1)
        self.assert_clean(result)

    def test_token_failure_body_does_not_reach_errors(self):
        self.setup_auth()
        marker = synthetic(99)
        self.issued.append(marker)
        self.server.handler = lambda req: (400, {"error": marker}, {})
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.server.of("/status")), 0)
        self.assert_clean(result)

    def test_token_response_missing_value_is_an_auth_error(self):
        self.setup_auth()
        for value in [{}, [], {"access_token": 12}, b"not json", {"access_token": ""}]:
            with self.subTest(kind=type(value).__name__):
                self.server.handler = lambda req: (200, value, {})
                result = self.run_ccs("status")
                self.assertEqual(result.returncode, 3)
                self.assert_clean(result)
        self.assertEqual(len(self.server.of("/status")), 0)

    def test_tailnet_omits_authorization_and_cache(self):
        server = FakeServer()
        self.addCleanup(server.close)
        self.write_config(server.base + "/api")
        result = self.good("status")
        self.assertEqual(len(server.requests), 1)
        self.assertNotIn("authorization", headers(server.requests[0]))
        cdir = Path(self.tmp) / ".config/session-search"
        self.assertFalse((cdir / "token.json").exists())
        self.assertFalse((cdir / "token.lock").exists())
        self.assertNotIn("Bearer", result.stdout + result.stderr)
