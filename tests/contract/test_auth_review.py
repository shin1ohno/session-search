"""Regression cases for the independent HTTP/auth review, Python as oracle."""
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess

from . import test_auth


class AuthReviewContract(test_auth.AuthContract):
    def test_cache_warning_to_closed_stderr_does_not_fail_request(self):
        self.setup_auth()
        self.cdir.chmod(0o755)
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = subprocess.run(self.command + ["status"], env=self.env, cwd=self.tmp,
                                    stdout=subprocess.PIPE, stderr=write_fd, text=True, timeout=10)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode, 0, "cache warning panicked on closed stderr")
        self.assertEqual(len(self.server.of("/status")), 1)
        result.stderr = ""
        self.assert_clean(result)

    def test_missing_credential_has_exit_status_three(self):
        self.setup_auth()
        (self.cdir / "client.secret").unlink()
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3, "credential failure mapped to usage")
        self.assertEqual(self.server.requests, [])

    def test_unreadable_credential_has_exit_status_three(self):
        self.setup_auth()
        (self.cdir / "client.secret").chmod(0o000)
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3, "unreadable credential mapped to usage")
        self.assertEqual(self.server.requests, [])
        (self.cdir / "client.secret").chmod(0o600)
        self.assert_clean(result)

    def test_symlinked_credential_is_read(self):
        self.setup_auth()
        secret = self.cdir / "client.secret"
        target = self.cdir / "actual.secret"
        secret.rename(target)
        secret.symlink_to(target)
        self.assert_clean(self.good("status"))
        self.assertEqual(len(self.server.of("/status")), 1)

    def test_fresh_short_lived_grant_can_make_its_first_send(self):
        self.setup_auth()
        self.grant_delay = 1.3
        original = self.server.handler
        def limited(req):
            status, body, headers = original(req)
            if req["path"] == "/token":
                body["expires_in"] = 61
            return status, body, headers
        self.server.handler = limited
        self.assert_clean(self.good("status"))
        self.assertEqual(len(self.server.of("/status")), 1)

    def test_get_wire_headers_match_python(self):
        self.setup_auth()
        self.assert_clean(self.good("status"))
        headers = test_auth.headers(self.server.of("/status")[0])
        self.assertEqual(headers.get("accept-encoding"), "identity")
        self.assertEqual(headers.get("connection"), "close")
        self.assertNotIn("content-length", headers)

    def certificate(self, name):
        openssl = shutil.which("openssl", path=self._env.get("PATH"))
        self.assertIsNotNone(openssl, "openssl required for hermetic TLS contract")
        cert = Path(self.tmp) / (name + ".pem")
        key = Path(self.tmp) / (name + ".key")
        result = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                 "-days", "1", "-keyout", str(key), "-out", str(cert),
                                 "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                                 "-addext", "basicConstraints=critical,CA:FALSE"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, "local test certificate generation failed")
        return cert, key

    def test_ssl_cert_file_trusts_only_the_selected_bundle(self):
        self.setup_auth()
        cert, key = self.certificate("server")
        other_cert, _ = self.certificate("other")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        self.server.httpd.socket = context.wrap_socket(self.server.httpd.socket, server_side=True)
        path = self.cdir / "config.json"
        data = json.loads(path.read_text())
        data["endpoint"] = data["endpoint"].replace("http:", "https:")
        data["auth"]["token_url"] = data["auth"]["token_url"].replace("http:", "https:")
        path.write_text(json.dumps(data))
        self.assert_clean(self.good("status", env={"SSL_CERT_FILE": str(cert)}))
        count = len(self.server.requests)
        result = self.run_ccs("status", env={"SSL_CERT_FILE": str(other_cert)})
        self.assertEqual(result.returncode, 3, "untrusted TLS peer accepted")
        self.assertEqual(len(self.server.requests), count)
        self.assert_clean(result)

    def test_http_does_not_load_ssl_cert_file(self):
        self.setup_auth()
        self.assert_clean(self.good("status", env={"SSL_CERT_FILE": str(self.cdir / "missing.pem")}))

    def test_config_diagnostics_preserve_python_order_and_field_names(self):
        self.setup_auth()
        base = {"endpoint": self.server.base, "host_label": "test", "hmac_key_file": "key"}
        cases = [
            ({}, "config: `endpoint` is missing"),
            ({"endpoint": self.server.base}, "config: `host_label` must match ^[a-z0-9-]{1,63}$"),
            (base, "config: `auth` must be an object"),
            (dict(base, auth={}), 'config: `auth.type` must be "tailnet" or "client_credentials"'),
            (dict(base, auth={"type": "client_credentials"}), "config: `auth.token_url` is missing"),
            (dict(base, auth={"type": "client_credentials", "token_url": self.server.base}), "config: `auth.client_id` is missing"),
            (dict(base, auth={"type": "client_credentials", "token_url": self.server.base, "client_id": "test"}), "config: `auth.secret_file` is missing"),
        ]
        path = self.cdir / "config.json"
        for data, expected in cases:
            with self.subTest(expected=expected):
                path.write_text(json.dumps(data))
                result = self.run_ccs("status")
                self.assertIn(expected, result.stdout + result.stderr)
        path.write_text("{invalid")
        result = self.run_ccs("status")
        self.assertIn("config %s is not valid JSON" % path, result.stdout + result.stderr)
        path.unlink()
        path.mkdir()
        result = self.run_ccs("status")
        self.assertIn("config %s unreadable (IsADirectoryError)" % path, result.stdout + result.stderr)

    def test_progressing_response_survives_past_status_timeout(self):
        import time
        self.setup_auth()
        handler = self.server.httpd.RequestHandlerClass
        original = handler.do_GET
        requests = self.server.requests
        def slow_get(request):
            if request.path != "/api/status":
                return original(request)
            requests.append({"path": "/api/status", "method": "GET"})
            body = b'{"ok":true}'.ljust(100, b' ')
            request.send_response(200)
            request.send_header("Content-Length", str(len(body)))
            request.end_headers()
            for offset in range(0, len(body), 10):
                time.sleep(0.4)
                try:
                    request.wfile.write(body[offset:offset + 10])
                    request.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
        handler.do_GET = slow_get
        self.assert_clean(self.good("status", timeout=12))
        self.assertEqual(len(self.server.of("/status")), 1)
