"""Per-scheme environment proxy selection, without the harness NO_PROXY=*.

The fake proxy records CONNECT as well as ordinary requests and never contacts
another host. All credentials in these tests are synthetic.
"""
import http.server
import threading

from . import test_auth


class RecordingProxy:
    def __init__(self):
        self.requests = []
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def handle_request(self):
                outer.requests.append((self.command, self.path))
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_CONNECT = do_GET = do_POST = handle_request
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class ProxyContract(test_auth.AuthContract):
    def test_http_ignores_https_and_all_proxy_without_no_proxy(self):
        self.setup_auth()
        proxy = RecordingProxy()
        self.addCleanup(proxy.close)
        self.env.pop("NO_PROXY", None)
        self.env.pop("no_proxy", None)
        for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            with self.subTest(variable=name):
                self.server.requests.clear()
                result = self.run_ccs("status", env={name: proxy.url})
                self.assertEqual(proxy.requests, [], "HTTP request reached a proxy for another scheme")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(self.server.of("/status"))
                self.assert_clean(result)

    def test_http_proxy_lowercase_and_no_proxy_precedence(self):
        self.setup_auth()
        upper, lower = RecordingProxy(), RecordingProxy()
        self.addCleanup(upper.close)
        self.addCleanup(lower.close)
        self.env.pop("NO_PROXY", None)
        self.env.pop("no_proxy", None)
        result = self.run_ccs("status", env={"HTTP_PROXY": upper.url, "http_proxy": lower.url})
        self.assertEqual(result.returncode, 3)
        self.assertEqual(upper.requests, [])
        self.assertTrue(lower.requests, "lowercase HTTP proxy was not selected")
        lower.requests.clear()
        self.assert_clean(self.good("status", env={"HTTP_PROXY": upper.url, "http_proxy": ""}))
        self.assertEqual(upper.requests, [])
        for rule in ("127.0.0.1", " .127.0.0.1 ", "127.0.0.1:%d" % self.server.port):
            self.assert_clean(self.good("status", env={"http_proxy": lower.url, "no_proxy": rule}))
        self.assertEqual(lower.requests, [])
        # A present empty lowercase value disables the uppercase exemption.
        result = self.run_ccs("status", env={"http_proxy": lower.url, "NO_PROXY": "*", "no_proxy": ""})
        self.assertEqual(result.returncode, 3)
        self.assertTrue(lower.requests)
