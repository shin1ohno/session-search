"""A3's real fzf callbacks, with a loopback HTTP/1.1 receiver.

Python deliberately does not implement A3. The Rust CI job must enable these
with CCS_RUST_CLIENT=1; ordinary helper compatibility lives in test_helper.py.
"""
import concurrent.futures
import json
import io
import ssl
import os
from pathlib import Path
import socket
import threading
import time
import unittest

from contract.test_helper import HelperBase, PREVIEW
from contract.test_auth import synthetic, headers
from contract import test_auth_review
from contract.harness import FakeServer


@unittest.skipUnless(os.environ.get("CCS_RUST_CLIENT") == "1", "Rust A3 pooled helper extension")
class HelperPool(HelperBase):
    def setUp(self):
        super().setUp()
        self.connections = 0
        self.connection_lock = threading.Lock()
        handler = self.srv.httpd.RequestHandlerClass
        handler.protocol_version = "HTTP/1.1"
        handler.disable_nagle_algorithm = True
        self.srv.httpd.socket.listen(128)
        original_setup = handler.setup
        def setup(request):
            with self.connection_lock:
                self.connections += 1
                request.connection_id = self.connections
            original_setup(request)
        handler.setup = setup
        self.srv.handler = self.echo

    def echo(self, req):
        if req["path"].endswith("/preview"):
            return 200, PREVIEW, {}
        return 200, {"sessions": [{"session_key": "key", "host": "pro-dev", "cwd": "/w",
                                   "title": "echo:" + req["body"]["q"]}]}, {}

    def key(self, query, prompt="ccs> "):
        result = self.invoke(self.backend_command(query), prompt)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(("echo:" + query).encode(), result.stdout)
        return result

    def test_thirty_keystrokes_share_one_connection(self):
        self.start_picker()
        for i in range(30):
            self.key("key%03d" % i)
        self.assertEqual(len(self.srv.of("/search")), 30)
        self.assertEqual(self.connections, 1, "helper did not reuse its HTTP agent")

    def test_fuse_and_lexical_overlap_use_two_connections(self):
        entered, release = threading.Event(), threading.Event()
        def handler(req):
            if req["body"].get("mode") == "hybrid":
                entered.set()
                self.assertTrue(release.wait(5), "lexical request serialized behind fuse")
            return self.echo(req)
        self.srv.handler = handler
        posted = FakeServer(lambda req: (200, {}, {}))
        self.addCleanup(posted.close)
        self.start_picker(env={"FZF_PORT": str(posted.httpd.server_address[1])})
        try:
            self.key("first", "ccs:s> ")
            self.assertTrue(entered.wait(3), "semantic fuse never fired")
            started = time.monotonic()
            self.key("during")
            self.assertLess(time.monotonic() - started, .7, "lexical I/O serialized behind fuse")
            self.assertEqual(self.connections, 2, "fuse did not overlap lexical I/O")
        finally:
            release.set()
        deadline = time.monotonic() + 3
        while not posted.requests and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(len(posted.requests), 1, "hybrid rows were not published to fzf")
        request = posted.requests[0]
        self.assertIn("reload(cat ", request["raw"].decode())
        self.assertEqual(headers(request).get("x-api-key"), self.child_env["FZF_API_KEY"])

    def test_server_closes_every_fourth_completed_request(self):
        handler = self.srv.httpd.RequestHandlerClass
        original = handler.handle_one_request
        completed = [0]
        def one(request):
            original(request)
            with self.connection_lock:
                completed[0] += 1
                if completed[0] % 4 == 0:
                    request.close_connection = True
        handler.handle_one_request = one
        self.start_picker()
        for i in range(24):
            self.key("closing%03d" % i)
        self.assertEqual(len(self.srv.of("/search")), 24)
        self.assertEqual(self.connections, 6)

    def test_twenty_four_concurrent_queries_keep_their_own_response(self):
        self.start_picker()
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            results = list(pool.map(lambda i: self.key("parallel%03d" % i), range(24)))
        for i, result in enumerate(results):
            self.assertEqual(result.stdout.count(b"echo:"), 1)
            self.assertIn(("echo:parallel%03d" % i).encode(), result.stdout)
        self.assertEqual(len(self.srv.of("/search")), 24)

    def preview_command(self):
        return self.argv[self.argv.index("--preview") + 1].replace("{1}", "key").replace("{q}", "query")

    def test_reused_preview_disconnect_retries_once(self):
        handler = self.srv.httpd.RequestHandlerClass
        original = handler.do_GET
        gets = []
        def get(request):
            gets.append("get")
            if len(gets) == 1:
                request.close_connection = True
                request.connection.shutdown(socket.SHUT_RDWR)
                return
            original(request)
        handler.do_GET = get
        self.start_picker()
        self.key("prime")
        result = self.invoke(self.preview_command())
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Enter: resume", result.stdout)
        self.assertEqual(len(gets), 2)

    def test_new_preview_disconnect_is_not_retried(self):
        handler = self.srv.httpd.RequestHandlerClass
        gets = []
        def get(request):
            gets.append("get")
            request.close_connection = True
            request.connection.shutdown(socket.SHUT_RDWR)
        handler.do_GET = get
        self.start_picker()
        result = self.invoke(self.preview_command())
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"server unreachable", result.stdout)
        self.assertEqual(len(gets), 1, "a new connection failure was retried")

    def test_partial_preview_response_is_not_retried(self):
        handler = self.srv.httpd.RequestHandlerClass
        gets = []
        def get(request):
            gets.append("get")
            request.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
            request.close_connection = True
            request.connection.shutdown(socket.SHUT_RDWR)
        handler.do_GET = get
        self.start_picker()
        self.key("prime")
        result = self.invoke(self.preview_command())
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"server unreachable", result.stdout)
        self.assertEqual(len(gets), 1, "partial response was retried")

    def test_concurrent_401_does_not_resend_or_invalidate_replacement(self):
        directory = Path(self.tmp) / ".config/session-search"
        directory.chmod(0o700)
        secret = directory / "client.secret"
        secret.write_text("synthetic-pool-client-secret")
        secret.chmod(0o600)
        config = directory / "config.json"
        data = json.loads(config.read_text())
        data["auth"] = {"type": "client_credentials", "client_id": "pool", "secret_file": str(secret),
                        "token_url": self.srv.base + "/token"}
        config.write_text(json.dumps(data))
        issued, sent = [], []
        barrier = threading.Barrier(2)
        replacement_sent = threading.Event()
        def handler(req):
            if req["path"] == "/token":
                issued.append(synthetic(len(issued) + 1))
                return 200, {"access_token": issued[-1], "expires_in": 3600}, {}
            bearer = headers(req).get("authorization")
            sent.append((req["body"]["q"], bearer))
            if req["body"]["q"].startswith("reject") and bearer == "Bearer " + issued[0]:
                barrier.wait(4)
                if req['body']['q'] == 'reject-two':
                    self.assertTrue(replacement_sent.wait(2), 'replacement bearer not observed before late 401')
                return 401, {}, {}
            if len(issued) > 1 and bearer == 'Bearer ' + issued[1]:
                replacement_sent.set()
            return self.echo(req)
        self.srv.handler = handler
        self.start_picker()
        self.key("prime")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(self.key, ("reject-one", "reject-two")))
        self.key("after")
        self.assertEqual(len(issued), 2, "late 401 invalidated a replacement grant")
        self.assertEqual(sum(value == "Bearer " + issued[0] for _, value in sent), 3,
                         "a rejected bearer was resent")
        self.assertTrue(sent[-1][1] == "Bearer " + issued[1], "replacement was not retained")
        for path in Path(self.tmp).rglob("*"):
            if path.is_file() and not path.is_symlink() and path.name != "token.json":
                self.assertFalse(any(value.encode() in path.read_bytes() for value in issued), "bearer leaked")
        self.assertEqual(self.finish_picker(), 0)
        self.assertFalse(any(value.encode() in b"".join(self.picker_output) for value in issued),
                         "bearer in picker stdout/stderr")

    def intercept_search(self, action):
        handler = self.srv.httpd.RequestHandlerClass
        original = handler.do_POST
        attempts = []
        def post(request):
            if not request.path.endswith('/search'):
                return original(request)
            raw = request.rfile.read(int(request.headers.get('Content-Length', 0)))
            body = json.loads(raw)
            request.search_count = getattr(request, 'search_count', 0) + 1
            attempts.append((request.connection_id, body['q'], raw, request.headers.get('Authorization')))
            if action(request, body):
                request.close_connection = True
                request.connection.shutdown(socket.SHUT_RDWR)
                return
            reader = request.rfile
            request.rfile = io.BytesIO(raw)
            try:
                return original(request)
            finally:
                request.rfile = reader
        handler.do_POST = post
        return attempts

    def test_reused_post_drop_every_fourth_request_retries_identical_body(self):
        reused, dropped = [0], []
        def action(request, body):
            if request.search_count > 1:
                reused[0] += 1
                if reused[0] % 4 == 0:
                    dropped.append(body['q'])
                    return True
            return False
        attempts = self.intercept_search(action)
        self.start_picker()
        for i in range(24):
            self.key('drop%03d' % i)
        self.assertEqual(len(dropped), 5)
        self.assertEqual(len(attempts), 29)
        self.assertEqual(self.connections, 6)
        for q in dropped:
            copies = [raw for _, query, raw, _ in attempts if query == q]
            self.assertEqual(len(copies), 2)
            self.assertEqual(copies[0], copies[1], 'retry changed the search body')

    def enable_auth(self):
        directory = Path(self.tmp) / '.config/session-search'
        directory.chmod(0o700)
        secret = directory / 'client.secret'
        secret.write_text('synthetic-pool-client-secret')
        secret.chmod(0o600)
        config = directory / 'config.json'
        data = json.loads(config.read_text())
        data['auth'] = {'type': 'client_credentials', 'client_id': 'pool', 'secret_file': str(secret),
                        'token_url': self.srv.base + '/token'}
        config.write_text(json.dumps(data))
        return config

    def test_transport_retry_reacquires_after_another_request_rejects(self):
        self.enable_auth()
        dropped, replacement = threading.Event(), threading.Event()
        issued, sent = [], []
        def handler(req):
            if req['path'] == '/token':
                issued.append(synthetic(len(issued) + 1))
                return 200, {'access_token': issued[-1], 'expires_in': 3600}, {}
            bearer = headers(req).get('authorization')
            sent.append((req['body']['q'], bearer))
            if req['body']['q'] == 'reject' and bearer == 'Bearer ' + issued[0]:
                return 401, {}, {}
            if len(issued) > 1 and bearer == 'Bearer ' + issued[1]:
                replacement.set()
            return self.echo(req)
        self.srv.handler = handler
        def action(request, body):
            if body['q'] == 'drop' and not dropped.is_set():
                self.assertGreater(request.search_count, 1)
                dropped.set()
                self.assertTrue(replacement.wait(2), 'replacement request never arrived')
                return True
            return False
        attempts = self.intercept_search(action)
        self.start_picker()
        self.key('prime')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            waiting = pool.submit(self.key, 'drop')
            self.assertTrue(dropped.wait(2))
            self.key('reject')
            waiting.result()
        copies = [bearer for _, q, _, bearer in attempts if q == 'drop']
        self.assertEqual(copies, ['Bearer ' + issued[0], 'Bearer ' + issued[1]],
                         'transport retry resent a bearer rejected by another request')
        self.assertEqual(len(issued), 2)

    def test_transport_retry_reacquires_single_use_token(self):
        self.enable_auth()
        issued, dropped = [], [False]
        def handler(req):
            if req['path'] == '/token':
                issued.append(synthetic(len(issued) + 1))
                return 200, {'access_token': issued[-1]}, {}
            return self.echo(req)
        self.srv.handler = handler
        def action(request, body):
            if body['q'] == 'drop' and not dropped[0]:
                self.assertGreater(request.search_count, 1)
                dropped[0] = True
                return True
            return False
        attempts = self.intercept_search(action)
        self.start_picker()
        self.key('prime')
        self.key('drop')
        self.assertEqual(len(issued), 3, 'one-use bearer reused for a transport retry')
        self.assertEqual([bearer for _, q, _, bearer in attempts if q == 'drop'],
                         ['Bearer ' + issued[1], 'Bearer ' + issued[2]])
        # Three token POSTs have their own close-per-request connections.
        # Prime and first drop share an API connection; its retry creates one.
        self.assertEqual(self.connections, 5, 'token grants consumed an API pool connection')

    def test_slow_token_fetch_is_single_flight_and_bounds_waiters(self):
        self.enable_auth()
        release = threading.Event()
        grants = []
        handler = self.srv.httpd.RequestHandlerClass
        original = handler.do_POST
        def post(request):
            if request.path != '/token':
                return original(request)
            request.rfile.read(int(request.headers.get('Content-Length', 0)))
            grants.append(time.monotonic())
            body = b'{' + b' ' * 30 + b'}'
            request.send_response(503)
            request.send_header('Content-Length', str(len(body)))
            request.end_headers()
            try:
                for byte in body:
                    request.wfile.write(bytes([byte]))
                    request.wfile.flush()
                    release.wait(.15)
            except (BrokenPipeError, ConnectionResetError):
                pass
        handler.do_POST = post
        # Disable the best-effort disk cache so flock cannot accidentally
        # conceal a broken single-flight implementation in this test.
        (Path(self.tmp) / '.config/session-search').chmod(0o777)
        self.start_picker()
        started = time.monotonic()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                results = list(pool.map(lambda i: self.invoke(self.backend_command('slow%d' % i)), range(24)))
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 2.5, 'waiters exceeded the helper acquisition deadline')
            self.assertEqual(len(grants), 1, 'waiters started serial token fetches')
            self.assertTrue(all(b'OFFLINE' in r.stdout for r in results))
        finally:
            release.set()

    def test_pool_headers_match_plain_cli_except_connection(self):
        self.start_picker()
        self.key('wire')
        pooled = headers(self.srv.of('/search')[-1])
        self.good('search', 'wire')
        plain = headers(self.srv.of('/search')[-1])
        self.assertEqual(plain.pop('connection'), 'close')
        self.assertNotIn('connection', pooled)
        self.assertEqual(pooled, plain)
        self.assertEqual(pooled['accept-encoding'], 'identity')

    def test_https_bundle_keeps_one_connection_after_http_config_change(self):
        cert, key = test_auth_review.AuthReviewContract.certificate(self, 'pool-server')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server = FakeServer(self.echo)
        self.addCleanup(server.close)
        server.httpd.socket = context.wrap_socket(server.httpd.socket, server_side=True)
        handler = server.httpd.RequestHandlerClass
        handler.protocol_version = 'HTTP/1.1'
        handler.disable_nagle_algorithm = True
        setup = handler.setup
        connections = []
        def count(request):
            connections.append(1)
            setup(request)
        handler.setup = count
        self.start_picker(env={'SSL_CERT_FILE': str(cert)})
        self.key('http-first')
        config = Path(self.tmp) / '.config/session-search/config.json'
        data = json.loads(config.read_text())
        data['endpoint'] = server.base.replace('http:', 'https:')
        config.write_text(json.dumps(data))
        for i in range(30):
            self.key('tls%03d' % i)
        self.assertEqual(len(server.of('/search')), 30)
        self.assertEqual(len(connections), 1, 'TLS configuration disabled connection reuse')

    def test_config_rebuild_keeps_process_rejection_registry(self):
        config = self.enable_auth()
        values = [synthetic(1), synthetic(2), synthetic(1), synthetic(3)]
        issued, sent, connections = [], [], []
        def handler(req):
            if req['path'] == '/token':
                value = values[len(issued)]
                issued.append(value)
                return 200, {'access_token': value, 'expires_in': 3600}, {}
            bearer = headers(req).get('authorization')
            sent.append(bearer)
            if len(sent) == 1:
                return 401, {}, {}
            return self.echo(req)
        self.srv.handler = handler
        def action(request, body):
            connections.append(request.connection_id)
            return False
        self.intercept_search(action)
        self.start_picker()
        self.key('reject-first')
        data = json.loads(config.read_text())
        data['endpoint'] += '/changed'
        config.write_text(json.dumps(data))
        self.key('after-rebuild')
        self.assertEqual(issued, values)
        self.assertEqual(sent, ['Bearer ' + values[i] for i in (0, 1, 3)],
                         'config rebuild forgot a previously rejected bearer')
        self.assertNotEqual(connections[-1], connections[-2], 'API was not rebuilt after config changed')

    def test_large_helper_response_is_capped(self):
        self.srv.handler = lambda req: (200, {'sessions': [{'session_key': 'large', 'title': 'x' * (4 * 1024 * 1024 + 1)}]}, {})
        self.start_picker()
        result = self.invoke(self.backend_command('large'))
        self.assertIn(b'OFFLINE', result.stdout, 'unbounded helper response accepted')
        self.assertLess(len(result.stdout), 10000)

    def test_helper_worker_count_is_bounded(self):
        self.start_picker()
        sockets = []
        try:
            for _ in range(64):
                stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                stream.settimeout(2)
                stream.connect(self.sock)
                try:
                    stream.sendall(b'GET /')
                except BrokenPipeError:
                    pass
                sockets.append(stream)
            time.sleep(.2)
            # The receiver must reject excess connections without allocating workers.
            rejected = 0
            for stream in sockets[32:]:
                stream.settimeout(.05)
                try:
                    rejected += b'503 Service Unavailable' in stream.recv(4096)
                except (TimeoutError, ConnectionResetError):
                    pass
            self.assertGreaterEqual(rejected, 28, 'helper accepted excess workers')
            if os.path.exists('/proc/self/status'):
                status = Path('/proc/%d/status' % self.proc.pid).read_text()
                threads = int(next(line.split()[1] for line in status.splitlines() if line.startswith('Threads:')))
                self.assertLessEqual(threads, 36, 'helper spawned an unbounded worker per connection')
        finally:
            for stream in sockets:
                stream.close()

    def test_failed_token_fetch_is_shared_briefly(self):
        self.enable_auth()
        grants = []
        def handler(req):
            if req['path'] == '/token':
                grants.append(1)
                return 503, {}, {}
            return self.echo(req)
        self.srv.handler = handler
        self.start_picker()
        for i in range(5):
            self.breaker_path.unlink(missing_ok=True)
            self.invoke(self.backend_command('failure%d' % i))
        self.assertEqual(len(grants), 1, 'failed grant was not briefly cached')

    def test_token_grants_do_not_consume_warm_api_connections(self):
        self.enable_auth()
        issued = []
        def handler(req):
            if req['path'] == '/token':
                issued.append(synthetic(len(issued) + 1))
                return 200, {'access_token': issued[-1]}, {}
            return self.echo(req)
        self.srv.handler = handler
        attempts = self.intercept_search(lambda request, body: False)
        self.start_picker()
        for i in range(3):
            self.key('grant%d' % i)
        self.assertEqual(len(issued), 3)
        self.assertEqual(len({connection for connection, _, _, _ in attempts}), 1,
                         'token fetch borrowed and closed a warm API connection')
