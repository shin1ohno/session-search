"""External-process regressions from the native CLI integration review."""
import json
import os
from pathlib import Path
import resource
import subprocess
import unittest

from contract.harness import ClientCase, FakeServer, user


class CliReview(ClientCase):
    def server(self, body):
        server = FakeServer(lambda request: (200, body, {}))
        self.addCleanup(server.close)
        self.write_config(server.base)
        return server

    def test_dash_words_with_spaces_are_positional(self):
        server = self.server({"sessions": []})
        self.make_fzf()
        for command in ("search", "_backend", "pick"):
            for query in ("-foo bar", "--force push", "-x y"):
                with self.subTest(command=command, query=query):
                    self.good(*(([command] if command != "pick" else []) + [query]))
                    if command != "pick":
                        self.assertEqual(server.of("/search")[-1]["body"]["q"], query)

    def test_empty_current_session_does_not_expand_limit_or_drop_rows(self):
        server = self.server({"sessions": [{"session_id": "", "session_key": "empty"},
                                           {"session_id": "other", "session_key": "other"}]})
        result = self.good("search", "--limit", "3", "query", env={"CODEX_THREAD_ID": ""})
        self.assertEqual(server.of("/search")[-1]["body"]["limit"], 3)
        self.assertEqual([r["session_key"] for r in json.loads(result.stdout.decode("utf-8", "surrogateescape") if isinstance(result.stdout, bytes) else result.stdout)["sessions"]], ["empty", "other"])

    def test_since_before_year_one_is_internal_error_without_request(self):
        server = self.server({"sessions": []})
        for duration in ("999999d", "110000w"):
            with self.subTest(duration=duration):
                self.assertEqual(self.run_ccs("search", "--since", duration, "query").returncode, 1)
                self.assertEqual(server.requests, [])

    def test_non_mapping_rows_and_preview_sessions_fail(self):
        server = self.server({})
        for command, payload in (("search", {"sessions": [{}, "str-row"]}),
                                 ("preview", {"session": ["x", "y"]})):
            with self.subTest(command=command):
                server.handler = lambda request: (200, payload, {})
                self.assertEqual(self.run_ccs(command, "key").returncode, 1)

    def test_non_utf8_query_preserves_python_surrogateescape(self):
        server = self.server({"sessions": []})
        self.transcript([user("recent transcript")])
        for query in (b"\xff", b"\xffab", b"a\xc3\xa9\xfe", b"\xed\xa0\x80"):
            for command in ("search", "_backend"):
                with self.subTest(query=query, command=command):
                    result = subprocess.run(self.command + [command, query], env=self.env, cwd=self.tmp,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                    points = query.decode("utf-8", "surrogateescape").strip()
                    if len(points) >= 2:
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertEqual(result.stdout, b"")
                        self.assertEqual(server.requests, [])
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        expected = {"q": "", "mode": "lexical", "deep": False, "include_headless": False, "include_sidechain": False, "limit": 50}
                        self.assertEqual(server.of("/search")[-1]["raw"], json.dumps(expected, ensure_ascii=False, separators=(",", ":")).encode())
                    server.requests.clear()
        result = subprocess.run(self.command + ["_preview", "remote", b"query\xff"], env=self.env,
                                cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(server.requests, [])
        result = subprocess.run(self.command + ["search", "--offline", b"\xff"], env=self.env,
                                cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout.decode("utf-8", "surrogateescape") if isinstance(result.stdout, bytes) else result.stdout)["sessions"]), 1)

    def offline_query_fixture(self):
        path = self.transcript([user("Straße\udcff")])
        self.fake("rg", "import os,sys,json\nfrom pathlib import Path\n"
                  "Path(os.environ['CCS_EXEC_LOG']).write_text(json.dumps([os.fsencode(x).hex() for x in sys.argv[1:]]))\n"
                  "print(" + repr(path) + ")\n")
        expected = [b"-l", b"-F", b"-i", b"--glob", b"*.jsonl", b"--glob", b"!**/subagents/**", b"--", b"STRASSE\xff", os.fsencode(Path(self.tmp) / ".claude/projects")]
        return path, expected

    def test_non_utf8_offline_query_preserves_rg_bytes_and_casefold_matches(self):
        path, expected = self.offline_query_fixture()
        result = subprocess.run(self.command + ["search", "--offline", b"STRASSE\xff"],
                                env=self.env, cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.exec_path.read_text()), [x.hex() for x in expected])
        rows = json.loads(result.stdout.decode("utf-8", "surrogateescape") if isinstance(result.stdout, bytes) else result.stdout)["sessions"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hit_count"], 1)
        self.assertEqual(rows[0]["title"], "Straße\udcff")

    def test_non_utf8_backend_with_open_circuit_uses_original_rg_bytes(self):
        path, expected = self.offline_query_fixture()
        server = self.server({"sessions": []})
        self.breaker_path.write_text(json.dumps({"failures": 3, "open_until": 9999999999}))
        result = subprocess.run(self.command + ["_backend", b"STRASSE\xff"], env=self.env,
                                cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(os.fsencode(path), result.stdout)
        self.assertEqual(server.requests, [])
        self.assertEqual(json.loads(self.exec_path.read_text()), [x.hex() for x in expected])


@unittest.skipUnless(os.environ.get("CCS_RUST_CLIENT") == "1", "Rust process and token-state extension")
class RustReview(ClientCase):
    def test_resume_preserves_hard_core_limit(self):
        cwd = Path(self.tmp) / "work"
        cwd.mkdir()
        path = self.transcript([user("resume", cwd=str(cwd))], cwd=str(cwd))
        self.fake("claude", "import json,os,resource\nfrom pathlib import Path\n"
                  "Path(os.environ['CCS_EXEC_LOG']).write_text(json.dumps({'core':resource.getrlimit(resource.RLIMIT_CORE)}))\n")
        inherited = resource.getrlimit(resource.RLIMIT_CORE)[1]
        self.assertNotEqual(inherited, 0)
        def enable_soft_limit():
            _, hard = resource.getrlimit(resource.RLIMIT_CORE)
            resource.setrlimit(resource.RLIMIT_CORE, (min(hard, 1048576) if hard >= 0 else 1048576, hard))
        result = subprocess.run(self.command + ["resume", "local:" + path, "--to", str(cwd)],
                                env=self.env, cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                preexec_fn=enable_soft_limit, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.exec_path.read_text())["core"], [0, inherited])

    def test_status_reports_refreshed_disk_and_rejected_token_state(self):
        from contract import test_auth
        test_auth.AuthContract.setup_auth(self)
        self.assertIn("token:      refreshed\n", self.good("status").stdout)
        self.assertIn("token:      disk\n", self.good("status").stdout)
        self.api_handler = lambda request: (401, {}, {})
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertIn("token:      rejected\n", result.stdout)
