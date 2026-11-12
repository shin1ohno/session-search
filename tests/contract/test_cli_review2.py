"""Oracle regressions for preview encoding, argparse and platform dates."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess

from contract.harness import ClientCase, FakeServer, user


class CliReview2(ClientCase):
    def server(self):
        server = FakeServer(lambda request: (200, {"sessions": []}, {}))
        self.addCleanup(server.close)
        self.write_config(server.base)
        return server

    def test_preview_defers_non_utf8_encoding_until_remote_request(self):
        server = self.server()
        path = self.transcript([user("Straße\udcff")])
        for configured in (True, False):
            if not configured:
                (Path(self.tmp) / ".config/session-search/config.json").unlink()
            for command, key in (("_preview", "-"), ("_preview", "local:" + path),
                                 ("preview", "local:" + path)):
                with self.subTest(configured=configured, command=command, key=key):
                    result = subprocess.run(self.command + [command, key, b"STRASSE\xff"],
                                            env=self.env, cwd=self.tmp, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if key == "-":
                        self.assertIn(b"Offline fallback:", result.stdout)
                    elif command == "preview":
                        data = json.loads(result.stdout.decode("utf-8", "surrogateescape"))
                        self.assertEqual(data["snippets"][0]["fragment"], "Straße\udcff")
                    else:
                        self.assertIn(b"[user] Stra\xc3\x9fe\xff", result.stdout)
                    self.assertEqual(server.requests, [])
        self.write_config(server.base)
        self.write_breaker(3, 9999999999)
        result = subprocess.run(self.command + ["_preview", "remote", b"query\xff"],
                                env=self.env, cwd=self.tmp, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"server unavailable (circuit open)", result.stdout)
        self.assertEqual(server.requests, [])

    def test_short_help_prefix_precedes_spaced_positional_rule(self):
        server = self.server()
        for query in ("-h foo", "-hx y"):
            with self.subTest(query=query):
                result = self.good("search", query)
                self.assertIn("usage:", result.stdout.lower())
                self.assertEqual(server.requests, [])

    def test_since_early_year_uses_this_platform_strftime(self):
        server = self.server()
        now = datetime.now(timezone.utc)
        for year in (1, 384, 999):
            days = (now - datetime(year, 6, 15, tzinfo=timezone.utc)).days
            before = datetime.now(timezone.utc) - timedelta(days=days)
            self.good("search", "--since", str(days) + "d", "query")
            after = datetime.now(timezone.utc) - timedelta(days=days)
            expected = {(before + timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ")
                        for n in range(int((after - before).total_seconds()) + 2)}
            self.assertIn(server.of("/search")[-1]["body"]["since"], expected)

    def test_required_context_depends_on_macos_contract(self):
        workflow = (self.repo / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  test-python3:", 1)[1].split("\n  test-python39:", 1)[0]
        needs = next(line for line in job.splitlines() if line.strip().startswith("needs:"))
        self.assertIn("rust-macos", needs)
        self.assertIn("needs.rust-macos.result", job)

    def test_credential_error_text_has_one_owner(self):
        sources = self.repo / "crates/ccs/src"
        message = '"client secret unreadable or empty"'
        self.assertEqual((sources / "token.rs").read_text().count(message), 1)
        for name in ("resume.rs", "cli.rs", "picker.rs", "api.rs"):
            self.assertNotIn(message, (sources / name).read_text(), name)
