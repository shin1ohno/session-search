"""Compare CLI parsing and received search requests with the Python oracle."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))
from contract.harness import ClientCase, FakeServer
from ccs import cli, picker


class ParsingOracle(ClientCase):
    def test_picker_and_structured_argument_grammar(self):
        srv = FakeServer(lambda req: (200, {"sessions": []}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.make_fzf()
        cases = [
            [], ["-V"], ["search", "-V"], ["one", "two"], ["--", "status"], ["--", "--", "--offline"],
            ["search", "--sem", "two words"], ["search", "--sem", "--sem", "hello"],
            ["search", "--deep", "foo", "bar"], ["search", "foo", "--deep", "bar"],
            ["search", "foo", "--deep", "--", "bar"], ["search", "foo", "bar", "--deep"],
            ["search", "--host", "pro-dev", "--host", "mini"],
            ["search", "--limit", "2", "--limit", "3"],
            ["search", "--since", "30m"], ["search", "--since", ""],
            ["search", "--since", "0d"], ["search", "--since", "7d\n"],
            ["search", "--host", "Bad_Host"], ["search", "--s"], ["search", "--limit", "51"],
            ["search", "--limit", "1.0"], ["search", "--limit", ""],
        ]
        for value in ("-1", "-.2", "-1.2", "-١", "-１.２", "-\U00010d40", "-\U00011bf0", "-\U00016130", "-\U0001ccf0", "-1e3", "-NaN", "-inf", "--", "-", "日本語"):
            cases.extend((["search", value], ["_backend", value]))
        for value in ("1", "+2", " 2 ", "0_2", "０２", "٢", "2_", "1__0", "-1", "-２"):
            cases.append(["search", "--limit", value])
        for args in cases:
            with self.subTest(args=args):
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    try:
                        command, ns = cli.parse(args)
                    except SystemExit as error:
                        expected = error.code
                    else:
                        expected = 0
                # D1 deliberately rejects validation values ending in LF.
                if args == ["search", "--since", "7d\n"]:
                    expected = 2
                before = len(srv.requests)
                result = self.run_ccs(*args)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertEqual(len(srv.requests), before)
                    continue
                if command in ("search", "pick"):
                    flags, opts = cli.pick_options(ns)
                    if command == "search":
                        body = srv.of("/search")[-1]["body"]
                        oracle = picker.search_body(" ".join(ns.query), flags, opts)
                        oracle["limit"] = ns.limit
                        if "since" in oracle:
                            self.assertTrue(body.pop("since").endswith("Z"))
                            oracle.pop("since")
                        self.assertEqual(body, oracle)
                    else:
                        capture = json.loads((Path(self.tmp) / "fzf.json").read_text())
                        self.assertEqual(capture["argv"][capture["argv"].index("--query") + 1], " ".join(ns.query))
                        self.assertEqual(json.loads(capture["pick"]), dict(opts, flags="".join(sorted(flags))))
                elif command == "_backend":
                    self.assertEqual(srv.of("/search")[-1]["body"]["q"], picker.search_body(ns.q, set(), {})["q"])


if __name__ == "__main__":
    os.environ.setdefault("CCS_UNDER_TEST", str(ROOT / "target/release/ccs"))
    unittest.main()
