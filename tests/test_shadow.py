"""Unit tests for the S3 shadow comparison rules (tools/shadow), on synthetic data."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/shadow"))
import common  # noqa: E402
import compare  # noqa: E402
import lines  # noqa: E402
import read  # noqa: E402

KEY = b"shadow-test-key"
SURROGATE = b'{"x":"\\ud800","x":"ok"}'
DEEP = b"[" * 65 + b"0" + b"]" * 65
BIG = b'{"n":' + b"1" * 4301 + b"}"


class Source:
    """A transcript at a fixed path, served the way ingest.FileBytes serves the frozen copy."""

    path = "/home/u/.claude/projects/-w/s.jsonl"

    def __init__(self, raw_lines):
        self.data = b"".join(line + b"\n" for line in raw_lines)
        self.python, self.offsets = compare.frozen_mask_chunk(self.data, 0, KEY)

    def __call__(self, path):
        return self.data if path == self.path else None

    def tomb(self, reason, index):
        return compare.line_oracle().ORACLE._tomb_line(reason, [], self.offsets[index])


def body(lines_, path=Source.path, end=100):
    payload = ("\n".join(lines_) + "\n").encode()
    return json.dumps({"client": {"host": "h"}, "file": {"jsonl_path": path},
                       "segment": {"generation": 0, "offset": 0, "end_offset": end,
                                   "sha256": hashlib.sha256(payload).hexdigest(), "lines": lines_}},
                      ensure_ascii=False).encode()


def run(src, lines_, tombstones=0, warnings=(), state="{}"):
    req = {"method": "POST", "path": "/memory/sessions/v1/ingest", "headers": {"gzip": True},
           "body": body(lines_, end=len(src.data))}
    stats = {"files": 1, "tombstones": tombstones}
    return {"exit": 0, "stdout": ("ccs ingest: %s\n" % json.dumps(stats, sort_keys=True)).encode(),
            "state": state, "warnings": list(warnings), "requests": [req]}


def kinds(result):
    return sorted(u["kind"] for u in result.unexplained)


class IngestComparison(unittest.TestCase):
    def test_identical_runs_have_no_difference_and_count_what_they_compared(self):
        src = Source([b'{"a":1}'])
        r = compare.compare_ingest(run(src, src.python), run(src, src.python), src, KEY)
        self.assertEqual(r.unexplained, [])
        self.assertEqual(r.compared["ingest_requests"], 1)

    def test_a_changed_line_is_unexplained(self):
        src = Source([b'{"a":1}', b'{"b":2}'])
        rs = [src.python[0], '{"b":3}']
        self.assertEqual(kinds(compare.compare_ingest(run(src, src.python), run(src, rs), src, KEY)), ["line"])

    def test_d2_overwritten_surrogate_is_classified_with_its_extra_tombstone_and_warning(self):
        src = Source([b'{"a":1}', SURROGATE])
        rs = run(src, [src.python[0], src.tomb("surrogate", 1)], tombstones=1,
                 warnings=["ingest: surrogate at offset %d -> tombstoned" % src.offsets[1]])
        r = compare.compare_ingest(run(src, src.python), rs, src, KEY)
        self.assertEqual(r.unexplained, [])
        self.assertEqual(r.classified["D2-surrogate"], 1)
        self.assertEqual(r.classified["D2-warning"], 1)

    def test_d3_depth_and_integer_tombstones_are_classified(self):
        src = Source([DEEP, BIG])
        rs = run(src, [src.tomb("too-deep", 0), src.tomb("invalid-json", 1)], tombstones=2)
        r = compare.compare_ingest(run(src, src.python), rs, src, KEY)
        self.assertEqual(r.unexplained, [])
        self.assertEqual(r.classified["D3-too-deep"], 1)
        self.assertEqual(r.classified["D3-invalid-json"], 1)

    def test_a_tombstone_naming_another_lines_offset_is_unexplained(self):
        # Rust replaces the ordinary line 0 with the tombstone of the genuine D2 line 1.
        src = Source([b'{"a":1}', SURROGATE])
        rs = run(src, [src.tomb("surrogate", 1), src.python[1]], tombstones=1)
        self.assertIn("line", kinds(compare.compare_ingest(run(src, src.python), rs, src, KEY)))

    def test_a_tombstone_on_an_ordinary_line_is_unexplained(self):
        src = Source([b'{"a":1}'])
        rs = run(src, [src.tomb("surrogate", 0)], tombstones=1)
        self.assertEqual(kinds(compare.compare_ingest(run(src, src.python), rs, src, KEY)), ["line", "stdout-stats"])

    def test_python_output_that_is_not_the_frozen_client_is_unexplained(self):
        src = Source([b'{"a":1}', SURROGATE])
        py = run(src, ['{"a":2}', src.python[1]])
        rs = run(src, ['{"a":2}', src.tomb("surrogate", 1)], tombstones=1)
        self.assertIn("python-not-frozen-client", kinds(compare.compare_ingest(py, rs, src, KEY)))

    def test_stats_may_differ_only_by_the_classified_tombstones(self):
        src = Source([SURROGATE])
        rs = run(src, [src.tomb("surrogate", 0)], tombstones=1,
                 warnings=["ingest: surrogate at offset 0 -> tombstoned"])
        rs["stdout"] = rs["stdout"].replace(b'"files": 1', b'"files": 2')
        self.assertEqual(kinds(compare.compare_ingest(run(src, src.python), rs, src, KEY)), ["stdout-stats"])

    def test_an_unmatched_rust_warning_is_unexplained(self):
        src = Source([b'{"a":1}'])
        rs = run(src, src.python, warnings=["ingest: surrogate at offset 0 -> tombstoned"])
        self.assertEqual(kinds(compare.compare_ingest(run(src, src.python), rs, src, KEY)), ["warning-rust-only"])

    def test_non_utf8_warnings_must_match_the_d5_paths(self):
        src = Source([b'{"a":1}'])
        rs = run(src, src.python, warnings=[compare.NON_UTF8_WARN])
        self.assertEqual(kinds(compare.compare_ingest(run(src, src.python), rs, src, KEY)), ["warning-rust-only"])
        py = run(src, src.python)
        py["requests"].append(dict(py["requests"][0], key=("ingest", "/home/u/\udcff.jsonl", 0)))
        r = compare.compare_ingest(py, rs, src, KEY)
        self.assertEqual(r.unexplained, [])
        self.assertEqual((r.classified["D5"], r.classified["D5-warning"]), (1, 1))

    def test_missing_requests_state_and_exit_are_unexplained(self):
        src = Source([b'{"a":1}'])
        py, rs = run(src, src.python), run(src, src.python, state="other")
        rs["requests"] = []
        rs["exit"] = 1
        self.assertEqual(kinds(compare.compare_ingest(py, rs, src, KEY)), ["exit", "request-count", "state"])

    def test_a_state_file_out_of_contract_is_unexplained_even_when_both_agree(self):
        src = Source([b'{"a":1}'])
        bad = {"format_ok": False, "text": "{}"}
        r = compare.compare_ingest(run(src, src.python, state=bad), run(src, src.python, state=bad), src, KEY)
        self.assertEqual(kinds(r), ["state-format"])

    def test_report_holds_no_content(self):
        src = Source([b'{"secret":"value-from-data"}'])
        r = compare.compare_ingest(run(src, src.python), run(src, ['{"secret":"other"}']), src, KEY)
        self.assertNotIn("value-from-data", json.dumps(r.report()))
        common.check_content_free(r.report())


class DeepLines(unittest.TestCase):
    def test_valid_nesting_beyond_python_recursion_is_d3(self):
        deep = b"[" * 20000 + b"0" + b"]" * 20000
        tomb = compare.line_oracle().ORACLE._tomb_line
        self.assertEqual(compare.classify_line(deep, 7, tomb("too-deep", [], 7)), "D3-too-deep")
        self.assertIsNone(compare.classify_line(deep, 7, tomb("surrogate", [], 7)))

    def test_invalid_deep_nesting_is_not_d3(self):
        broken = b"[" * 20000 + b"0" + b"]" * 19999 + b"x"
        tomb = compare.line_oracle().ORACLE._tomb_line("too-deep", [], 7)
        self.assertIsNone(compare.classify_line(broken, 7, tomb))


class LineJudge(unittest.TestCase):
    def test_the_expected_row_passes_and_a_wrong_route_fails(self):
        raw = b'{"password":"abcdefghijk"}'
        want, _ = lines.expectation(raw, 5)
        tally = lines.collections.Counter()
        self.assertIsNone(lines.judge(raw, 5, want, tally))
        self.assertEqual(lines.judge(raw, 5, dict(want, route="text"), tally), "route-text-expected-record")

    def test_labels_from_output_are_allow_listed(self):
        self.assertEqual(compare.label("record"), "record")
        self.assertTrue(compare.label("sk-live-SECRET value").startswith("other-"))


class ReadVerdict(unittest.TestCase):
    def test_verdicts(self):
        ok, other, failed = (0, b"a", b""), (0, b"b", b""), (3, b"", b"ccs: down")
        self.assertEqual(read.verdict(failed, failed), "python-failed")
        self.assertEqual(read.verdict(ok, ok), "equal")
        self.assertEqual(read.verdict(ok, other, ok), "different")
        self.assertEqual(read.verdict(ok, other, other), "server-changed")
        self.assertEqual(read.verdict(ok, (0, b"a", b"ccs: warn")), "different")

    def test_status_ignores_only_the_token_line(self):
        py = (0, b"breaker: closed\nlast errors:\n", b"")
        rs = (0, b"breaker: closed\ntoken:      cached\nlast errors:\n", b"")
        self.assertEqual(read.verdict(py, rs, normalize=read.without_token_line), "equal")

    def test_online_search_ignores_only_server_timing_and_scores(self):
        def out(score, took, title="テ", **dumps):
            return (0, json.dumps({"sessions": [{"session_key": "k", "title": title, "score": score}],
                                   "took_ms": took}, **dict({"ensure_ascii": False}, **dumps)).encode(), b"")
        n = read.server_noise_removed
        self.assertEqual(read.verdict(out(1.5, 3), out(1.25, 9), normalize=n), "equal")
        self.assertEqual(read.verdict(out(1.5, 3), out(1.5, 3, title="u"), out(1.5, 3), normalize=n), "different")
        # Formatting that parsing would hide is still a difference.
        self.assertEqual(read.verdict(out(1.5, 3), out(1.5, 3, ensure_ascii=True), normalize=n), "different")
        self.assertEqual(read.verdict(out(1.5, 3), out(1.5, 3, separators=(",", ":")), normalize=n), "different")
        # Only numeric scores are blanked.
        self.assertEqual(read.verdict(out(1.5, 3), out("1.5", 3), normalize=n), "different")
        self.assertEqual(read.verdict(out(1.5, 3), out(None, 3), normalize=n), "different")

    def test_equal_scores_must_have_identical_text(self):
        self.assertTrue(read.score_text_mismatch((0, b'{"score": 1.50}', b""), (0, b'{"score": 1.5}', b"")))
        self.assertTrue(read.score_text_mismatch((0, b'{"score":1.50}', b""), (0, b'{"score":1.5}', b"")))
        self.assertFalse(read.score_text_mismatch((0, b'{"score": 1.5}', b""), (0, b'{"score": 1.25}', b"")))

    def test_only_sessions_quiet_for_fifteen_minutes_are_previewed_online(self):
        rows = {"sessions": [{"session_key": "live", "updated_at": "2026-11-28T00:59:00.000Z"},
                             {"session_key": "live-jst", "updated_at": "2026-11-28T09:59:00+09:00"},
                             {"updated_at": "2026-11-28T00:10:00Z"},
                             {"session_key": "no-zone", "updated_at": "2026-11-28T00:10:00"},
                             "not-a-row",
                             {"session_key": "quiet", "updated_at": "2026-11-28T00:40:00.000Z"}]}
        now = 1795827600.0  # 2026-11-28T01:00:00Z
        self.assertEqual(read.quiet_keys(json.dumps(rows).encode(), 2, now), ["quiet"])
        for odd in (b'{"sessions": null}', b"[]", b"not json", b'{"sessions": [null]}'):
            self.assertEqual(read.quiet_keys(odd, 2, now), [])

    def test_snippet_order_is_excused_only_with_rerun_evidence(self):
        def out(snippets, n=1, **dumps):
            value = {"session": {"n": n}, "snippets": snippets}
            return (0, json.dumps(value, **dict({"ensure_ascii": False}, **dumps)).encode(), b"")
        a, b, c = {"ts": "1", "fragment": "x"}, {"ts": "2", "fragment": "y"}, {"ts": "3", "fragment": "テ"}
        order, python = read.order_verdict, [out([a, b, c])] * 3
        # Rust follows the server: its own order varies across reruns.
        self.assertEqual(order(python, [out([b, a, c]), out([c, b, a])]), "server-order")
        # A rerun byte-identical to Python shows Rust can produce Python's output.
        self.assertEqual(order(python, [out([b, a, c]), out([a, b, c])]), "server-changed")
        # A Rust order that never varies and never matches is a Rust difference.
        self.assertEqual(order(python, [out([b, a, c])] * 3), "different")
        # Number types and formatting outside the order still count.
        self.assertEqual(order(python, [out([b, a, c], n=1.0), out([c, b, a], n=1.0)]), "different")
        self.assertEqual(order(python, [out([b, a, c], ensure_ascii=True), out([c, b, a], ensure_ascii=True)]),
                         "different")
        self.assertEqual(order(python, [out([b, a, c], separators=(",", ":")), out([c, b, a], separators=(",", ":"))]),
                         "different")
        # A changed snippet is not a reorder, nor is a changed exit code.
        self.assertEqual(order(python, [out([b, a, dict(c, fragment="w")]), out([c, b, a])]), "different")
        self.assertEqual(order(python, [(1,) + out([b, a, c])[1:], (1,) + out([c, b, a])[1:]]), "different")

    def test_gate_requires_an_equal_comparison_and_hits(self):
        t = read.Tally()
        t.add("search-offline", "equal", "q", hits=0)
        self.assertEqual(t.gate(["search-offline", "preview-local"]),
                         ["search-offline-no-hits", "preview-local-compared-nothing"])
        t = read.Tally()
        t.add("search-online", "server-changed", "q", hits=3)
        t.add("preview-online", "server-order", "k")
        self.assertEqual(t.gate(["search-online", "preview-online"]),
                         ["search-online-equal-nothing", "search-online-no-hits", "preview-online-equal-nothing"])


class Guards(unittest.TestCase):
    def test_free_text_long_strings_and_non_ascii_are_refused(self):
        for bad in ["x" * 200, "line\nbreak", "日本語", {"k": ["ok", b"bytes"]}]:
            with self.assertRaises(ValueError):
                common.check_content_free({"v": bad})
        common.check_content_free({"label": "route_text", "n": 3, "digest": "a" * 64, "ok": True})

    def test_write_report_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            with self.assertRaises(ValueError):
                common.write_report(target, {"leak": "transcript text that is far too long to be a label " * 3})
            self.assertFalse(target.exists())
            common.write_report(target, {"n": 1})
            self.assertEqual(json.loads(target.read_text()), {"n": 1})
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_tools_refuse_the_real_home_and_unmarked_directories(self):
        with self.assertRaises(SystemExit):
            common.require_snapshot(Path.home())
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                common.require_snapshot(Path(tmp))
            (Path(tmp) / common.MARKER).write_text("")
            self.assertEqual(common.require_snapshot(Path(tmp)), Path(tmp).resolve())
            with self.assertRaises(SystemExit):
                common.require_snapshot(Path(tmp), source_home=Path(tmp))

    def test_a_snapshot_under_a_group_writable_directory_is_refused(self):
        # Rust would run without its disk token cache there and warn on stderr.
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "shared"
            home = parent / "home"
            home.mkdir(parents=True)
            (home / common.MARKER).write_text("")
            os.chmod(home, 0o700)
            os.chmod(parent, 0o700)
            self.assertEqual(common.require_snapshot(home), home.resolve())
            os.chmod(parent, 0o775)
            with self.assertRaises(SystemExit):
                common.require_snapshot(home)
            self.assertEqual(common.writable_ancestor(home.resolve()), parent.resolve())


if __name__ == "__main__":
    unittest.main()
