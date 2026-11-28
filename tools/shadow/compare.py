"""Comparison rules for the S3 shadow run.

A difference between the Python and Rust outputs is either one of the
approved deviations (docs/compat-deviations.md: D2, D3, D5) proven line by
line from the raw input, or it is reported as unexplained. Results carry
counts, labels and digests only.
"""
from __future__ import annotations

import collections
import json
import re
import sys
import threading
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, sha  # noqa: E402

TOMBSTONE = "session-search-tombstone"
SURROGATE_WARN = re.compile(r"ingest: surrogate at offset (\d+) -> tombstoned\Z")
NON_UTF8_WARN = "ingest: non-UTF-8 name skipped"
ROUTES = {"text", "record", "tombstone", "skip"}
FIELD = re.compile(r"[a-z_]{1,32}\Z")
_LINE_ORACLE = None


def line_oracle():
    """tests/conformance/line_oracle.py: the frozen client and the D2/D3 contract."""
    global _LINE_ORACLE
    if _LINE_ORACLE is None:
        sys.path.insert(0, str(REPO / "tests/conformance"))
        import line_oracle as module
        _LINE_ORACLE = module
    return _LINE_ORACLE


def label(value) -> str:
    """A report-safe label for a value that came from an implementation's output."""
    if isinstance(value, str) and (value in ROUTES or FIELD.match(value)):
        return value
    return "other-" + sha(repr(value))[:8]


def deep_call(fn, *args):
    """Run fn where json.loads accepts any nesting depth.

    The C scanner has its own recursion bound (fixed from Python 3.12), so the
    pure-Python scanner is swapped in, with a large stack and recursion limit.
    """
    import json.scanner
    box = {}

    def target():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # re-raised in the caller's thread
            box["error"] = exc
    old_limit, old_stack = sys.getrecursionlimit(), threading.stack_size()
    old_scanner, old_default = json.scanner.make_scanner, json._default_decoder
    try:
        json.scanner.make_scanner = json.scanner.py_make_scanner
        json._default_decoder = json.JSONDecoder()
        sys.setrecursionlimit(max(old_limit, 1_000_000))
        threading.stack_size(1 << 29)
        t = threading.Thread(target=target)
        t.start()
        t.join()
    finally:
        threading.stack_size(old_stack)
        sys.setrecursionlimit(old_limit)
        json.scanner.make_scanner, json._default_decoder = old_scanner, old_default
    if "error" in box:
        raise box["error"]
    return box["value"]


def contract(raw: bytes, offset: int, python_expect=None):
    """(tags, expectation) of the approved D2/D3 contract, valid at any nesting depth."""
    lo = line_oracle()
    value = {"hex": raw.hex(), "offset": offset}
    try:
        tags, _, expect = lo.G.rust_line_contract(lo.ORACLE, value, python_expect)
    except RecursionError:
        tags, _, expect = deep_call(lo.G.rust_line_contract, lo.ORACLE, value, python_expect)
    return tags, expect


def classify_line(raw: bytes, offset: int, rust_line: str):
    """The approved deviation that makes Rust's tombstone correct for this raw line, or None."""
    tags, expect = contract(raw, offset)
    if not tags or rust_line != expect["output"]:
        return None
    return "%s-%s" % (tags[0], json.loads(expect["output"])["reason"])


def frozen_mask_chunk(chunk: bytes, start: int, key: bytes):
    """(lines, offsets) the frozen Python client produces for a newline-terminated chunk."""
    lo = line_oracle()
    shipper = lo.ORACLE.Shipper.__new__(lo.ORACLE.Shipper)
    shipper.redactor = types.SimpleNamespace(redact_text=lo.SR.redact_text, redact_record=lo.SR.redact_record)
    shipper.key, shipper.stats = key, {"tombstones": 0}
    try:
        return shipper._mask_chunk(chunk, start)
    except RecursionError:
        return deep_call(shipper._mask_chunk, chunk, start)


def tombstone_offset(line: str):
    try:
        value = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if isinstance(value, dict) and value.get("type") == TOMBSTONE and isinstance(value.get("line_offset"), int):
        return value["line_offset"]
    return None


def body_of(request) -> bytes:
    body = request["body"]
    return body() if callable(body) else body


def request_key(request):
    if "key" in request:
        return tuple(request["key"])
    if request["path"].endswith("/ingest"):
        value = json.loads(body_of(request))
        return ("ingest", value["file"]["jsonl_path"], value["segment"]["offset"])
    return ("other", request["method"], request["path"], sha(body_of(request)))


def non_utf8(path: str) -> bool:
    try:
        path.encode("utf-8")
        return False
    except UnicodeEncodeError:
        return True


def ingest_stats(stdout: bytes):
    text = stdout.decode("utf-8", "replace").strip()
    if not text.startswith("ccs ingest: "):
        return None
    try:
        return json.loads(text[len("ccs ingest: "):])
    except ValueError:
        return None


class Result:
    def __init__(self):
        self.unexplained = []
        self.classified = collections.Counter()
        self.compared = collections.Counter()
        self.extra_tombstones = 0
        self.d2_offsets = collections.Counter()
        self.d5_paths = set()

    def bad(self, kind, **facts):
        self.unexplained.append(dict(kind=kind, **facts))

    def report(self) -> dict:
        return {"unexplained_total": len(self.unexplained), "unexplained": self.unexplained[:50],
                "classified": dict(self.classified), "compared": dict(self.compared)}


def compare_segment(p: dict, r: dict, file_bytes, key: bytes, result: Result, digest: str) -> None:
    """A differing /ingest body: every differing line must be Rust's contract tombstone for that line."""
    def strip(body):
        out = dict(body)
        out["segment"] = {k: v for k, v in body["segment"].items() if k not in ("lines", "sha256")}
        return out
    if strip(p) != strip(r):
        result.bad("ingest-fields", key=digest)
        return
    for side, body in (("python", p), ("rust", r)):
        seg = body["segment"]
        if seg["sha256"] != sha("\n".join(seg["lines"]) + "\n"):
            result.bad("segment-digest", key=digest, side=side)
    seg = r["segment"]
    plines, rlines = p["segment"]["lines"], seg["lines"]
    if len(plines) != len(rlines):
        result.bad("line-count", key=digest, python=len(plines), rust=len(rlines))
        return
    data = file_bytes(r["file"]["jsonl_path"])
    chunk = data[seg["offset"]:seg["end_offset"]] if data is not None else b""
    if not chunk.endswith(b"\n"):
        result.bad("segment-source", key=digest)
        return
    expected, offsets = frozen_mask_chunk(chunk, seg["offset"], key)
    if expected != plines or len(offsets) != len(rlines):
        # The Python run is not what the frozen client produces for these bytes.
        result.bad("python-not-frozen-client", key=digest)
        return
    for index, (lp, lr) in enumerate(zip(plines, rlines)):
        if lp == lr:
            continue
        offset = offsets[index]
        start = offset - seg["offset"]
        raw = chunk[start:chunk.index(b"\n", start)]
        line_label = classify_line(raw, offset, lr) if tombstone_offset(lr) == offset else None
        if line_label is None or tombstone_offset(lp) is not None:
            result.bad("line", key=digest, index=index)
            continue
        result.classified[line_label] += 1
        result.extra_tombstones += 1
        if line_label.startswith("D2"):
            result.d2_offsets[offset] += 1


def state_view(state):
    """(format_ok, text) from ingest.normalized_state, or (True, None) for no file."""
    if state is None or isinstance(state, str):
        return True, state
    return state["format_ok"], state["text"]


def compare_ingest(py: dict, rs: dict, file_bytes, key: bytes) -> Result:
    """Compare two captured `ccs ingest` runs over identical input, state and HMAC key."""
    result = Result()
    if py["exit"] != rs["exit"]:
        result.bad("exit", python=py["exit"], rust=rs["exit"])
    groups = {}
    for side, run in (("python", py), ("rust", rs)):
        for request in run["requests"]:
            groups.setdefault(request_key(request), {"python": [], "rust": []})[side].append(request)
    for k in sorted(groups, key=repr):
        a, b = groups[k]["python"], groups[k]["rust"]
        digest = sha(repr(k))[:16]
        if len(a) != len(b):
            if k[0] == "ingest" and not b and non_utf8(k[1]):
                result.classified["D5"] += len(a)
                result.d5_paths.add(k[1])
                continue
            result.bad("request-count", key=digest, python=len(a), rust=len(b))
            continue
        for x, y in zip(a, b):
            result.compared["requests"] += 1
            if (x["method"], x["path"], x.get("headers")) != (y["method"], y["path"], y.get("headers")):
                result.bad("request-header", key=digest)
                continue
            bx, by = body_of(x), body_of(y)
            result.compared["body_bytes"] += len(by)
            if k[0] == "ingest":
                result.compared["ingest_requests"] += 1
                result.compared["lines"] += y.get("lines", 0)
            if bx == by:
                continue
            if k[0] != "ingest":
                result.bad("request-body", key=digest)
                continue
            compare_segment(json.loads(bx), json.loads(by), file_bytes, key, result, digest)
    if py["stdout"] != rs["stdout"]:
        ps, rss = ingest_stats(py["stdout"]), ingest_stats(rs["stdout"])
        if ps is None or rss is None:
            result.bad("stdout")
        else:
            adjusted = dict(ps, tombstones=ps.get("tombstones", 0) + result.extra_tombstones)
            if adjusted != rss:
                result.bad("stdout-stats", fields=sorted(label(f) for f in set(adjusted) | set(rss)
                                                         if adjusted.get(f) != rss.get(f)))
    (pok, ptext), (rok, rtext) = state_view(py["state"]), state_view(rs["state"])
    if not pok or not rok:
        result.bad("state-format", python=pok, rust=rok)
    if ptext != rtext:
        result.bad("state")
    pw, rw = collections.Counter(py["warnings"]), collections.Counter(rs["warnings"])
    extra_rust, extra_python = rw - pw, pw - rw
    allowed = collections.Counter(result.d2_offsets)
    for message, count in extra_rust.items():
        m = SURROGATE_WARN.match(message)
        if m and allowed[int(m.group(1))] >= count:
            allowed[int(m.group(1))] -= count
            result.classified["D2-warning"] += count
        elif message == NON_UTF8_WARN and count == len(result.d5_paths):
            result.classified["D5-warning"] += count
        else:
            result.bad("warning-rust-only", digest=sha(message)[:16], count=count)
    for message, count in extra_python.items():
        result.bad("warning-python-only", digest=sha(message)[:16], count=count)
    return result
