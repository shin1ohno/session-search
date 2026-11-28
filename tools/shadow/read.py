#!/usr/bin/env python3
"""Compare the read paths of both implementations on a snapshot HOME.

Offline: `search --offline` and `preview local:<path>` over the frozen copy.
Online (optional): `search`, `preview` and `status` against the real server.
These are read-only requests (POST /search, GET /preview, GET /status and the
token grant); nothing is ingested. They go through a temporary CCS_CONFIG
whose secret_file points at the real file by absolute path, so the secret is
not copied. Queries are recorded only as sha256 digests. `--bench N` times
`search --offline` for the A6 target.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (add_implementation_arguments, environment, implementations,  # noqa: E402
                    require_snapshot, sha, write_report)

QUERIES = ["rust", "error", "docker", "memory", "session", "deploy", "README", "テスト", "zz-shadow-no-hit-7f3c9e"]
NO_HIT = QUERIES[-1]


def private_config(home: Path, source: Path) -> Path:
    value = json.loads(source.read_text())
    real_home = os.path.expanduser("~")
    for holder, field in ((value.get("auth") or {}, "secret_file"), (value, "hmac_key_file")):
        if isinstance(holder.get(field), str):
            path = holder[field]
            path = os.path.expanduser(path) if path.startswith("~") else path
            holder[field] = path if os.path.isabs(path) else os.path.join(real_home, path)
    target = home / ".shadow-read/config.json"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(json.dumps(value))
    os.chmod(target, 0o600)
    return target


def run(command: list, args: list, env: dict, home: Path, timeout: int = 120) -> tuple:
    """(exit, stdout, stderr) with the breaker reset, so one failure cannot shape the next call."""
    (home / ".claude/session-search/breaker.json").unlink(missing_ok=True)
    r = subprocess.run(command + args, env=env, cwd=home, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout)
    return r.returncode, r.stdout, r.stderr


QUIET_SECONDS = 15 * 60
RETRIES = 4
NUMBER = rb"-?[0-9][0-9.eE+-]*"
NOISE = re.compile(rb'"(took_ms|score)":(\s*)' + NUMBER)
SCORE = re.compile(rb'"score":\s*(' + NUMBER + rb")")
STAMP = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)")


def server_noise_removed(result: tuple) -> tuple:
    """Online search with the numbers the server recomputes per call blanked in the raw bytes.

    `took_ms` is the server's own timing and `score` moves as other hosts
    ingest (BM25 corpus statistics). Every other byte, including separators,
    escapes and a non-numeric score, is still compared; where Python's and
    Rust's scores are equal, score_text_mismatch also checks their text.
    """
    code, out, err = result
    return code, NOISE.sub(lambda m: b'"' + m.group(1) + b'":' + m.group(2) + b"#", out), err


def score_text_mismatch(py: tuple, rs: tuple) -> bool:
    for a, b in zip(SCORE.findall(py[1]), SCORE.findall(rs[1])):
        if float(a) == float(b) and a != b:
            return True
    return False


def updated_epoch(text) -> float | None:
    m = STAMP.fullmatch(text) if isinstance(text, str) else None
    if not m:
        return None
    stamp = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=datetime.timezone.utc).timestamp()
    if m.group(2) != "Z":
        sign = -1 if m.group(2)[0] == "-" else 1
        stamp -= sign * (int(m.group(2)[1:3]) * 3600 + int(m.group(2)[4:6]) * 60)
    return stamp


def quiet_keys(stdout: bytes, n: int, now: float) -> list:
    """Session keys whose last update is old enough that a live session cannot change mid-comparison."""
    try:
        value = json.loads(stdout)
    except ValueError:
        return []
    rows = value.get("sessions") if isinstance(value, dict) else None
    keys = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("session_key"), str):
            continue
        stamp = updated_epoch(row.get("updated_at"))
        if stamp is not None and now - stamp >= QUIET_SECONDS:
            keys.append(row["session_key"])
        if len(keys) == n:
            break
    return keys


def snippet_parts(result: tuple):
    """Everything a preview must share regardless of snippet order, or None when it is not a preview.

    The dumps keep key order and int/float types, and the sorted raw bytes
    catch escapes, spacing and number text that parsing would hide.
    """
    try:
        value = json.loads(result[1])
    except ValueError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("snippets"), list):
        return None
    dump = lambda v: json.dumps(v, ensure_ascii=False)  # noqa: E731
    snippets = [dump(s) for s in value.pop("snippets")]
    return result[0], result[2], dump(value), sorted(snippets), sorted(result[1]), tuple(snippets)


def order_verdict(pys: list, rss: list) -> str:
    """server-changed | server-order | different, for an online preview whose first runs differed.

    The server ranks preview snippets with no tie-breaking sort (ai-memory
    memory-mcp/sessions_search.py preview_match_body), so hits with equal scores
    can come back in either order. That excuses a difference only with evidence
    from the reruns: a Rust run byte-identical to a Python run, or Rust runs
    whose snippet order itself varies. A Rust order that never varies and never
    matches Python's is a Rust difference.
    """
    if any(r == p for r in rss for p in pys):
        return "server-changed"
    parts = [snippet_parts(x) for x in pys + rss]
    if parts[0] is None or any(p is None or p[:5] != parts[0][:5] for p in parts):
        return "different"
    if len({p[5] for p in parts[len(pys):]}) < 2:
        return "different"
    return "server-order"


def without_token_line(result: tuple) -> tuple:
    """D8: only Rust prints the token state line in `ccs status`."""
    code, out, err = result
    return code, b"".join(line for line in out.splitlines(True) if not line.startswith(b"token:")), err


def verdict(py1: tuple, rs: tuple, py2: tuple | None = None, normalize=lambda r: r) -> str:
    """equal | server-changed | python-failed | different, for one command line.

    py2 is a second Python run after Rust. A Rust result that matches either
    Python run is equal; it is "server-changed" only when the two Python runs
    themselves differ, which proves the server answered differently in between.
    """
    p1, r = normalize(py1), normalize(rs)
    if p1[0] != 0:
        return "python-failed"
    if r == p1:
        return "equal"
    if py2 is not None:
        p2 = normalize(py2)
        if p2 != p1 and r == p2:
            return "server-changed"
    return "different"


class Tally:
    def __init__(self):
        self.counts = {}
        self.differences = []

    def add(self, mode: str, outcome: str, case: str, hits: int | None = None):
        c = self.counts.setdefault(mode, {"compared": 0, "equal": 0, "server_changed": 0, "server_order": 0,
                                          "with_hits": 0})
        c["compared"] += 1
        c["equal"] += int(outcome == "equal")
        c["server_changed"] += int(outcome == "server-changed")
        c["server_order"] += int(outcome == "server-order")
        c["with_hits"] += int(outcome == "equal" and bool(hits))
        if outcome not in ("equal", "server-changed", "server-order"):
            self.differences.append({"mode": mode, "outcome": outcome, "case": sha(case)[:16]})

    def gate(self, modes) -> list:
        """Positive controls: every enabled mode proved at least one output equal, and searches proved rows."""
        problems = []
        for mode in modes:
            c = self.counts.get(mode, {"compared": 0, "equal": 0, "with_hits": 0})
            if c["compared"] == 0:
                problems.append(mode + "-compared-nothing")
            elif c["equal"] == 0:
                problems.append(mode + "-equal-nothing")
            if mode.startswith("search") and c["with_hits"] == 0:
                problems.append(mode + "-no-hits")
        return problems


def hits(stdout: bytes) -> int:
    try:
        return len(json.loads(stdout)["sessions"])
    except (ValueError, KeyError, TypeError):
        return 0


def session_keys(stdout: bytes, n: int) -> list:
    try:
        return [s["session_key"] for s in json.loads(stdout)["sessions"][:n]]
    except (ValueError, KeyError, TypeError):
        return []


def bench(command, env, home, query, n):
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        run(command, ["search", query, "--offline"], env, home)
        samples.append((time.perf_counter() - start) * 1000)
    return {"runs": n, "p50_ms": round(statistics.median(samples), 1), "max_ms": round(max(samples), 1)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, required=True, help="snapshot HOME from snapshot.py")
    p.add_argument("--config-source", type=Path, default=Path("~/.config/session-search/config.json").expanduser())
    p.add_argument("--online", action="store_true", help="also compare against the real server (read-only requests)")
    p.add_argument("--bench", type=int, default=0, help="time search --offline N times per implementation")
    p.add_argument("--out", type=Path, required=True)
    add_implementation_arguments(p)
    a = p.parse_args(argv)
    home = require_snapshot(a.home)
    config = private_config(home, a.config_source)
    env = environment(home, config)
    impls = implementations(a)
    py, rs = impls["python"], impls["rust"]
    tally = Tally()
    no_hit_ok = True
    for q in QUERIES:
        args = ["search", q, "--offline"]
        py1, r = run(py, args, env, home), run(rs, args, env, home)
        tally.add("search-offline", verdict(py1, r), "offline:" + q, hits(py1[1]))
        if q == NO_HIT:
            no_hit_ok = py1[0] == 0 and hits(py1[1]) == 0
        for key in session_keys(py1[1], 3):
            args = ["preview", key, q]
            tally.add("preview-local", verdict(run(py, args, env, home), run(rs, args, env, home)),
                      "preview:" + key + q)
    modes = ["search-offline", "preview-local"]
    if a.online:
        modes += ["search-online", "preview-online", "status"]
        for q in QUERIES:
            args = ["search", q]
            py1, r, py2 = run(py, args, env, home), run(rs, args, env, home), run(py, args, env, home)
            outcome = verdict(py1, r, py2, normalize=server_noise_removed)
            if outcome == "equal" and score_text_mismatch(py1, r):
                outcome = "score-format"
            tally.add("search-online", outcome, "online:" + q, hits(py1[1]))
            for key in quiet_keys(py1[1], 2, time.time()):
                args = ["preview", key, q]
                p1, r, p2 = run(py, args, env, home), run(rs, args, env, home), run(py, args, env, home)
                outcome = verdict(p1, r, p2)
                if outcome == "different":
                    pys, rss = [p1, p2], [r]
                    for _ in range(RETRIES):
                        rss.append(run(rs, args, env, home))
                        pys.append(run(py, args, env, home))
                    outcome = order_verdict(pys, rss)
                tally.add("preview-online", outcome, "preview-online:" + key + q)
        outcome = verdict(run(py, ["status"], env, home), run(rs, ["status"], env, home),
                          run(py, ["status"], env, home), normalize=without_token_line)
        tally.add("status", outcome, "status")
    problems = tally.gate(modes) + ([] if no_hit_ok else ["no-hit-query-returned-rows"])
    report = {"tool": "read", "online": a.online, "queries": len(QUERIES), "counts": tally.counts,
              "difference_total": len(tally.differences), "differences": tally.differences[:50],
              "gate_problems": problems}
    if a.bench:
        report["bench_search_offline"] = {name: bench(cmd, env, home, "rust", a.bench) for name, cmd in impls.items()}
    write_report(a.out, report)
    print(json.dumps({"counts": tally.counts, "differences": len(tally.differences), "gate_problems": problems}))
    return 0 if not tally.differences and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
