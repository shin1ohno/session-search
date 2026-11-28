#!/usr/bin/env python3
"""Per-line comparison of the Rust redactor route against the frozen Python client.

Every complete line of every transcript in a snapshot HOME goes through
`ccs _conformance redact --requests` (line mode, fixed test key) and is
compared with tests/conformance/line_oracle.py, which applies the approved
D2/D3 contract. Rust's masked output is then run through the server
detector. Only counts, labels and digests are reported.
"""
from __future__ import annotations

import argparse
import collections
import json
import multiprocessing
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import environment, require_snapshot, sha, write_report  # noqa: E402
from compare import contract, label, line_oracle  # noqa: E402

BATCH_LINES = 4000
BATCH_BYTES = 16 << 20


def transcripts(home: Path) -> list:
    found = []
    for root in (home / ".claude/projects", home / ".codex/sessions"):
        for dirpath, dirnames, names in os.walk(root, followlinks=False):
            for name in names:
                p = Path(dirpath) / name
                if name.endswith(".jsonl") and not p.is_symlink() and p.is_file():
                    found.append(str(p))
    return sorted(found)


def complete_lines(data: bytes):
    """(offset, raw) for every newline-terminated line; ingest never ships a partial tail."""
    start = 0
    while True:
        end = data.find(b"\n", start)
        if end < 0:
            return
        yield start, data[start:end]
        start = end + 1


def expectation(raw: bytes, offset: int):
    """(expected row or None, contract tags) from the frozen client and the D2/D3 contract.

    None means the frozen client itself cannot process the line (Python's own
    recursion limit); only a D3 tombstone proven by the contract is then accepted.
    """
    lo = line_oracle()
    value = {"hex": raw.hex(), "offset": offset}
    try:
        py = lo.G.line_result(lo.ORACLE, lo.SR, value, lo.KEY)
    except RecursionError:
        tags, e = contract(raw, offset)
        if not tags:
            return None, []
        return {"out": e["output"], "counts": e["counts"], "route": e["route"]}, tags
    tags, e = contract(raw, offset, py)
    return {"out": e["output"], "counts": e["counts"], "route": e["route"]}, tags


def detections(got: dict) -> list:
    lo = line_oracle()
    if got["route"] == "text":
        return lo.SR.detect_text(got["out"])
    if got["route"] == "record":
        return lo.SR.detect_record(json.loads(got["out"]))
    return []


def judge(raw: bytes, offset: int, got: dict, tally: collections.Counter) -> str | None:
    """None when Rust's row is correct for this line, else a mismatch label."""
    want, tags = expectation(raw, offset)
    tally["route_" + label(got.get("route"))] += 1
    if want is None:
        return "python-recursion-not-d3"
    if tags:
        tally["classified_%s-%s" % (tags[0], json.loads(want["out"])["reason"])] += 1
    if got != want:
        return "route-%s-expected-%s" % (label(got.get("route")), label(want["route"]))
    kinds = detections(got)
    if kinds:
        # Equal outputs mean Python leaves the same residue (the pass-limit contract).
        tally["residual_detection_lines_equal_python"] += 1
        for kind in kinds:
            tally["residual_kind_" + label(kind)] += 1
    return None


def run_batch(binary: str, env: dict, batch: list) -> list:
    req = "".join(json.dumps({"mode": "line", "hex": raw.hex(), "off": off}) + "\n" for off, raw in batch)
    r = subprocess.run([binary, "_conformance", "redact", "--requests"], input=req, env=env,
                       capture_output=True, text=True, check=True)
    rows = [json.loads(x) for x in r.stdout.split("\n") if x]
    if len(rows) != len(batch):
        raise RuntimeError("conformance runner returned %d rows for %d lines" % (len(rows), len(batch)))
    return rows


def check_file(args) -> dict:
    binary, env, path = args
    tally = collections.Counter()
    mismatches = []
    data = Path(path).read_bytes()
    tally["bytes"] += len(data)
    batch, size = [], 0

    def flush():
        for (off, raw), got in zip(batch, run_batch(binary, env, batch)):
            tally["lines"] += 1
            label = judge(raw, off, got, tally)
            if label:
                mismatches.append({"file": sha(path)[:16], "offset": off, "label": label})
    for off, raw in complete_lines(data):
        batch.append((off, raw))
        size += len(raw)
        if len(batch) >= BATCH_LINES or size >= BATCH_BYTES:
            flush()
            batch, size = [], 0
    if batch:
        flush()
    tally["files"] += 1
    return {"tally": tally, "mismatches": mismatches}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, required=True, help="snapshot HOME from snapshot.py")
    p.add_argument("--rust", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) // 2)))
    p.add_argument("--max-residual", type=int, default=0,
                   help="lines where Rust and Python leave the same detector hit (the accepted pass-limit residue)")
    a = p.parse_args(argv)
    home = require_snapshot(a.home)
    env = environment(home)
    started = time.time()
    files = transcripts(home)
    tally = collections.Counter()
    mismatches = []
    with multiprocessing.Pool(a.workers) as pool:
        for result in pool.imap_unordered(check_file, [(str(Path(a.rust).resolve()), env, f) for f in files]):
            tally.update(result["tally"])
            mismatches.extend(result["mismatches"])
    report = {"tool": "lines", "files_found": len(files), "tally": dict(tally),
              "mismatch_total": len(mismatches), "mismatches": sorted(mismatches, key=lambda m: (m["file"], m["offset"]))[:50],
              "elapsed_s": round(time.time() - started, 1)}
    write_report(a.out, report)
    residual = tally["residual_detection_lines_equal_python"]
    print(json.dumps({"lines": tally["lines"], "files": tally["files"], "mismatches": len(mismatches),
                      "residual": residual}))
    if mismatches or tally["lines"] == 0:
        return 1
    # Same residue as Python is not a Rust regression, but it must be looked at.
    return 3 if residual > a.max_residual else 0


if __name__ == "__main__":
    sys.exit(main())
