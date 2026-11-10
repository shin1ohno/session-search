#!/usr/bin/env python3
"""Publication gate. No dry-run, bypass, or expected-failure option exists."""
import argparse
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile

def check_codex_emit(binary, vendor, work):
    """Require one ordered, exact result per validated server-owned vector."""
    from check_conformance import module
    runner = module("ccs_codex_vectors", vendor / "conformance/gen_vectors.py")
    corpus = vendor / "conformance/session_codex_v1.jsonl"
    if runner.check(corpus, "codex"):
        raise ValueError("Codex Python oracle mismatch")
    with corpus.open() as source:
        next(source)
        vectors = [runner.expand(json.loads(line)) for line in source]
    emit = work / "codex-emit.jsonl"
    with corpus.open("rb") as source, emit.open("wb") as output:
        subprocess.run([binary, "_conformance", "codex", "--emit"],
                       stdin=source, stdout=output, check=True)
    with emit.open() as output:
        rows = (json.loads(line) for line in output)
        for vector, row in itertools.zip_longest(vectors, rows):
            if vector is None or row is None:
                raise ValueError("missing or extra Codex emit row")
            if not isinstance(row, dict) or set(row) != {"id", "result"} or row["id"] != vector["id"]:
                raise ValueError("unknown, duplicate or out-of-order Codex emit id")
            if runner.dumps(row["result"]) != runner.dumps(vector["expect"]):
                raise ValueError(vector["id"] + ": Codex output mismatch")
    print("PASS Codex emit: %d complete normalization/index vectors" % len(vectors))


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("commit")
parser.add_argument("target")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
binary = str(args.binary.resolve())
vendor = root / "vendor/memory-mcp"
try:
    info = json.loads(subprocess.check_output([binary, "_buildinfo"], text=True))
    assert info["commit"] == args.commit and info["target"] == args.target, "build identity mismatch"
    assert info["redact_version"] == "r1", "unsupported ruleset"
    for suite, corpus in (("redact", "session_redact_r1.jsonl"), ("codex", "session_codex_v1.jsonl")):
        with (vendor / "conformance" / corpus).open("rb") as stream:
            subprocess.run([binary, "_conformance", suite], stdin=stream, check=True)
    with tempfile.TemporaryDirectory() as work:
        check_codex_emit(binary, vendor, Path(work))
        emit = Path(work) / "emit.jsonl"
        with (vendor / "conformance/session_redact_r1.jsonl").open("rb") as stream, emit.open("wb") as out:
            subprocess.run([binary, "_conformance", "redact", "--emit"], stdin=stream, stdout=out, check=True)
        subprocess.run([sys.executable, "-B", "-I", str(root / "tools/check_conformance.py"),
                        "--server", str(vendor), "--emit", str(emit)], check=True)
except (AssertionError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
    print("FAIL publication gate: " + str(exc), file=sys.stderr)
    sys.exit(1)
print("PASS publication gate")
