#!/usr/bin/env python3
"""Publication gate. No dry-run, bypass, or expected-failure option exists."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

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
        emit = Path(work) / "emit.jsonl"
        with (vendor / "conformance/session_redact_r1.jsonl").open("rb") as stream, emit.open("wb") as out:
            subprocess.run([binary, "_conformance", "redact", "--emit"], stdin=stream, stdout=out, check=True)
        subprocess.run([sys.executable, "-B", "-I", str(root / "tools/check_conformance.py"),
                        "--server", str(vendor), "--emit", str(emit)], check=True)
except (AssertionError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
    print("FAIL publication gate: " + str(exc), file=sys.stderr)
    sys.exit(1)
print("PASS publication gate")
