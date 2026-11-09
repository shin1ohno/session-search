#!/usr/bin/env python3
"""Real-corpus controls for the release cross-check; no production switches."""
import copy
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_conformance as gate

server = Path(__file__).resolve().parents[1] / "vendor/memory-mcp"
runner, sr, header, vectors = gate.load(server, server / "conformance/session_redact_r1.jsonl")
passes = [v for v in vectors if v["id"].split("/", 1)[0] == "pass-limit" and v["op"] == "redact_text"]
outputs = [(v, gate.reference(runner, sr, header, v)) for v in passes]
positive = next((v, out) for v, out in outputs if gate.detection(sr, v["op"], out, out)[0])
different_count = next((v, out) for v, out in outputs
                       if gate.detection(sr, v["op"], out, out)[0] and
                       gate.detection(sr, v["op"], out, out)[1] != gate.detection(sr, positive[0]["op"], positive[1], positive[1])[1])
normal = next(v for v in vectors if v["op"] == "redact_text" and v["id"].split("/", 1)[0] != "pass-limit")
normal_out = gate.reference(runner, sr, header, normal)

def reject(name, fn, reason):
    try:
        fn()
    except ValueError as exc:
        assert reason in str(exc), (name, str(exc))
        print("PASS negative %s: rejected (%s)" % (name, exc))
    else:
        raise AssertionError(name + " accepted")

gate.check_rows(runner, sr, header, passes, [{"id": v["id"], "result": out} for v, out in outputs])
reject("non-pass-limit detection", lambda: gate.check_detection(sr, normal, positive[1], normal_out), "non-pass-limit detection")
reject("pass-limit count changed", lambda: gate.check_detection(sr, positive[0], different_count[1], positive[1]), "kind/count mismatch")
missing = copy.deepcopy(positive[1]); missing["output"] = "plain"
reject("pass-limit missing detection", lambda: gate.check_detection(sr, positive[0], missing, positive[1]), "kind/count mismatch")
# Derive a different detection kind from the corpus's own real input.
for v in vectors:
    if v["op"] == "redact_text" and v["id"].split("/", 1)[0] != "pass-limit":
        raw = runner.expand(v)["input"]
        if isinstance(raw, str) and sr.detect_text(raw) and sr.detect_text(raw) != sr.detect_text(positive[1]["output"]):
            changed = copy.deepcopy(positive[1]); changed["output"] = raw
            break
else:
    raise AssertionError("no different-kind control in corpus")
reject("pass-limit kind changed", lambda: gate.check_detection(sr, positive[0], changed, positive[1]), "kind/count mismatch")
rows = [{"id": v["id"], "result": out} for v, out in outputs]
reject("missing emit", lambda: gate.check_rows(runner, sr, header, passes, rows[:-1]), "missing or extra")
reject("duplicate emit", lambda: gate.check_rows(runner, sr, header, passes, [rows[0]] + rows), "emit id")
print("PASS all cross-check negative controls")
