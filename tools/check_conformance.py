#!/usr/bin/env python3
"""Check release emit output against the server oracle (ADR 0015, check 5).

Emit protocol: one {"id": ..., "result": ...} JSON line for each redact_text,
redact_record or mask_line vector, in corpus order. Other ops emit no row.
Diagnostics contain IDs and reasons, never input or output content.
"""
import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sys

MASK_OPS = {"redact_text", "redact_record", "mask_line"}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def load(server, corpus):
    runner = module("ccs_vectors", server / "conformance/gen_vectors.py")
    sr = module("ccs_oracle", server / "session_redact.py")
    raw = corpus.read_bytes()
    head, body = raw.split(b"\n", 1)
    header = json.loads(head)
    if header["format"] != "ccs-redact-conformance/1" or header["source_blob"] != runner.blob(server / "session_redact.py"):
        raise ValueError("source_blob mismatch")
    lines = body.splitlines()
    if header["min_vectors"] < 8000 or len(lines) < header["min_vectors"] or len(lines) != header["vectors"]:
        raise ValueError("vector count mismatch")
    if hashlib.sha256(body).hexdigest() != header["sha256_of_vectors"]:
        raise ValueError("corpus digest mismatch")
    if runner.blob_bytes(header["client_source"].encode()) != header["client_source_blob"]:
        raise ValueError("frozen client source mismatch")
    runner.LINE_ORACLE = runner.line_oracle(header["client_source"])
    vectors = [json.loads(line) for line in lines]
    ids = [v["id"] for v in vectors]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate corpus id")
    if any(v["op"] not in MASK_OPS | {"detect_text", "detect_record"} for v in vectors):
        raise ValueError("unknown corpus op")
    return runner, sr, header, vectors


def reference(runner, sr, header, vector):
    v = runner.expand(vector)
    key = bytes.fromhex(v.get("hmac_key_hex", header["hmac_key_hex"]))
    got = runner.evaluate(sr, None, v["op"], v["input"], key, v.get("kwargs"))
    if runner.dumps(got) != runner.dumps(v["expect"]):
        raise ValueError(v["id"] + ": Python oracle mismatch")
    if v["op"] == "mask_line":
        got = runner.rust_line_contract(runner.LINE_ORACLE, v["input"], got)[2]
        if runner.dumps(got) != runner.dumps(v["rust_expect"]):
            raise ValueError(v["id"] + ": bounded line contract mismatch")
    return got


def detection(sr, op, result, expected):
    content = result["output"]
    if op == "mask_line":
        if result["route"] != expected["route"]:
            raise ValueError("line route mismatch")
        if expected["route"] == "skip":
            if content is not None:
                raise ValueError("skip output is not null")
            return [], {}
        op = "redact_text" if expected["route"] == "text" else "redact_record"
        if op == "redact_record":
            content = json.loads(content)
    detector = sr.detect_text if op == "redact_text" else sr.detect_record
    redactor = sr.redact_text if op == "redact_text" else sr.redact_record
    kinds = detector(content)
    counts = redactor(content, sr._DETECT_KEY)[1]
    if kinds != sorted(counts):
        raise ValueError("detector/count oracle disagreement")
    return kinds, counts


def check_detection(sr, vector, result, expected):
    actual = detection(sr, vector["op"], result, expected)
    if vector["id"].split("/", 1)[0] == "pass-limit":
        if actual != detection(sr, vector["op"], expected, expected):
            raise ValueError(vector["id"] + ": pass-limit detection kind/count mismatch")
    elif actual != ([], {}):
        raise ValueError(vector["id"] + ": non-pass-limit detection")


def check_rows(runner, sr, header, vectors, rows):
    count = 0
    for vector, row in itertools.zip_longest((v for v in vectors if v["op"] in MASK_OPS), rows):
        if vector is None or row is None:
            raise ValueError("missing or extra emit row")
        if set(row) != {"id", "result"} or row["id"] != vector["id"]:
            raise ValueError("unknown, duplicate or out-of-order emit id")
        expected = reference(runner, sr, header, vector)
        check_detection(sr, vector, row["result"], expected)
        if runner.dumps(row["result"]) != runner.dumps(expected):
            raise ValueError(vector["id"] + ": output mismatch")
        count += 1
    if not count:
        raise ValueError("empty emit stream")
    print("PASS cross-check: %d complete masking vectors; pass limit 8 reference equality" % count)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--emit", type=Path, required=True)
    args = parser.parse_args()
    runner, sr, header, vectors = load(args.server, args.corpus or args.server / "conformance/session_redact_r1.jsonl")
    with args.emit.open() as stream:
        check_rows(runner, sr, header, vectors, (json.loads(line) for line in stream))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError) as exc:
        print("FAIL cross-check: " + str(exc), file=sys.stderr)
        sys.exit(1)
