#!/usr/bin/env python3
"""Differential test: Rust vs session_redact.py. Prints counts and a few diffs (kinds only)."""
import argparse
import importlib.util
import json
import os
import random
import subprocess
import sys

from regressions import records as regression_records, lines as regression_lines
from line_oracle import expected as line_expected
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('source');parser.add_argument('binary');parser.add_argument('output')
parser.add_argument('count',type=int,nargs='?',default=100000)
parser.add_argument('--seed',type=int,default=20261109)
parser.add_argument('--regressions-only',action='store_true')
args=parser.parse_args()
sr_path,bin_path,out_path=args.source,args.binary,args.output
N_FUZZ=0 if args.regressions_only else args.count
spec = importlib.util.spec_from_file_location("sr", sr_path)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)
KEY = b"test-key-not-a-secret"
A36 = "A" * 36
VEC = {
    "aws": "AKIA" + "Z" * 16, "aws2": "ASIA" + "Q7" * 8, "gh": "ghp_" + A36, "ghs": "ghs_" + A36 + "b",
    "pat": "github_pat_" + "a_" * 31, "ant": "sk-ant-" + "a" * 24, "oai": "sk-proj-" + "b" * 24, "oai2": "sk-" + "c-" * 12,
    "slack": "xoxb-" + "1" * 12, "goog": "AIza" + "C" * 35, "goog2": "AIza" + "C" * 34 + "-", "gl": "glpat-" + "d" * 20,
    "jwt": "eyJ" + "e" * 10 + "." + "f" * 10 + "." + "g" * 10,
    "bearer": "Authorization: Bearer " + "h" * 20, "bearer2": '"authorization" : "bearer ' + "i" * 18 + '"',
    "pk": "-----BEGIN OPENSSH PRIVATE KEY-----\nQUFBQQ==\n-----END OPENSSH PRIVATE KEY-----",
    "pk2": "-----BEGIN RSA PRIVATE KEY BLOCK-----\ntruncated",
    "kv": "DB_PASSWORD=hunter2hunter2", "kv2": "api-key: 'abcdefghij'", "kv3": "my.secret_token =\tvalue1234;",
    "json": '"client_secret": "va\\"lue with space"', "url": "https://alice:wonderland99@example.com/x",
    "url2": "postgres+ssl://u.v:p@ss:w0rd@h/", "ph": "[REDACTED:bearer]", "ph2": "[REDACTED:aws-key:0123abcd]",
    "cred": "CREDENTIAL=${HOME}xxxxxx", "xxx": "password=xXxabcdefgh", "star": "token=***abcdefgh", "lt": "secret: <placeholder>",
}
BOUND = ["", " ", "\n", "\t", "a", "Z", "0", "_", "-", ".", "+", "/", ":", "=", '"', "'", "`", ",", ";", "&", "@", "(", "\\",
         "é", "́", "‍", "‌", "½", "٣", "ı", "İ", "ſ", "K", "\x1c", "\x1f", "\x85", "\xa0", "　",
         " ", " ", "🙂", "中", "²", "‿", "️", "٠", "Ⅰ"]
CASEMUT = [("authorization", "AUTHORIZATION"), ("authorization", "authorızatıon"), ("authorization", "authorİzation"),
           ("Bearer", "BEARER"), ("Bearer", "beareR"), ("PASSWORD", "password"), ("PASSWORD", "PAſſWORD"), ("secret", "ſecret"),
           ("api-key", "api_KEY"), ("api-key", "apiKey"), ("api-key", "apiKey"), ("https", "HTTPS"), ("https", "httpſ")]
reqs = []


def add(mode, value):
    reqs.append({"mode": mode, "input": value})


def text(v):
    add("text", v)
    add("detect", v)


for v in ([] if args.regressions_only else VEC.values()):
    text(v)
    for a in BOUND:
        for b in BOUND:
            text(a + v + b)
    for i in (1, 2, 4, 8):
        text(v[:-i])
        text(v[i:])
    for x, y in CASEMUT:
        if x in v:
            text(v.replace(x, y))
base_n = len(reqs)
rnd = random.Random(args.seed)
frags = list(VEC.values()) + BOUND + ["key", "token", "secret", "pass", "://", "@", ":", "=", "sk-", "eyJ", "AKIA", "AIza", "gh", "xoxb-", "glpat-",
                                      "-----BEGIN ", "PRIVATE KEY-----", "-----END ", "[REDACTED:", "]", "abcdefgh", "ABCDEFGHIJKLMNOP", "1234567890", "\\", '"']
for _ in range(N_FUZZ):
    text("".join(rnd.choice(frags) for _ in range(rnd.randint(1, 14))))
fuzz_n = len(reqs)
# records: dict-key rule, key secrets, collisions, budget order, oversize, depth to 64
recs = [{"password": "hunter2hunter2", "a": 1}, {"PASSWORD": "short"}, {"x-api-key": "abcdefghij", "n": None, "t": True, "f": 1.5},
        {"AKIA" + "Z" * 16: "v"}, {"AKIA" + "Z" * 16: "1", "AKIA" + "Y" * 16: "2"}, {"sk-ant-" + "a" * 24: 1, "[REDACTED:anthropic-key:" + "0" * 8 + "]": 2},
        {"k" * 129 + "secret": "abcdefghij"}, {"token": "  ${X}"}, {"nest": [{"secret": "abcdefghij"}, ["Authorization: Bearer " + "h" * 20]]},
        ["AKIA" + "Z" * 16, {"a": "b"}], "bare string sk-ant-" + "a" * 24, 42, None,
        {"a": "x" * 1_000_001}, {"a": "x" * 1_000_000, "b": "y"},
        {"a": "x" * 1_500_000, "b": ["y" * 900_000, "z" * 900_000, "w" * 900_000, "v" * 900_000, "u" * 900_000]},
        {"k1": "p" * 999_999, "k2": "q" * 999_999, "k3": "r" * 999_999, "k4": "s" * 999_999, "k5": "t" * 999_999, "password": "abcdefghij"}]
d = "leaf sk-ant-" + "a" * 24
for _ in range(63):
    d = [d] if rnd.random() < 0.5 else {"k": d}
recs.append(d)
for _ in range(0 if args.regressions_only else 4000):
    def gen(depth):
        r = rnd.random()
        if depth > 5 or r < 0.45:
            return "".join(rnd.choice(frags) for _ in range(rnd.randint(0, 5)))
        if r < 0.7:
            return [gen(depth + 1) for _ in range(rnd.randint(0, 4))]
        if r < 0.95:
            return {("".join(rnd.choice(frags) for _ in range(rnd.randint(0, 3)))): gen(depth + 1) for _ in range(rnd.randint(0, 4))}
        return rnd.choice([1, 1.5, None, True, False])
    recs.append(gen(0))
named=regression_records()
if args.regressions_only: recs=[]
labels=['generated']*len(reqs)+['record']*len(recs)+[name for name,_ in named]
recs.extend(record for _,record in named)
for r in recs:
    add("record", r)
for name,raw in regression_lines():
    reqs.append({"mode":"line","hex":raw.hex(),"off":1})
    labels.append(name)


def py(req):
    counts = {}
    m = req["mode"]
    if m == "line":
        e=line_expected(bytes.fromhex(req["hex"]),req["off"])
        return {"out":e["output"],"counts":e["counts"],"route":e["route"]}
    if m == "text":
        o, counts = sr.redact_text(req["input"], KEY)
    elif m == "detect":
        o, _ = None, sr.detect_text(req["input"])
        return {"out": None, "counts": sorted(_)}
    else:
        o, counts = sr.redact_record(req["input"], KEY)
    return {"out": o, "counts": counts}


expected = [py(r) for r in reqs]
payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in reqs).encode("utf-8")
env = dict(os.environ)
res = subprocess.run([bin_path, "_conformance", "redact", "--requests"], input=payload, stdout=subprocess.PIPE, env=env, check=True)
got = [json.loads(x) for x in res.stdout.decode("utf-8").split("\n") if x]
assert len(got) == len(reqs), (len(got), len(reqs))
diff = []
for i, (r, e, g) in enumerate(zip(reqs, expected, got)):
    if r["mode"] == "detect":
        g = {"out": None, "counts": sorted(g["counts"])}
    if json.dumps(e, ensure_ascii=False, sort_keys=False) != json.dumps(g, ensure_ascii=False, sort_keys=False) \
            and json.dumps(e, ensure_ascii=False, sort_keys=True) != json.dumps(g, ensure_ascii=False, sort_keys=True):
        diff.append(i)
        if len(diff)<=10: print("differential mismatch:",labels[i],"index",i)
# Key order of the record output must match, not only content.
order = sum(1 for r, e, g in zip(reqs, expected, got)
            if r["mode"] == "record" and json.dumps(e["out"], ensure_ascii=False) != json.dumps(g["out"], ensure_ascii=False))
leak = 0
for i, (r, e, g) in enumerate(zip(reqs, expected, got)):
    if r["mode"] == "text" and isinstance(g["out"], str) and sr.detect_text(g["out"]) != sr.detect_text(e["out"]):
        leak += 1
    if r["mode"] == "record" and sr.detect_record(g["out"]) != sr.detect_record(e["out"]):
        leak += 1
summary = {"cases": len(reqs), "seed": args.seed, "directed_requests": base_n,
           "fuzz_requests": fuzz_n - base_n, "record_requests": sum(r["mode"]=="record" for r in reqs), "line_requests": sum(r["mode"]=="line" for r in reqs), "diffs": len(diff), "record_key_order_diffs": order, "python_detect_hits_on_rust_output": leak}
with open(out_path, "a") as f:
    f.write(json.dumps(summary) + "\n")
print(json.dumps(summary))
assert not diff and not order and not leak, "differential mismatch"
