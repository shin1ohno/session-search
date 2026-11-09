#!/usr/bin/env python3
"""Inputs derived from each pattern's own parse tree, with Python as the oracle, and a mutation check.

Every decision node of a pattern (each repeat bound, each alternative, each class edge and its
neighbours outside the class, each case-fold member) is exercised one at a time and in random
combinations, inside boundary contexts. Then one-change mutants of the Rust patterns are run against
the same inputs and against a corpus-style baseline, to measure what each set can notice.

usage: structgen.py session_redact.py binary mutants.json out-prefix [--no-mutants]
"""
import concurrent.futures
import json
import os
import random
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sr_path, binary, mutants_path, prefix = sys.argv[1:5]
run_mutants = "--no-mutants" not in sys.argv
_argv = sys.argv
tmp_tables = prefix + ".tables.tmp"
sys.argv = ["gen.py", sr_path, tmp_tables]
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(HERE, "../../tools"))
import gen_redact_tables as G  # noqa: E402

sys.argv = _argv
os.remove(tmp_tables)
C = G.C
sr = G.sr
KEY = b"test-key-not-a-secret"
rnd = random.Random(20261111)
CHAR = (C.LITERAL, C.NOT_LITERAL, C.IN, C.ANY)
BOUND = ["", " ", "\n", "\t", "a", "Z", "0", "_", "-", ".", "+", "/", ":", "=", '"', "'", "`", ",", ";", "&", "@", "(", "\\",
         "é", "́", "‍", "‌", "½", "٣", "ı", "İ", "ſ", "K", "\x1c", "\x1f", "\x85", "\xa0", "　",
         " ", " ", "🙂", "中", "²", "‿", "️", "٠", "Ⅰ"]
SHORT = ["", " ", "a", "_", "-", "é", "\x85", " "]
MAX_PER_RULE = 200000


def valid(cp):
    return 0 <= cp < 0x110000 and not 0xD800 <= cp <= 0xDFFF


def char_choices(op, av, icase):
    chars = G.node_chars(op, av, icase)
    have = set(chars)
    rs = G.ranges(chars)
    picked = []
    for a, b in rs[:6] + rs[-6:]:
        picked += [chr(a), chr(b)]
    picked += [c for c in chars if ord(c) > 127][:6] if len(chars) < 200 else []
    outside = []
    for a, b in rs[:8] + rs[-8:]:
        for cp in (a - 1, b + 1):
            if valid(cp) and chr(cp) not in have:
                outside.append(chr(cp))
    return list(dict.fromkeys(picked)) + list(dict.fromkeys(outside))[:8]


_DEFAULT = {}


def default_char(op, av, icase):
    # Some classes have 1.1 million members, and this runs for every node of every render.
    key = (repr(op), repr(av), icase)
    if key not in _DEFAULT:
        chars = G.node_chars(op, av, icase)
        have = set(chars)
        _DEFAULT[key] = next((c for c in "aA0_" if c in have), chars[0])
    return _DEFAULT[key]


def count_choices(lo, hi):
    out = {max(lo - 1, 0), lo, lo + 1}
    if hi is C.MAXREPEAT:
        out |= {lo + 20}
        if lo <= 1:
            out |= {7, 8, 9}
    else:
        out |= {max(hi - 1, 0), hi, hi + 1}
    return sorted(out)


def default_count(lo, hi):
    return max(lo, 12) if hi is C.MAXREPEAT else lo


def collect(seq, icase, out, ctx=()):
    """Each decision carries the overrides that make it reachable: its enclosing alternatives and repeats."""
    for item in seq:
        op, av = item
        if op in CHAR:
            out.append((item, char_choices(op, av, icase), ctx))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            out.append((item, count_choices(av[0], av[1]), ctx))
            inner = ctx if default_count(av[0], av[1]) > 0 else ctx + ((id(item), 1),)
            collect(av[2], icase, out, inner)
        elif op is C.BRANCH:
            out.append((item, list(range(len(av[1]))), ctx))
            for k, a in enumerate(av[1]):
                collect(a, icase, out, ctx + ((id(item), k),))
        elif op is C.SUBPATTERN:
            collect(av[3], (icase or bool(av[1] & G.re.I)) and not (av[2] & G.re.I), out, ctx)


def guard_contexts(tree, icase):
    """Left contexts from a leading lookbehind class: each range edge and its outside neighbours."""
    if not tree or tree[0][0] is not C.ASSERT_NOT:
        return []
    body = list(tree[0][1][1])
    chars = G.node_chars(body[0][0], body[0][1], icase)
    have = set(chars)
    out = []
    for a, b in G.ranges(chars):
        out += [chr(a), chr(b)]
        for cp in (a - 1, b + 1):
            if valid(cp) and chr(cp) not in have:
                out.append(chr(cp))
    return list(dict.fromkeys(out))


def render(seq, icase, ov):
    parts = []
    for item in seq:
        op, av = item
        key = id(item)
        if op in CHAR:
            parts.append(ov[key] if key in ov else default_char(op, av, icase))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            n = ov[key] if key in ov else default_count(av[0], av[1])
            if isinstance(n, tuple):  # ("seq", [override per iteration]): the iterations differ
                for o in n[1]:
                    merged = dict(ov)
                    merged.update(o)
                    parts.append(render(av[2], icase, merged))
            else:
                parts.append(render(av[2], icase, ov) * n)
        elif op is C.BRANCH:
            parts.append(render(av[1][ov.get(key, 0)], icase, ov))
        elif op is C.SUBPATTERN:
            parts.append(render(av[3], (icase or bool(av[1] & G.re.I)) and not (av[2] & G.re.I), ov))
    return "".join(parts)


def repeats_in(seq, icase, ctx, out):
    for item in seq:
        op, av = item
        if op in (C.MAX_REPEAT, C.MIN_REPEAT):
            out.append((item, icase, ctx))
            inner = ctx if default_count(av[0], av[1]) > 0 else ctx + ((id(item), 1),)
            repeats_in(av[2], icase, inner, out)
        elif op is C.BRANCH:
            for k, a in enumerate(av[1]):
                repeats_in(a, icase, ctx + ((id(item), k),), out)
        elif op is C.SUBPATTERN:
            repeats_in(av[3], (icase or bool(av[1] & G.re.I)) and not (av[2] & G.re.I), ctx, out)


MAX_PAIRS_PER_REPEAT = 4096
MAX_ADJACENT_PER_RULE = 15000


def iteration_strings(tree, icase):
    """Two different iterations next to each other, and short runs of different iterations."""
    repeats = []
    repeats_in(tree, icase, (), repeats)
    out = []
    for item, ic, ctx in repeats:
        lo, hi, body = item[1]
        if hi is not C.MAXREPEAT and hi < 2:
            continue
        inner = []
        collect(body, ic, inner)
        variants = [{}]
        for it, choices, c2 in inner:
            for c in choices:
                o = dict(c2)
                o[id(it)] = c
                variants.append(o)
        pairs = [(u, v) for u in variants for v in variants]
        if len(pairs) > MAX_PAIRS_PER_REPEAT:
            pairs = rnd.sample(pairs, MAX_PAIRS_PER_REPEAT)
        unbounded = hi is C.MAXREPEAT
        fills = [(max(lo, 8), 3), (0, 0)] if unbounded else [(max(lo - 2, 0), 0)]

        def emit(seq_ov, f1, f2):
            ov = dict(ctx)
            ov[id(item)] = ("seq", [{}] * f1 + seq_ov + [{}] * f2)
            out.append(render(tree, icase, ov))

        for u, v in pairs:
            for f1, f2 in fills:
                emit([u, v], f1, f2)
        for _ in range(300):
            k = rnd.randint(3, 6) if unbounded or hi >= 6 else 2
            f1, f2 = fills[0]
            emit([rnd.choice(variants) for _ in range(k)], f1, f2)
    return out


def adjacent_strings(tree, icase, decisions):
    """Each decision with the next one, so a character and what follows it vary together."""
    combos = []
    for (i1, c1, x1), (i2, c2, x2) in zip(decisions, decisions[1:]):
        for a in c1:
            for b in c2:
                combos.append((i1, a, x1, i2, b, x2))
    if len(combos) > MAX_ADJACENT_PER_RULE:
        combos = rnd.sample(combos, MAX_ADJACENT_PER_RULE)
    out = []
    for i1, a, x1, i2, b, x2 in combos:
        ov = dict(x1)
        ov.update(x2)
        ov[id(i1)] = a
        ov[id(i2)] = b
        out.append(render(tree, icase, ov))
    return out


def structured_inputs(name):
    tree, icase, _ = G.TREES[name]
    decisions = []
    collect(tree, icase, decisions)
    out = {}
    base = render(tree, icase, {})
    strings = [base]
    for item, choices, ctx in decisions:
        for c in choices:
            ov = dict(ctx)
            ov[id(item)] = c
            strings.append(render(tree, icase, ov))
    strings = list(dict.fromkeys(strings))
    single = len(strings)
    n_choice = sum(len(c) for _, c, _ctx in decisions)
    for _ in range(2000):
        ov = {}
        for item, choices, ctx in decisions:
            if choices and rnd.random() < 0.3:
                ov.update(ctx)
                ov[id(item)] = rnd.choice(choices)
        strings.append(render(tree, icase, ov))
    strings = list(dict.fromkeys(strings))
    plain_end = len(strings)
    strings += iteration_strings(tree, icase) + adjacent_strings(tree, icase, decisions)
    strings = list(dict.fromkeys(strings))
    return strings, single, len(decisions), n_choice, plain_end


def add(out, mode, value):
    key = (mode, json.dumps(value, ensure_ascii=False, sort_keys=False))
    if key not in out:
        out[key] = {"mode": mode, "input": value}


def requests_for(name, strings, single, others, plain_end):
    out = {}
    budget = MAX_PER_RULE
    tree, icase, _ = G.TREES[name]
    guard = guard_contexts(tree, icase)
    for i, s in enumerate(strings):
        if i >= plain_end:
            add(out, "text", s)
            add(out, "record", {"k": s})
            continue
        ctx = [("", "")] + [(a, "") for a in guard]
        if i < single and len(out) < budget * 0.7:
            ctx += [(a, "") for a in BOUND[1:]] + [("", b) for b in BOUND[1:]]
            if i < 25:
                ctx += [(a, b) for a in SHORT[1:] for b in SHORT[1:]]
        else:
            ctx += [(rnd.choice(BOUND), rnd.choice(BOUND)) for _ in range(3)]
        for a, b in ctx:
            add(out, "text", a + s + b)
        add(out, "detect", s)
        if name == "placeholder":
            add(out, "text", s + " " + rnd.choice(others))
            add(out, "text", rnd.choice(others) + s)
        if rnd.random() < 0.3:
            add(out, "text", s + rnd.choice(BOUND) + rnd.choice(others))
            add(out, "text", s + s)
        add(out, "record", {"k": s})
        add(out, "record", {s: "abcdefghij"})
        add(out, "record", [s, {"password": s}])
        if len(out) >= budget and i < plain_end:
            break
    return list(out.values())


def py(req):
    m = req["mode"]
    if m == "text":
        o, c = sr.redact_text(req["input"], KEY)
        return {"out": o, "counts": c}
    if m == "detect":
        return {"out": None, "counts": sr.detect_text(req["input"])}
    o, c = sr.redact_record(req["input"], KEY)
    return {"out": o, "counts": c}


RX = {name: (rx, full) for name, rx, full in G.SOURCES}


def span_reqs(name, reqs):
    seen = {}
    for r in reqs:
        if r["mode"] == "text" and r["input"] not in seen:
            seen[r["input"]] = {"mode": "spans", "rule": name, "input": r["input"]}
    return list(seen.values())


def py_spans(req):
    rx, full = RX[req["rule"]]
    ms = ([] if rx.fullmatch(req["input"]) is None else [rx.fullmatch(req["input"])]) if full else list(rx.finditer(req["input"]))
    return {"out": [[list(m.span(i)) for i in range(rx.groups + 1)] for m in ms], "counts": {}}


def norm(req, g):
    if req["mode"] == "detect":
        return {"out": None, "counts": sorted(g["counts"])}
    return g


def encode(reqs):
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in reqs).encode("utf-8")


def run_raw(payload, env=None):
    e = dict(os.environ)
    e.pop("CCS_MUTANT_BINARY", None)
    e.update(env or {})
    res = subprocess.run([e.pop("CCS_MUTANT_BINARY", binary), "_conformance", "redact", "--requests"], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
    return None if res.returncode != 0 else res.stdout.decode("utf-8").split("\n")


def run(reqs, env=None):
    out = run_raw(encode(reqs), env)
    return None if out is None else [json.loads(x) for x in out if x]


def diffs(reqs, exp, got):
    if got is None or len(got) != len(reqs):
        return -1
    n = 0
    for r, e, g in zip(reqs, exp, got):
        if json.dumps(e, ensure_ascii=False, sort_keys=False) != json.dumps(norm(r, g), ensure_ascii=False, sort_keys=False):
            if json.dumps(e, ensure_ascii=False, sort_keys=True) != json.dumps(norm(r, g), ensure_ascii=False, sort_keys=True):
                n += 1
    return n


def first_diff(cs, env):
    """Stop only after an observed difference; EOF/errors are never detections."""
    import threading
    payload, reqs, want = cs
    e = dict(os.environ)
    e.pop("CCS_MUTANT_BINARY", None)
    e.update(env or {})
    program = e.pop("CCS_MUTANT_BINARY", binary)
    errors = []
    with tempfile.TemporaryFile() as stderr, subprocess.Popen(
            [program, "_conformance", "redact", "--requests"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=stderr, env=e) as process:
        def feed():
            try:
                with process.stdin:
                    process.stdin.write(payload)
            except BrokenPipeError:
                pass  # expected when an observed difference stops the child
            except Exception as exc:
                errors.append(type(exc).__name__)
        sender = threading.Thread(target=feed)
        sender.start()
        result = 0
        try:
            for r, expected in zip(reqs, want):
                line = process.stdout.readline()
                if not line:
                    result = -1
                    break
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict) or set(row) != {"out", "counts"} or not isinstance(row["counts"], dict):
                        result = -1
                        break
                    actual = json.dumps(norm(r, row), ensure_ascii=False, sort_keys=True)
                except (ValueError, KeyError, TypeError):
                    result = -1
                    break
                if actual != expected:
                    result = 1
                    break
            if result == 0 and (process.stdout.read() or process.wait() != 0):
                result = -1
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait()
            sender.join()
        return -1 if errors else result


t0 = time.time()
names = list(G.TREES)
strings = {n: structured_inputs(n) for n in names}
others = [s for n in names if n not in ("placeholder", "anchor", "cfg-key-full") for s in strings[n][0][:3]]
report = {"python": sys.version.split()[0], "rules": {}}
all_reqs = {}
all_exp = {}
span_reqs_all = {}
span_exp_all = {}
for n in names:
    st, single, nd, nc, plain_end = strings[n]
    reqs = requests_for(n, st, single, others, plain_end)
    exp = [py(r) for r in reqs]
    got = run(reqs)
    d = diffs(reqs, exp, got)
    leak = 0
    for r, g in zip(reqs, got):
        if r["mode"] == "text" and sr.detect_text(g["out"]):
            leak += 1
        if r["mode"] == "record" and sr.detect_record(g["out"]):
            leak += 1
    positive = sum(1 for e in exp if e["counts"])
    sreqs = span_reqs(n, reqs)
    sexp = [py_spans(r) for r in sreqs]
    sd = diffs(sreqs, sexp, run(sreqs))
    span_reqs_all[n], span_exp_all[n] = sreqs, sexp
    report["rules"][n] = {"span_requests": len(sreqs), "span_diffs": sd, "python_rule_matches": sum(1 for e in sexp if e["out"]), "decision_nodes": nd, "choices": nc, "distinct_strings": len(st), "requests": len(reqs), "python_masked_or_detected": positive, "diffs": d, "python_detect_hits_on_rust_output": leak}
    all_reqs[n], all_exp[n] = reqs, exp
    print(n, json.dumps(report["rules"][n]), flush=True)
report["total_requests"] = sum(v["requests"] for v in report["rules"].values())
report["total_diffs"] = sum(v["diffs"] for v in report["rules"].values())
report["total_span_requests"] = sum(v["span_requests"] for v in report["rules"].values())
report["total_span_diffs"] = sum(v["span_diffs"] for v in report["rules"].values())
report["total_python_detect_hits_on_rust_output"] = sum(v["python_detect_hits_on_rust_output"] for v in report["rules"].values())
report["seconds"] = round(time.time() - t0, 1)
json.dump(report, open(prefix + "-structgen.json", "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in report.items() if k != "rules"}), flush=True)
assert report["total_diffs"] == 0 and report["total_span_diffs"] == 0
assert report["total_python_detect_hits_on_rust_output"] == 0
assert all(v["decision_nodes"] > 0 for v in report["rules"].values())
if not run_mutants:
    sys.exit(0)

# Corpus-style baseline: the same fragments and boundaries as driver.py, without any knowledge of a pattern's structure.
ns = {}
source = open(os.path.join(HERE, "differential.py"), encoding="utf-8").read()
exec(source[source.index('A36 = '):source.index('CASEMUT = ')], ns)
baseline = []
VEC, BND = ns["VEC"], ns["BOUND"]
for v in VEC.values():
    baseline.append(v)
    for a in BND:
        baseline += [a + v, v + a]
    for i in (1, 2, 4, 8):
        baseline += [v[:-i], v[i:]]
frags = list(VEC.values()) + BND + ["key", "token", "secret", "pass", "://", "@", ":", "=", "sk-", "eyJ", "AKIA", "AIza", "gh", "xoxb-", "glpat-", "-----BEGIN ", "PRIVATE KEY-----", "-----END ", "[REDACTED:", "]", "abcdefgh", "ABCDEFGHIJKLMNOP", "1234567890", "\\", '"']
b_rnd = random.Random(20261109)
for _ in range(20000):
    baseline.append("".join(b_rnd.choice(frags) for _ in range(b_rnd.randint(1, 14))))
base_reqs = [{"mode": "text", "input": s} for s in dict.fromkeys(baseline)]
base_exp = [py(r) for r in base_reqs]
mutants = json.load(open(mutants_path))


def compile_set(reqs, exp):
    """Payload and sorted expected results, built once: a mutant only needs the first difference."""
    return encode(reqs), reqs, [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in exp]


SETS = {n: compile_set(all_reqs[n], all_exp[n]) for n in names}
SPAN_SETS = {n: compile_set(span_reqs_all[n], span_exp_all[n]) for n in names}
BASE_SET = compile_set(base_reqs, base_exp)
print("mutant inputs ready", round(time.time() - t0, 1), flush=True)




ncls = mutants["cls"]
tmpd = tempfile.mkdtemp(prefix="mut.", dir=os.path.dirname(prefix))


done = [0]


def one(args):
    i, m = args
    env = {"CCS_TEST_MUTANT": str(i), "CCS_MUTANT_BINARY": os.environ["CCS_MUTANT_BINARY"]}
    name = m["name"]
    s = first_diff(SPAN_SETS[name], env) or first_diff(SETS[name], env)
    b = first_diff(BASE_SET, env)
    done[0] += 1
    if done[0] % 50 == 0:
        print("mutants done", done[0], round(time.time() - t0, 1), flush=True)
    return {"mutant": m["mutant"], "rule": name, "structgen_diffs": s, "baseline_diffs": b}


with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
    results = list(ex.map(one, enumerate(mutants["mutants"])))
os.rmdir(tmpd)
killed = [r for r in results if r["structgen_diffs"] != 0]
base_killed = [r for r in results if r["baseline_diffs"] != 0]
errors = [r for r in results if r["structgen_diffs"] == -1 or r["baseline_diffs"] == -1]
survivors = [r for r in results if r["structgen_diffs"] == 0]
summary = {"mutants": len(results), "killed_by_structure_inputs": len(killed), "killed_by_baseline_inputs": len(base_killed), "build_or_run_errors": len(errors),
           "survivors_of_structure_inputs": [r["mutant"] for r in survivors], "killed_only_by_structure_inputs": sum(1 for r in results if r["structgen_diffs"] != 0 and r["baseline_diffs"] == 0),
           "killed_only_by_baseline_inputs": [r["mutant"] for r in results if r["structgen_diffs"] == 0 and r["baseline_diffs"] != 0], "baseline_requests": len(base_reqs), "seconds": round(time.time() - t0, 1)}
json.dump({"summary": summary, "results": results}, open(prefix + "-mutants.json", "w"), ensure_ascii=False, indent=1)
print(json.dumps(summary, ensure_ascii=False)[:6000])

assert not errors, "build/run errors are not mutation detections"
