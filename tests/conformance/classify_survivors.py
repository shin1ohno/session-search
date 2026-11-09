#!/usr/bin/env python3
"""Decide, for each mutant that survived the gate, whether it is equivalent; never by a hand-written row.

A survivor is equivalent only if a predicate computed from the rule's parse tree holds for that mutant's
own node and kind, AND a constructed-input hunt built to break the predicate finds no difference.
Anything else is "unresolved", which fails a release. The reason each predicate implies identical
reported spans is in the PREDICATES table. Writes survivors-classified.json.

usage: classify_survivors.py session_redact.py binary
"""
import json
import os
import random
import re
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sr_path, binary, artifact_dir = sys.argv[1:4]
sys.path.insert(0, HERE)
sys.argv = ["structgen.py", sr_path, binary, os.path.join(artifact_dir, "mutants.json"), os.path.join(artifact_dir, "classify"), "--no-mutants"]
src = open(os.path.join(HERE, "structgen.py"), encoding="utf-8").read()
exec(compile(src.split("t0 = time.time()\nnames = list(G.TREES)")[0], "structgen-helpers", "exec"))

PREDICATES = {
    "fixed-count": "lo == hi: greedy and lazy iterate the same number of times",
    "full-match": "the rule is only used through fullmatch and has no groups: greedy and lazy accept the same language",
    "end-anchored": "the repeat is followed only by an end-of-string anchor and its body is one character wide: only one count can reach the end",
    "disjoint-continuation": "the body is non-nullable and shares no first character with what follows: the text fixes the count",
    "run-determined": "every element up to a non-nullable delimiter draws from a set U and the delimiter is outside U: the delimiter is the first non-U character, so every parse ends there; no capture group lies in between",
    "subsumed-optional": "the optional group's characters, including any a mutant adds, are inside the unbounded class that follows it: the span is the whole class run with or without the group",
}
data = json.load(open(os.path.join(artifact_dir, "gate-mutants.json")))
survivors = data["summary"]["survivors_of_structure_inputs"]
mutants = {m["mutant"]: m for m in json.load(open(os.path.join(artifact_dir, "mutants.json")))["mutants"]}


def resolve(name, path_text):
    tree, icase, _ = G.TREES[name]
    seq, chain, parent = tree, [], None
    node = None
    for idx, alt in re.findall(r"\[(\d+)\]|\.a(\d+)", path_text[len(name):]):
        if alt:
            seq = node[1][1][int(alt)]
            continue
        i = int(idx)
        node = seq[i]
        chain.append((seq, i, icase, parent))
        op, av = node
        parent = None
        if op is C.SUBPATTERN:
            icase = (icase or bool(av[1] & G.re.I)) and not (av[2] & G.re.I)
            seq = av[3]
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            parent = node
            seq = av[2]
    return node, icase, chain


def continuation_first(chain):
    out = set()
    for seq, i, ic, parent in reversed(chain):
        s, nullable = G.firsts(seq[i + 1:], ic)
        out |= s
        if not nullable:
            return out
        if parent is not None:
            s2, _ = G.firsts(parent[1][2], ic)
            out |= s2
    return None


def all_chars(seq, ic):
    out = set()
    for op, av in seq:
        if op in CHAR:
            out |= set(G.node_chars(op, av, ic))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            out |= all_chars(av[2], ic)
        elif op is C.BRANCH:
            for a in av[1]:
                out |= all_chars(a, ic)
        elif op is C.SUBPATTERN:
            out |= all_chars(av[3], (ic or bool(av[1] & G.re.I)) and not (av[2] & G.re.I))
    return out


def has_group(seq):
    for op, av in seq:
        if op is C.SUBPATTERN and (av[0] is not None or has_group(av[3])):
            return True
        if op in (C.MAX_REPEAT, C.MIN_REPEAT) and has_group(av[2]):
            return True
        if op is C.BRANCH and any(has_group(a) for a in av[1]):
            return True
    return False


def is_repeat(n):
    return n[0] in (C.MAX_REPEAT, C.MIN_REPEAT)


def run_determined(node, ic, chain):
    seq, i, sic, _ = chain[-1]
    if has_group(node[1][2]):
        return False
    u = all_chars(node[1][2], sic)
    for n in seq[i + 1:]:
        if n[0] is C.SUBPATTERN and n[1][0] is not None:
            return False
        s = all_chars([n], sic)
        if not G.firsts([n], sic)[1] and s and not (s & u):
            return True
        if has_group([n]):
            return False
        u |= s
    return False


def next_absent(chars):
    have = set(chars)
    for c in chars:
        n = ord(c) + 1
        if n < 0x110000 and not 0xD800 <= n <= 0xDFFF and chr(n) not in have:
            return chr(n)
    return None


def subsumed_optional(name, path_text, kind):
    node, ic, chain = resolve(name, path_text)
    added = None
    if kind == "add-next":
        if len(chain) < 2:
            return False
        added = next_absent(G.node_chars(node[0], node[1], ic))
        outer_seq, outer_i, outer_ic, _ = chain[-2]
        node, ic = outer_seq[outer_i], outer_ic
        chain = chain[:-1]
    if not is_repeat(node) or node[1][0] != 0:
        return False
    seq, i, sic, _ = chain[-1]
    if i + 1 >= len(seq) or not is_repeat(seq[i + 1]) or seq[i + 1][1][1] is not C.MAXREPEAT:
        return False
    if i + 2 != len(seq):
        return False
    cls = all_chars(seq[i + 1][1][2], sic)
    return all_chars(node[1][2], sic) <= cls and (added is None or added in cls)


def classify(mutant):
    parts = mutant.split()
    name, path_text, kind = parts[0], parts[1], parts[-1]
    if kind in ("add-next", "hi+1", "hi-1", "swap-greed") and subsumed_optional(name, path_text, kind):
        return "subsumed-optional"
    if kind != "swap-greed":
        return "unresolved"
    node, ic, chain = resolve(name, path_text)
    if not is_repeat(node):
        return "unresolved"
    if G.TREES[name][2] and not has_group(G.TREES[name][0]):
        return "full-match"
    if node[1][0] == node[1][1]:
        return "fixed-count"
    body, nullable = G.firsts(node[1][2], ic)
    seq, i, sic, _ = chain[-1]
    rest = seq[i + 1:]
    if len(chain) == 1 and len(rest) == 1 and rest[0][0] is C.AT and rest[0][1] is C.AT_END_STRING and len(node[1][2]) == 1:
        return "end-anchored"
    if len(chain) > 1 and len(rest) == 1 and rest[0][0] is C.AT and rest[0][1] is C.AT_END_STRING and len(node[1][2]) == 1:
        return "end-anchored"
    cont = continuation_first(chain)
    if not nullable and cont is not None and not (body & cont):
        return "disjoint-continuation"
    if run_determined(node, ic, chain):
        return "run-determined"
    return "unresolved"


# Constructed inputs aimed at breaking each predicate, built from the rule's own structured strings.
HUNT = 60000
hrnd = random.Random(20261112)
SPLICE = ["\\", "\n", '"', "'", "]", "-", "_", ".", ":", "=", " ", "\t", "é", "ſ", "K", "\x85", " ", "\\\n", '\\"', "]\\\n"]


def constructed(name):
    tree, icase, _ = G.TREES[name]
    st, single, _, _, plain_end = structured_inputs(name)
    base = st[:plain_end]
    out = list(st[:min(len(st), 15000)])
    decisions = []
    collect(tree, icase, decisions)
    alphabet = list(dict.fromkeys(c for _, choices, _x in decisions for c in choices if isinstance(c, str)))
    for _ in range(HUNT):
        s = hrnd.choice(base)
        k = hrnd.random()
        if not s:
            continue
        p = hrnd.randrange(len(s) + 1)
        if k < 0.2:
            out.append(s[:p] + s)
        elif k < 0.4:
            out.append(s + s[p:])
        elif k < 0.6:
            out.append(s[:p] + hrnd.choice(SPLICE) + s[p:])
        elif k < 0.8:
            out.append(s[:p] + hrnd.choice(alphabet) * hrnd.choice([1, 2, 39, 40, 41, 80, 81]) + s[p:])
        else:
            q = hrnd.randrange(len(s) + 1)
            out.append(s[:min(p, q)] + hrnd.choice(base)[:hrnd.randint(0, 80)] + s[max(p, q):])
    if name == "openai-key":
        for k in range(10, 30):
            for head in ("sk-", "sk-proj-", "sk-proq-", "sk-proj-proj-", "sk-prpj-", "sk-qroj-", "sk-prok-", "sk-proj."):
                out += [head + "a" * k, head + "-" * k, "x " + head + "a" * k + " y"]
    if name in ("cfg-kv", "cfg-json", "private-key", "cfg-key-full"):
        for k in (0, 1, 38, 39, 40, 41, 42, 79, 80, 81, 82):
            run = "a" * k
            for kw in ("secret", "token", "password", "passwd", "api_key", "apikey", "api-key", "credential", "private", "ſecret", "toKen"):
                for tail in ('="abcdefghij"', ": abcdefghij", '":"abcdefghij"', '"abc', ""):
                    out += [run + kw + run + kw + tail, kw + run + tail, '"' + run + kw + run + tail, run + kw + "x" * k + kw + tail]
        for k in (0, 1, 39, 40, 41):
            out += ["-----BEGIN " + "A" * k + "PRIVATE KEY PRIVATE KEY-----x-----END PRIVATE KEY-----",
                    "-----BEGIN PRIVATE KEY" + " BLOCK" * (k % 3) + "-----\n" + "-----END " + "B " * k + "PRIVATE KEY-----"]
    return list(dict.fromkeys(out))


RX_SPANS = {}
cache = {}


def hunt_sets(name):
    if name not in cache:
        strs = constructed(name)
        sreq = [{"mode": "spans", "rule": name, "input": s} for s in strs]
        treq = [{"mode": "text", "input": s} for s in strs]
        cache[name] = (compile_set_(sreq, [py_spans(r) for r in sreq]), compile_set_(treq, [py(r) for r in treq]), len(strs))
    return cache[name]


def compile_set_(reqs, exp):
    return encode(reqs), reqs, [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in exp]


def first_diff_(cs, env):
    return first_diff(cs, env)

t0 = time.time()
tmpd = tempfile.mkdtemp(prefix="hunt.", dir=artifact_dir)
items, counts = [], {}
hunted_total = 0
for m in survivors:
    cls = classify(m)
    name = m.split()[0]
    sets = hunt_sets(name)
    index = list(mutants).index(m)
    env = {"CCS_TEST_MUTANT": str(index), "CCS_MUTANT_BINARY": os.environ["CCS_MUTANT_BINARY"]}
    broken = first_diff_(sets[0], env) or first_diff_(sets[1], env)
    hunted_total += sets[2]
    status = cls if broken == 0 else "broken-by-hunt"
    counts[status] = counts.get(status, 0) + 1
    items.append({"mutant": m, "class": status, "predicate": cls, "constructed_inputs": sets[2], "hunt_result": "no difference" if broken == 0 else "difference found"})
    print(m, status, flush=True)
os.rmdir(tmpd)
unresolved = counts.get("unresolved", 0) + counts.get("broken-by-hunt", 0)
equivalent = len(survivors) - unresolved
out = {"survivors": len(survivors), "equivalent": equivalent, "unresolved": unresolved, "counts": counts, "predicates": PREDICATES, "constructed_inputs_total": hunted_total, "seconds": round(time.time() - t0, 1), "items": items}
json.dump(out, open(os.path.join(artifact_dir, "survivors-classified.json"), "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in out.items() if k not in ("items", "predicates")}, ensure_ascii=False))

assert unresolved == 0, "unclassified or non-equivalent survivor"
