#!/usr/bin/env python3
"""Translate session_redact.py patterns to regex-automata patterns plus guards, from Python's own parser.

Character classes are expanded by asking Python's `re` which code points match, so (?i), \\s and
\\w follow Python's membership. That aligns character sets only; it says nothing about how the
two engines behave on an input, which structgen.py and the release gate test separately.

Refuses (SystemExit) any construct it cannot translate with a stated reason, including a trailing
\\b after a variable repeat whose class has non-word characters: the post-match check is only
correct when no shorter repeat could have satisfied the boundary.

usage: gen_redact_tables.py session_redact.py tables.rs [mutants.json]
"""
import importlib.util
import hashlib
from pathlib import Path
import json
import re
import re._constants as C
import re._parser as P
import sys
import unicodedata
import subprocess

if unicodedata.unidata_version != "15.1.0":
    raise SystemExit("generate with CPython 3.13 / Unicode 15.1.0")

spec = importlib.util.spec_from_file_location("sr", sys.argv[1])
sr = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(sr)
ALL = "".join(chr(i) for i in range(0x110000) if not 0xD800 <= i <= 0xDFFF)


def ranges(chars):
    cps = sorted(ord(c) for c in chars)
    out = []
    for cp in cps:
        if out and out[-1][1] == cp - 1:
            out[-1][1] = cp
        else:
            out.append([cp, cp])
    return out


RUST_CLASS_CACHE = {}
MEMBER_IDS = set()


def rust_class(chars):
    key = id(chars)
    if key in RUST_CLASS_CACHE:
        return RUST_CLASS_CACHE[key]
    result = _rust_class(chars)
    if key in MEMBER_IDS:
        RUST_CLASS_CACHE[key] = result
    return result


def _rust_class(chars):
    rs = ranges(chars)
    if not rs:
        raise SystemExit("empty class")
    if len(rs) == 1 and rs[0][0] == rs[0][1]:
        return r"\x{%X}" % rs[0][0]
    return "[" + "".join((r"\x{%X}" % a if a == b else r"\x{%X}-\x{%X}" % (a, b)) for a, b in rs) + "]"


CACHE = {}


def members(src, icase):
    k = (src, icase)
    if k not in CACHE:
        CACHE[k] = re.compile(("(?i)" if icase else "") + src).findall(ALL)
        MEMBER_IDS.add(id(CACHE[k]))
    return CACHE[k]


CATS = {C.CATEGORY_SPACE: r"\s", C.CATEGORY_NOT_SPACE: r"\S", C.CATEGORY_DIGIT: r"\d",
        C.CATEGORY_NOT_DIGIT: r"\D", C.CATEGORY_WORD: r"\w", C.CATEGORY_NOT_WORD: r"\W"}
WORD_SET = set(re.compile(r"\w").findall(ALL))


def class_src(items):
    neg = ""
    out = []
    for op, av in items:
        if op is C.NEGATE:
            neg = "^"
        elif op is C.LITERAL:
            out.append(re.escape(chr(av)))
        elif op is C.RANGE:
            out.append(re.escape(chr(av[0])) + "-" + re.escape(chr(av[1])))
        elif op is C.CATEGORY:
            out.append(CATS[av])
        else:
            raise SystemExit("class op %r" % (op,))
    return "[" + neg + "".join(out) + "]"


# The parse tree as plain lists, so a mutant can be built by editing one node.
SET = "SET"  # a mutant's explicit character list


def plain(seq):
    out = []
    for op, av in seq:
        if op is C.SUBPATTERN:
            out.append([op, [av[0], av[1], av[2], plain(av[3])]])
        elif op is C.BRANCH:
            out.append([op, [None, [plain(a) for a in av[1]]]])
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            out.append([op, [av[0], av[1], plain(av[2])]])
        elif op in (C.ASSERT, C.ASSERT_NOT):
            out.append([op, [av[0], plain(av[1])]])
        else:
            out.append([op, av])
    return out


def clone(seq):
    out = []
    for op, av in seq:
        if op is C.SUBPATTERN:
            out.append([op, [av[0], av[1], av[2], clone(av[3])]])
        elif op is C.BRANCH:
            out.append([op, [None, [clone(a) for a in av[1]]]])
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            out.append([op, [av[0], av[1], clone(av[2])]])
        elif op in (C.ASSERT, C.ASSERT_NOT):
            out.append([op, [av[0], clone(av[1])]])
        else:
            out.append([op, av])
    return out


def emit(seq, icase):
    return "".join(emit1(op, av, icase) for op, av in seq)


def node_chars(op, av, icase):
    if op is SET:
        return av
    if op is C.LITERAL:
        return members(re.escape(chr(av)), icase)
    if op is C.NOT_LITERAL:
        return members("[^" + re.escape(chr(av)) + "]", icase)
    if op is C.ANY:
        return members(".", False)
    if op is C.IN:
        return members(class_src(av), icase)
    raise SystemExit("not a char node %r" % (op,))


def emit1(op, av, icase):
    if op in (SET, C.LITERAL, C.NOT_LITERAL, C.ANY, C.IN):
        return rust_class(node_chars(op, av, icase))
    if op is C.BRANCH:
        return "(?:" + "|".join(emit(a, icase) for a in av[1]) + ")"
    if op is C.SUBPATTERN:
        g, add, dele, p = av
        ic = (icase or bool(add & re.I)) and not (dele & re.I)
        return ("(" if g is not None else "(?:") + emit(p, ic) + ")"
    if op in (C.MAX_REPEAT, C.MIN_REPEAT):
        lo, hi, p = av
        q = "{%d,}" % lo if hi is C.MAXREPEAT else "{%d,%d}" % (lo, hi)
        if lo == 0 and hi is C.MAXREPEAT:
            q = "*"
        if lo == 1 and hi is C.MAXREPEAT:
            q = "+"
        if lo == 0 and hi == 1:
            q = "?"
        return "(?:" + emit(p, icase) + ")" + q + ("?" if op is C.MIN_REPEAT else "")
    if op is C.AT and av is C.AT_END_STRING:
        return r"\z"
    raise SystemExit("unsupported %r %r" % (op, av))


def firsts(seq, icase):
    """(set of possible first characters, whether the sequence can be empty)."""
    out = set()
    for op, av in seq:
        if op in (SET, C.LITERAL, C.NOT_LITERAL, C.ANY, C.IN):
            out |= set(node_chars(op, av, icase))
            return out, False
        if op is C.BRANCH:
            nullable = False
            for a in av[1]:
                s, n = firsts(a, icase)
                out |= s
                nullable = nullable or n
            if not nullable:
                return out, False
        elif op is C.SUBPATTERN:
            ic = (icase or bool(av[1] & re.I)) and not (av[2] & re.I)
            s, n = firsts(av[3], ic)
            out |= s
            if not n:
                return out, False
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            s, n = firsts(av[2], icase)
            out |= s
            if av[0] > 0 and not n:
                return out, False
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            continue
        else:
            raise SystemExit("firsts: %r" % (op,))
    return out, True


CLS = []


def cls_id(chars):
    r = ranges(chars)
    if r not in CLS:
        CLS.append(r)
    return CLS.index(r)


def check_tail(seq, icase):
    """A trailing \\b is checked after the match, so a shorter repeat must never be able to pass it."""
    if not seq:
        return
    op, av = seq[-1]
    if op in (C.MAX_REPEAT, C.MIN_REPEAT) and av[0] != av[1]:
        body = av[2]
        if len(body) != 1 or body[0][0] not in (SET, C.LITERAL, C.IN):
            raise SystemExit("trailing \\b after a complex variable repeat")
        if not set(node_chars(body[0][0], body[0][1], icase)) <= WORD_SET:
            raise SystemExit("trailing \\b after a variable repeat with non-word characters")


def strip_guards(seq, icase):
    seq = list(seq)
    start, end = "None", "None"
    if seq and seq[0][0] is C.SUBPATTERN:
        g, add, dele, p = seq[0][1]
        inner = list(p)
        if inner and inner[0][0] is C.AT and inner[0][1] is C.AT_BOUNDARY:
            start = "Boundary"
            seq[0] = [C.SUBPATTERN, [g, add, dele, inner[1:]]]
    if seq and seq[0][0] is C.AT and seq[0][1] is C.AT_BOUNDARY:
        start = "Boundary"
        seq = seq[1:]
    elif seq and seq[0][0] is C.ASSERT_NOT and seq[0][1][0] == -1:
        body = list(seq[0][1][1])
        if len(body) != 1:
            raise SystemExit("lookbehind longer than one character")
        op, av = body[0]
        src = class_src(av) if op is C.IN else re.escape(chr(av))
        start = "NotAfter:%d" % cls_id(members(src, icase))
        seq = seq[1:]
    elif seq and seq[0][0] is C.BRANCH:
        alts = seq[0][1][1]
        heads = [bool(a) and a[0][0] is C.AT and a[0][1] is C.AT_BOUNDARY for a in alts]
        if all(heads):
            start = "Boundary"
            seq[0] = [C.BRANCH, [None, [a[1:] for a in alts]]]
        elif any(heads):
            raise SystemExit("mixed leading boundary")
    if seq and seq[-1][0] is C.AT and seq[-1][1] is C.AT_BOUNDARY:
        end = "Boundary"
        seq = seq[:-1]
        check_tail(seq, icase)
    elif seq and seq[-1][0] is C.BRANCH:
        alts = seq[-1][1][1]
        tails = [bool(a) and a[-1][0] is C.AT and a[-1][1] is C.AT_BOUNDARY for a in alts]
        if all(tails):
            end = "Boundary"
            seq[-1] = [C.BRANCH, [None, [a[:-1] for a in alts]]]
            for a in seq[-1][1][1]:
                check_tail(a, icase)
        elif any(tails):
            raise SystemExit("mixed trailing boundary")
    return seq, start, end


def compile_tree(name, tree, icase, full=False, force=None):
    tree = clone(tree)
    first_chars, nullable = firsts(tree, icase)
    if nullable:
        raise SystemExit("%s can match empty text" % name)
    if full:
        pat = r"\A(?:" + emit(tree, icase) + r")\z"
        s, e = "None", "None"
    else:
        tree, s, e = strip_guards(tree, icase)
        pat = emit(tree, icase)
    if force:
        s = force.get("start", s)
        e = force.get("end", e)
    return {"name": name, "pattern": pat, "start": s, "end": e, "first": sorted({c.encode("utf-8")[0] for c in first_chars})}


SOURCES = [("placeholder", sr.PLACEHOLDER_RE, False), ("private-key", sr._PRIVATE_KEY_RE, False)]
SOURCES += [(k, r, False) for k, r in sr._TAGGED]
SOURCES += [("bearer", sr._BEARER_RE, False), ("url-credential", sr._URL_CRED_RE, False), ("cfg-json", sr._CFG_JSON_RE, False),
            ("cfg-kv", sr._CFG_KV_RE, False), ("anchor", sr._ANCHOR_RE, False), ("cfg-key-full", sr._CFG_KEY_RE, True)]
TREES = {name: (plain(P.parse(rx.pattern)), bool(rx.flags & re.I), full) for name, rx, full in SOURCES}
rules = [compile_tree(n, t, ic, full) for n, (t, ic, full) in TREES.items()]
word = re.compile(r"\w").findall(ALL)
space = re.compile(r"\s").findall(ALL)


def tbl(r):
    return "&[" + ",".join("(0x%X,0x%X)" % (a, b) for a, b in r) + "]"


def g_rs(v):
    return "NotAfter(%s)" % v.split(":")[1] if v.startswith("NotAfter") else v


source = Path(sys.argv[1]).read_bytes()
source_blob = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
with open(sys.argv[2], "w") as f:
    f.write('pub const SOURCE_BLOB: &str = "%s";\n' % source_blob)
    f.write("// generated by tools/gen_redact_tables.py from Python %s unicodedata %s\n" % ("%d.%d" % sys.version_info[:2], unicodedata.unidata_version))
    f.write("#[rustfmt::skip]\npub static WORD: &[(u32,u32)] = %s;\n" % tbl(ranges(word)))
    f.write("#[rustfmt::skip]\npub static SPACE: &[(u32,u32)] = %s;\n" % tbl(ranges(space)))
    f.write("#[rustfmt::skip]\npub static CLS: &[&[(u32,u32)]] = &[%s];\n" % ",".join(tbl(c) for c in CLS))
    f.write("#[derive(Clone,Copy,Debug)] pub enum G { None, Boundary, NotAfter(usize) }\n")
    f.write("#[rustfmt::skip]\npub static RULES: &[(&str,&str,G,G,&[u8])] = &[\n")
    for r in rules:
        f.write('  ("%s", r####"%s"####, G::%s, G::%s, &%s),\n' % (r["name"], r["pattern"], g_rs(r["start"]), g_rs(r["end"]), json.dumps(r["first"])))
    f.write("];\n")
subprocess.run(["rustfmt", "--edition", "2021", sys.argv[2]], check=True)
print("python", sys.version.split()[0], "unidata", unicodedata.unidata_version, "rules", len(rules))
for r in rules:
    print(r["name"], len(r["pattern"]), r["start"], r["end"], "first_bytes", len(r["first"]))

if len(sys.argv) > 3:
    # One deliberate change per mutant, on the rule's parse tree or its guards.
    mutants = []

    def next_absent(chars):
        have = set(chars)
        for c in chars:
            n = ord(c) + 1
            if n < 0x110000 and not 0xD800 <= n <= 0xDFFF and chr(n) not in have:
                return chr(n)
        return None

    def visit(seq, icase, path, name, root, ricase, full, depth=0):
        for i, (op, av) in enumerate(seq):
            label = "%s[%d]" % (path, i)

            def add(kind, node):
                saved = seq[i]
                seq[i] = node
                try:
                    r = compile_tree(name, root, ricase, full)
                    r["mutant"] = "%s %s %s" % (name, label, kind)
                    mutants.append(r)
                except SystemExit as e:
                    pass
                seq[i] = saved

            if op in (C.MAX_REPEAT, C.MIN_REPEAT):
                lo, hi, p = av
                add("lo+1", [op, [lo + 1, hi if hi is C.MAXREPEAT or hi > lo else lo + 1, p]])
                if lo > 0:
                    add("lo-1", [op, [lo - 1, hi, p]])
                if hi is not C.MAXREPEAT:
                    add("hi+1", [op, [lo, hi + 1, p]])
                    if hi > lo:
                        add("hi-1", [op, [lo, hi - 1, p]])
                add("swap-greed", [C.MIN_REPEAT if op is C.MAX_REPEAT else C.MAX_REPEAT, av])
                visit(p, icase, label, name, root, ricase, full, depth + 1)
            elif op is C.BRANCH:
                alts = av[1]
                if len(alts) > 1:
                    for k in range(len(alts)):
                        add("drop-alt-%d" % k, [op, [None, alts[:k] + alts[k + 1:]]])
                for k, a in enumerate(alts):
                    visit(a, icase, label + ".a%d" % k, name, root, ricase, full, depth + 1)
            elif op is C.SUBPATTERN:
                ic = (icase or bool(av[1] & re.I)) and not (av[2] & re.I)
                visit(av[3], ic, label, name, root, ricase, full, depth + 1)
            elif op in (C.LITERAL, C.NOT_LITERAL, C.IN, C.ANY):
                chars = node_chars(op, av, icase)
                if len(chars) > 1:
                    non_ascii = [c for c in chars if ord(c) > 127]
                    if non_ascii and len(non_ascii) < len(chars) and len(chars) < 500:
                        add("drop-non-ascii", [SET, [c for c in chars if ord(c) < 128]])
                    add("drop-first", [SET, chars[1:]])
                    add("drop-last", [SET, chars[:-1]])
                n = next_absent(chars)
                if n and len(chars) < 500:
                    add("add-next", [SET, chars + [n]])
            elif op is C.AT and av is C.AT_END_STRING and depth < 9:
                pass

    for name, (tree, icase, full) in TREES.items():
        if name in ("placeholder", "anchor"):
            continue
        visit(tree, icase, name, name, tree, icase, full)
        if full:
            continue
        base = compile_tree(name, tree, icase, full)
        for field in ("start", "end"):
            if base[field] != "None":
                r = dict(base)
                r[field] = "None"
                r["mutant"] = "%s guard %s removed" % (name, field)
                mutants.append(r)
        if base["start"].startswith("NotAfter:"):
            cls = CLS[int(base["start"].split(":")[1])]
            expanded = [chr(c) for a, b in cls for c in range(a, b + 1)]
            for kind, chars in (("drop-first", expanded[1:]), ("drop-last", expanded[:-1])):
                r = dict(base)
                r["extra_cls"] = ranges(chars)
                r["start"] = "NotAfter:%d" % len(CLS)
                r["mutant"] = "%s guard start class %s" % (name, kind)
                mutants.append(r)
    with open(sys.argv[3], "w") as f:
        json.dump({"cls": len(CLS), "mutants": mutants}, f)
    print("mutants", len(mutants))
