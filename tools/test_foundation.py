#!/usr/bin/env python3
"""Exercise build identity, both conformance suites, and publication eligibility."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = root / "target/release/ccs"
def publication_guard(source):
    # Recognize the actual publish-job condition, rather than a comment or a
    # different job. Restrict it to the conjunction we require.
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", source.split("\njobs:\n",1)[1])
    jobs = dict(zip(parts[1::2],parts[2::2]))
    publish = jobs["publish"]
    release = r"\bgh\s+release\s+create\b"
    assert len(re.findall(release,source)) == 1 and len(re.findall(release,publish)) == 1, "release creation must occur exactly once, inside publish"
    condition = next(line.strip()[4:] for line in publish.splitlines() if line.startswith("    if: "))
    clauses = {x.strip() for x in condition.split("&&")}
    required = {"vars.CCS_RELEASE_ENABLED == 'true'", "github.event_name == 'push'",
                "github.ref == 'refs/heads/main'", "needs.release-check.outputs.ready == 'true'"}
    assert clauses == required, "publish must require explicit release enablement"
    first = publish.split("    steps:\n",1)[1].split("\n      - ",1)[0]
    assert first == ('      - name: Require exact release enablement\n'
                     '        env:\n'
                     '          RELEASE_ENABLED: ${{ vars.CCS_RELEASE_ENABLED }}\n'
                     '        shell: bash\n'
                     '        run: test "$RELEASE_ENABLED" = true'), "first publish step must test exact lowercase true"
    return first.split('        run: ',1)[1]


def check_codex():
    corpus = root / "vendor/memory-mcp/conformance/session_codex_v1.jsonl"
    raw = corpus.read_bytes()
    header, *vectors = [json.loads(line) for line in raw.splitlines()]
    result = subprocess.run([binary, "_conformance", "codex"], input=raw,
                            capture_output=True, check=True)
    assert not result.stdout and b"failures=0" in result.stderr
    emitted = subprocess.run([binary, "_conformance", "codex", "--emit"], input=raw,
                             capture_output=True, check=True)
    rows = [json.loads(line) for line in emitted.stdout.splitlines()]
    expected = [{"id": v["id"], "result": v["expect"]} for v in vectors]
    assert json.dumps(rows) == json.dumps(expected), "Codex emit values/types/key order differ"
    assert len(rows) == header["vectors"] and len(rows) >= header["min_vectors"]
    print("PASS Codex corpus and complete emit:", len(rows), "vectors")
    # Repair the checksum so this tests behavior, not only corpus integrity.
    vectors[0]["expect"]["type"] += "-incorrect"
    body = b"".join((json.dumps(v) + "\n").encode() for v in vectors)
    header["sha256_of_vectors"] = hashlib.sha256(body).hexdigest()
    broken = (json.dumps(header) + "\n").encode() + body
    result = subprocess.run([binary, "_conformance", "codex"], input=broken, capture_output=True)
    assert result.returncode == 1 and not result.stdout
    assert ('FAIL conformance: ' + json.dumps(vectors[0]["id"])).encode() in result.stderr
    assert b"failures=1" in result.stderr
    print("PASS negative Codex expected-value change: exact vector rejected with repaired checksum")


def check_foundation():
    info = json.loads(subprocess.check_output([binary, "_buildinfo"]))
    assert len(info["commit"]) == 40 and info["version"] == "0.2.0"
    assert subprocess.check_output([binary, "--version"], text=True) == "ccs 0.2.0\n"
    for args, code in ((["_conformance", "redact"], 1), (["_conformance", "codex"], 1), (["status"], 2)):
        p = subprocess.run([binary, *args], capture_output=True, text=True)
        assert p.returncode == code and not p.stdout
        print("PASS empty/unsupported command refusal:", *args, "exit", p.returncode)
    with tempfile.TemporaryDirectory() as work:
        ready = Path(work) / "ready"
        stage = ["bash", str(root / "tools/stage_release.sh")]
        result = subprocess.run([*stage, str(binary), info["commit"], info["target"], work],
                                capture_output=True, text=True, check=True)
        assert ready.is_file() and not (Path(work) / "refused.log").exists()
        assert "PASS publication gate" in (Path(work) / "gate.log").read_text()
        print("PASS both corpus suites authorize a fresh ready marker")
        # Each wrapper delegates every unaffected operation to the real binary.
        # This isolates the missing or failing suite, preserving a valid identity.
        for mode, reason in (("codex-fail", "exit status 35"),
                             ("codex-empty", "missing or extra Codex emit row"),
                             ("codex-missing", "missing or extra Codex emit row"),
                             ("codex-extra", "missing or extra Codex emit row"),
                             ("codex-order", "unknown, duplicate or out-of-order Codex emit id"),
                             ("codex-wrong", "Codex output mismatch"),
                             ("redact-empty", "missing or extra emit row")):
            fake = Path(work) / "ccs"
            code = "\n".join([
                "#!" + sys.executable,
                "import json, os, subprocess, sys",
                "binary = " + repr(str(binary)), "mode = " + repr(mode),
                "args = sys.argv[1:]",
                "if args[:2] == ['_conformance', 'codex']:",
                "    if mode == 'codex-fail': sys.exit(35)",
                "    if mode == 'codex-empty': sys.exit(0)",
                "    if mode in ('codex-missing', 'codex-extra', 'codex-order', 'codex-wrong') and args[2:] == ['--emit']:",
                "        p = subprocess.run([binary, *args], capture_output=True, check=True)",
                "        rows = [json.loads(line) for line in p.stdout.splitlines()]",
                "        if mode == 'codex-missing': rows.pop()",
                "        if mode == 'codex-extra': rows.append(rows[-1])",
                "        if mode == 'codex-order': rows[0], rows[1] = rows[1], rows[0]",
                "        if mode == 'codex-wrong': rows[0]['result']['type'] = 'incorrect'",
                "        print(*[json.dumps(row) for row in rows], sep=chr(10))",
                "        sys.exit(0)",
                "if args[:2] == ['_conformance', 'redact'] and mode == 'redact-empty': sys.exit(0)",
                "os.execv(binary, [binary, *args])", "",
            ])
            fake.write_text(code)
            fake.chmod(0o755)
            ready.touch()  # A stale result must be removed before this invocation.
            result = subprocess.run([*stage, str(fake), info["commit"], info["target"], work],
                                    capture_output=True, text=True)
            output = (Path(work) / "gate.log").read_text()
            assert result.returncode != 0 and not ready.exists(), (mode, "invalid binary left ready")
            refused = Path(work) / "refused.log"
            assert refused.is_file() and refused.read_text() == output, (mode, "refusal evidence missing")
            assert reason in output, (mode, "wrong refusal reason", output[-500:])
            print("PASS negative publication binary:", mode, "refused; stale ready removed")

    workflow = (root / ".github/workflows/release.yml").read_text()
    command = publication_guard(workflow)
    for value in ('true','TRUE','True','false','','true '):
        result = subprocess.run(['bash','-ec',command],env=dict(os.environ,RELEASE_ENABLED=value))
        assert result.returncode == (0 if value == 'true' else 1),(value,result.returncode)
    print("PASS exact release enablement: only lowercase true succeeds")
    extra = '\n  extra-publish:\n    steps:\n      - run: gh release create bad\n'
    publish_command = next(line for line in workflow.splitlines() if 'gh release create' in line)
    controls = {
        'removed expression guard': (workflow.replace("vars.CCS_RELEASE_ENABLED == 'true' && ", ""), 'explicit release enablement'),
        'removed shell guard': (workflow.replace('        run: test "$RELEASE_ENABLED" = true','        run: true'), 'first publish step'),
        'appended release job': (workflow + extra, 'exactly once, inside publish'),
        'inserted release job': (workflow.replace('  release-check:',extra+'  release-check:'), 'exactly once, inside publish'),
        'relocated release command': (workflow.replace(publish_command,'        run: true') + extra, 'exactly once, inside publish'),
    }
    for name,(broken,reason) in controls.items():
        try:
            publication_guard(broken)
        except AssertionError as exc:
            assert reason in str(exc),(name,str(exc))
            print('PASS negative publication control:',name)
        else:
            raise AssertionError('accepted publication control: '+name)



if __name__ == "__main__":
    check_codex()
    check_foundation()
    subprocess.run([sys.executable, str(root / "tests/conformance/run.py"), str(binary)], check=True)
