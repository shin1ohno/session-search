#!/usr/bin/env python3
"""Exercise build identity, S2 redaction, and fail-closed publication eligibility."""
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


def check_foundation():
    info = json.loads(subprocess.check_output([binary, "_buildinfo"]))
    assert len(info["commit"]) == 40 and info["version"] == "0.2.0"
    assert subprocess.check_output([binary, "--version"], text=True) == "ccs 0.2.0\n"
    for args, code in ((["_conformance", "redact"], 1), (["_conformance", "codex"], 1), (["status"], 2)):
        p = subprocess.run([binary, *args], capture_output=True, text=True)
        assert p.returncode == code and not p.stdout
        print("PASS empty/unsupported command refusal:", *args, "exit", p.returncode)
    gate = [sys.executable, str(root / "tools/release_gate.py")]
    p = subprocess.run([*gate, str(binary), info["commit"], info["target"]], capture_output=True, text=True)
    assert p.returncode == 1 and 'conformance is not implemented in S1' in p.stderr
    print(p.stderr.strip())
    print("PASS publication gate refuses incomplete client")
    with tempfile.TemporaryDirectory() as work:
        ready = Path(work) / "ready"
        ready.touch()
        subprocess.run(["bash", str(root / "tools/stage_release.sh"), str(binary),
                        info["commit"], info["target"], work], check=True)
        assert not ready.exists()
        print("PASS negative: stale publication marker removed after refused gate")
        # A fake executable claims every suite passed but emits no vectors.
        fake = Path(work) / "ccs"
        fake.write_text('#!/bin/sh\nif [ "$1" = _buildinfo ]; then\ncat <<\'JSON\'\n' + json.dumps(info) + '\nJSON\nfi\n')
        fake.chmod(0o755)
        p = subprocess.run([*gate, str(fake), info["commit"], info["target"]], capture_output=True, text=True)
        assert p.returncode == 1 and "missing or extra emit row" in p.stderr
        print("PASS negative: always-success conformance rejected for missing output")

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
    check_foundation()
    subprocess.run([sys.executable, str(root / "tests/conformance/run.py"), str(binary)], check=True)
