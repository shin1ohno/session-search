#!/usr/bin/env python3
"""Exercise build identity, S2 redaction, and fail-closed publication eligibility."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = root / "target/release/ccs"
def publication_guard(source):
    # Recognize the actual publish-job condition, rather than a comment or a
    # different job. Restrict it to the conjunction we require.
    publish = source.split("\n  publish:\n", 1)[1]
    condition = next(line.strip()[4:] for line in publish.splitlines() if line.startswith("    if: "))
    clauses = {x.strip() for x in condition.split("&&")}
    required = {"vars.CCS_RELEASE_ENABLED == 'true'", "github.event_name == 'push'",
                "github.ref == 'refs/heads/main'", "needs.release-check.outputs.ready == 'true'"}
    assert clauses == required, "publish must require explicit release enablement"


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
    publication_guard(workflow)
    try:
        publication_guard(workflow.replace("vars.CCS_RELEASE_ENABLED == 'true' && ", ""))
    except AssertionError as exc:
        assert "explicit release enablement" in str(exc)
        print("PASS negative: removed publication guard rejected")
    else:
        raise AssertionError("missing publication guard was accepted")


if __name__ == "__main__":
    check_foundation()
    subprocess.run([sys.executable, str(root / "tests/conformance/run.py"), str(binary)], check=True)
