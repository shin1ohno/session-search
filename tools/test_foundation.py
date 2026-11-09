#!/usr/bin/env python3
"""Exercise actual binary and publication rejection; no runtime test flags."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = root / "target/release/ccs"
info = json.loads(subprocess.check_output([binary, "_buildinfo"]))
assert len(info["commit"]) == 40 and info["version"] == "0.2.0"
assert subprocess.check_output([binary, "--version"], text=True) == "ccs 0.2.0\n"
for args, code in ((["_conformance", "redact"], 1), (["_conformance", "codex"], 1), (["status"], 2)):
    p = subprocess.run([binary, *args], capture_output=True, text=True)
    assert p.returncode == code and not p.stdout
    print("PASS skeleton refusal:", *args, "exit", p.returncode)
gate = [sys.executable, str(root / "tools/release_gate.py")]
p = subprocess.run([*gate, str(binary), info["commit"], info["target"]], capture_output=True, text=True)
assert p.returncode == 1 and 'not implemented in S1' in p.stderr
print(p.stderr.strip())
print("PASS publication gate refuses skeleton")
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
