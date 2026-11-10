#!/usr/bin/env python3
"""Check every workflow's action pins and release shell producer failures."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
workflow = (root / ".github/workflows/release.yml").read_text()
workflow_dir = root / ".github/workflows"
paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
assert paths, "no workflows found"
# Recognize block keys, quoted keys/values and single-entry flow mappings.
# Other syntax containing uses must fail closed rather than escape the scan.
use_line = re.compile(r'''\s*(?:-\s*)?(?:\{\s*)?(?:uses|"uses"|'uses')\s*:\s*(?:"([^"]+)"|'([^']+)'|([^\s,}#]+))\s*(?:\}\s*)?(?:#.*)?''')
total_actions = 0
for path in paths:
    actions = 0
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if "uses" not in line:
            continue
        location = path.name + ":" + str(number)
        match = use_line.fullmatch(line)
        assert match, location + ": unrecognized uses syntax: " + line.strip()
        action = next(value for value in match.groups() if value is not None)
        if action.startswith("./"):
            continue  # Local references use the same checked-out commit.
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), location + ": action is not pinned to a commit: " + action
        actions += 1
    total_actions += actions
    print("PASS", path.name, "external action pins:", actions)
assert total_actions, "no external actions found"
step = workflow.split(
    "      - name: Build and exercise the publication gate\n", 1)[1].split("      - uses:", 1)[0]
body = step.split("        run: |\n", 1)[1]
script = "\n".join(line[10:] for line in body.splitlines() if line.startswith("          "))
shell = ["/bin/bash", "--noprofile", "--norc", "-e"]
if "        shell: bash\n" in step:
    shell += ["-o", "pipefail"]
for label, lock_exit, info_exit, expected in [("baseline", 0, 0, 1), ("lock failure", 17, 0, 17), ("buildinfo failure", 0, 19, 19)]:
    with tempfile.TemporaryDirectory(prefix="ccs-workflow-") as tmp:
        work = Path(tmp); commands = work / "commands"; commands.mkdir()
        target = "x86_64-unknown-linux-gnu"; commit = "1" * 40
        out = work / "target" / target / "release"; (out / "examples").mkdir(parents=True)
        info = json.dumps(dict(version="0.2.0", commit=commit, target=target, redact_version="r1"), separators=(",", ":"))
        (out / "ccs").write_text("#!/bin/sh\nif [ \"$1\" = _buildinfo ]; then\nprintf '%s\\n' '" + info + "'\nexit ${INFO_EXIT}\nfi\necho 'ccs: conformance is not implemented in S1' >&2\nexit 1\n")
        (out / "ccs").chmod(0o755); (out / "examples/lock_probe").touch()
        # The adapter must propagate each producer's status, including on macOS.
        (commands / "cargo").write_text("#!/bin/sh\nexit 0\n")
        (commands / "python3").write_text('#!/bin/sh\nif [ "$1" = tools/test_lock.py ]; then echo lock-producer; exit "$LOCK_EXIT"; fi\nexec "' + sys.executable + '" "$@"\n')
        (commands / "uname").write_text("#!/bin/sh\necho Darwin\n")
        (commands / "codesign").write_text("#!/bin/sh\nexit 0\n")
        (commands / "otool").write_text("#!/bin/sh\nprintf 'cmd LC_BUILD_VERSION\\n minos 11.0\\n'\n")
        for p in commands.iterdir(): p.chmod(0o755)
        shutil.copytree(root / "tools", work / "tools")
        shutil.copytree(root / "vendor", work / "vendor")
        env = dict(os.environ, PATH=str(commands)+os.pathsep+os.environ["PATH"], TARGET=target,
                   GITHUB_SHA=commit, LOCK_EXIT=str(lock_exit), INFO_EXIT=str(info_exit))
        result = subprocess.run(shell, input=script, cwd=work, env=env, text=True, capture_output=True)
        assert result.returncode == expected, (label, "producer failure hidden", result.returncode, result.stdout, result.stderr)
        assert not (work / "artifact/ready").exists()
        if not lock_exit and not info_exit:
            refused = work / "artifact/refused.log"
            assert refused.is_file(), "refusal log missing"
            assert refused.read_bytes() == (work / "artifact/gate.log").read_bytes()
            assert "FAIL publication gate:" in refused.read_text()
        if info_exit: assert not (work / "artifact/lock.log").exists(), "continued after buildinfo failure"
        if lock_exit: assert not (work / "artifact/gate.log").exists(), "continued after lock failure"
        print("PASS release shell", label, "exit", result.returncode)
