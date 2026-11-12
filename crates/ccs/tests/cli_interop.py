#!/usr/bin/env python3
"""Run the state contract with Rust/Python in both external-command roles."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def main():
    rust = os.environ.get("CCS_UNDER_TEST", str(ROOT / "target/release/ccs"))
    with tempfile.TemporaryDirectory(prefix="ccs-interop-") as directory:
        stage = Path(directory)
        shutil.copytree(ROOT / "ccs", stage / "ccs", ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("session_redact.py", "session_codex.py"):
            shutil.copyfile(ROOT / "vendor/memory-mcp" / name, stage / "ccs" / name)
        launcher = stage / "python_ccs.py"
        launcher.write_text("import runpy,sys\nsys.path.insert(0," + repr(str(stage)) + ")\nrunpy.run_module('ccs',run_name='__main__')\n")
        python = shlex.join([sys.executable, str(launcher)])
        for command, peer, label in ((rust, python, "Rust writes / Python reads"),
                                     (python, rust, "Python writes / Rust reads")):
            print(label, flush=True)
            result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests/contract", "-t", "tests",
                                     "-p", "test_state_interop.py", "-v"], cwd=ROOT,
                                    env=dict(os.environ, CCS_UNDER_TEST=command, CCS_INTEROP_PEER=peer))
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
