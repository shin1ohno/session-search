#!/usr/bin/env python3
"""Real metadata inputs distinguish each check_dependencies.py assertion."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
for case, reason in [("baseline", None), ("redactor", "direct dependencies changed"),
                     ("inventory", "dependency missing from deny.toml"), ("json", "serde_json must remain banned")]:
    with tempfile.TemporaryDirectory(prefix="ccs-inventory-") as tmp:
        work = Path(tmp)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "deny.toml"):
            shutil.copy(root / name, work / name)
        shutil.copytree(root / "crates", work / "crates")
        (work / "tools").mkdir(); shutil.copy(root / "tools/check_dependencies.py", work / "tools")
        if case == "redactor":
            p = work / "crates/ccs-redact/Cargo.toml"
            p.write_text(p.read_text().replace("ring.workspace = true\n", ""))
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=work, check=True, capture_output=True)
        elif case in ("inventory", "json"):
            p = work / "deny.toml"; crate = "serde_json" if case == "json" else "libc"
            text, count = re.subn(r'^.*\{ crate = "'+crate+r'".*\n', '', p.read_text(), flags=re.M)
            assert count == 1
            p.write_text(text)
        result = subprocess.run([sys.executable, "tools/check_dependencies.py"], cwd=work, text=True, capture_output=True)
        if reason:
            assert result.returncode != 0 and reason in result.stderr, (case, "inventory guard missed", result.stdout, result.stderr)
        else: assert result.returncode == 0, result.stderr
        print("PASS dependency inventory", case)
