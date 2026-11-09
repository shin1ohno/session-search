#!/usr/bin/env python3
"""Break real workspace copies to prove the dependency gates reject changes."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
for name, dependency in (("redactor extra dependency", "libc.workspace = true\n"),
                         ("banned JSON dependency", 'serde_json = "1"\n')):
    with tempfile.TemporaryDirectory(prefix="ccs-deny-") as work:
        work = Path(work)
        for file in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "deny.toml"):
            shutil.copy(root / file, work / file)
        shutil.copytree(root / "crates", work / "crates")
        manifest = work / "crates/ccs-redact/Cargo.toml"
        manifest.write_text(manifest.read_text() + dependency)
        subprocess.run(["cargo", "generate-lockfile"], cwd=work, check=True, stdout=subprocess.DEVNULL)
        result = subprocess.run(["cargo", "deny", "--locked", "check", "bans"], cwd=work, capture_output=True, text=True)
        assert result.returncode != 0 and ("explicitly banned" in result.stderr or "not allowed" in result.stderr), result.stderr
        print("PASS negative dependency policy:", name)
        print("\n".join(line for line in result.stderr.splitlines() if "error" in line or "ccs-redact" in line or "serde_json" in line))
