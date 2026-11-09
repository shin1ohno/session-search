#!/usr/bin/env python3
"""Close the dependency-edge inventory that deny.toml enforces."""
import json
from pathlib import Path
import subprocess
import tomllib

root = Path(__file__).resolve().parents[1]
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root))
policy = tomllib.loads((root / "deny.toml").read_text())
banned = {entry["crate"] for entry in policy["bans"]["deny"]}
allowed = {"regex-automata", "ring", "ccs-pytext"}
for package in meta["packages"]:
    if package["name"] == "ccs-redact":
        assert {d["name"] for d in package["dependencies"]} == allowed, "ccs-redact direct dependencies changed"
    elif package["name"] not in allowed | {"ccs"}:
        assert package["name"] in banned, "dependency missing from deny.toml edge policy: " + package["name"]
assert "serde_json" in banned, "serde_json must remain banned"
print("PASS dependency edge policy")
