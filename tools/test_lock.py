#!/usr/bin/env python3
"""Verify both directions on the same real file, with an unlocked control."""
import fcntl
from pathlib import Path
import subprocess
import sys
import tempfile

probe = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as work:
    path = Path(work) / "lock"
    with path.open("w") as file:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([probe, str(path)], capture_output=True, text=True)
        assert result.returncode == 9 and result.stdout.strip() == "blocked", result
        print("PASS Python flock blocks Rust File::try_lock")
        fcntl.flock(file, fcntl.LOCK_UN)
        subprocess.run([probe, str(path)], check=True)
        with subprocess.Popen([probe, str(path), "hold"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
            assert child.stdout.readline().strip() == "locked"
            try:
                try:
                    fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    print("PASS Rust File::try_lock blocks Python flock")
                else:
                    raise AssertionError("Python acquired a Rust-held lock")
            finally:
                child.communicate("release\n")
            assert child.returncode == 0
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("PASS both unlocked controls")
