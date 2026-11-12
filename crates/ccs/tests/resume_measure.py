"""Measure a single process through exec, without sampling or external tools."""
import os
from pathlib import Path
import subprocess
import sys

with subprocess.Popen(sys.argv[2:]) as proc:
    _, status, usage = os.wait4(proc.pid, 0)
    proc.returncode = os.waitstatus_to_exitcode(status)
    rss = usage.ru_maxrss / 1024 if sys.platform == 'darwin' else usage.ru_maxrss
    Path(sys.argv[1]).write_text(str(int(rss)) + '\n')
    raise SystemExit(proc.returncode if proc.returncode >= 0 else 128 - proc.returncode)
