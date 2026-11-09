"""Real CLI processes, disposable HOME, loopback server and PATH executables.

CCS_UNDER_TEST is a shell-quoted argv string, never evaluated by a shell.
Without it, stage the Python package as deploy-pinned.sh does, including the
real server modules. No production endpoint or credentials are inherited.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from support import HomeCase, FakeServer, SID, SID2, FAKE_TOKEN, user, assistant, read


def encode_cwd(path):
    return re.sub(r"[^A-Za-z0-9-]", "-", path)


class ClientCase(HomeCase):
    def setUp(self):
        super().setUp()
        self.repo = ROOT.parent
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.state_dir = Path(self.tmp) / ".claude/session-search"
        self.state_dir.mkdir(parents=True)
        self.state_path = self.state_dir / "state.json"
        self.breaker_path = self.state_dir / "breaker.json"
        self.restored_path = self.state_dir / "restored.json"
        self.log_path = Path(self.tmp) / ".claude/session-search.log"
        self.exec_path = Path(self.tmp) / "exec.jsonl"
        self.env = dict(os.environ)
        for name in list(self.env):
            if name.startswith(("CCS_", "FZF_", "CODEX_")) or name in (
                    "CLAUDE_CODE_SESSION_ID", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
                self.env.pop(name, None)
        self.env.update(HOME=self.tmp, CODEX_HOME=str(Path(self.tmp) / ".codex"),
                        PYTHONDONTWRITEBYTECODE="1", CCS_EXEC_LOG=str(self.exec_path),
                        TMPDIR=self.tmp, NO_PROXY="*")
        selected = self._env.get("CCS_UNDER_TEST")
        if selected:
            self.command = shlex.split(selected)
        else:
            stage = Path(self.tmp) / "python"
            shutil.copytree(self.repo / "ccs", stage / "ccs", ignore=shutil.ignore_patterns("__pycache__"))
            for name in ("session_redact.py", "session_codex.py"):
                shutil.copyfile(self.repo / "vendor/memory-mcp" / name, stage / "ccs" / name)
            self.env["PYTHONPATH"] = str(stage)
            self.command = [sys.executable, "-m", "ccs"]
        launcher = self.bin / "ccs"
        launcher.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(s) for s in self.command) + ' "$@"\n')
        launcher.chmod(0o755)
        self.env["CCS_LAUNCHER"] = str(launcher)
        self.env["PATH"] = str(self.bin)
        # Real native tools avoid HOME-dependent version-manager shims.
        for name in ("rg", "curl", "sh"):
            candidates = [str(Path(d) / name) for d in ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin")]
            candidates.append(self._env.get("CCS_TEST_" + name.upper()) or shutil.which(name, path=self._env.get("PATH")) or "/nonexistent")
            for candidate in candidates:
                path = Path(candidate)
                if path.is_file() and os.access(str(path), os.X_OK):
                    (self.bin / name).symlink_to(path)
                    break
        for name in ("claude", "codex"):
            self.fake(name, "import json, os, sys\n"
                      "with open(os.environ['CCS_EXEC_LOG'], 'a') as f:\n"
                      "    f.write(json.dumps({'argv': [os.path.basename(sys.argv[0])] + sys.argv[1:], 'cwd': os.getcwd()}) + '\\n')\n")

    def fake(self, name, code):
        path = self.bin / name
        if path.is_symlink():
            path.unlink()
        path.write_text("#!" + sys.executable + "\n" + code)
        path.chmod(0o755)
        return path

    def tearDown(self):
        # Process/socket cleanups need HOME to exist and its environment intact.
        self.doCleanups()
        super().tearDown()

    def run_ccs(self, *args, env=None, command=None, cwd=None, input=None, timeout=30):
        values = dict(self.env)
        values.update(env or {})
        return subprocess.run(list(command or self.command) + list(args), env=values,
                              cwd=cwd or self.tmp, input=input, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=timeout)

    def good(self, *args, **kwargs):
        result = self.run_ccs(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def files(self):
        return json.loads(self.state_path.read_text())["files"] if self.state_path.exists() else {}

    def ingest(self, mode, file_path=None, quiet=False, with_subagents=False):
        args = ["ingest", "--" + mode] if mode != "file" else ["ingest", "--file", file_path]
        if quiet:
            args.append("--quiet")
        if with_subagents:
            args.append("--with-subagents")
        result = self.run_ccs(*args)
        self.last_ingest = result
        return result.returncode

    def ship_file(self, path):
        result = self.good("ingest", "--file", path)
        stats = json.loads(result.stdout.removeprefix("ccs ingest: "))
        return "unchanged" if stats["segments"] == 0 else "shipped"

    def ship(self, path):
        return self.ship_file(path)

    def execs(self):
        if not self.exec_path.exists():
            return []
        return [json.loads(line) for line in self.exec_path.read_text().splitlines()]

    def reset_execs(self):
        self.exec_path.write_text("")

    def write_breaker(self, failures, open_until):
        self.breaker_path.write_text(json.dumps({"failures": failures, "open_until": open_until}))

    def native_path(self, sid=SID):
        folder = Path(self.env["CODEX_HOME"]) / "sessions/2026/10/25"
        folder.mkdir(parents=True, exist_ok=True)
        return str(folder / ("rollout-2026-10-25T00-00-00-" + sid + ".jsonl"))

    def write_native(self, rows, sid=SID):
        path = self.native_path(sid)
        Path(path).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
        return path

    def local_search(self, query, *args):
        return json.loads(self.good("search", query, "--offline", *args).stdout)

    def rows(self, query="", **kwargs):
        return self.good("_backend", query, **kwargs).stdout

    def make_fzf(self, output="", exit_code=130):
        self.fake("fzf", "import json, os, sys\n"
                  "with open(os.environ['HOME'] + '/fzf.json', 'w') as f:\n"
                  "    json.dump({'argv': sys.argv[1:], 'pick': os.environ.get('CCS_PICK')}, f)\n"
                  "sys.stdout.write(" + repr(output) + ")\nraise SystemExit(" + str(exit_code) + ")\n")
