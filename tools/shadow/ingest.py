#!/usr/bin/env python3
"""Run both implementations' real `ccs ingest --backfill` over a snapshot HOME.

Requests go to a loopback server that answers like crates/ccs/tests/
ingest_oracle.py's `ok` handler and stores each decompressed body inside the
private work directory, never in memory or in the report. The two runs start
from identical state bytes and are compared by compare.compare_ingest.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import add_implementation_arguments, environment, implementations, require_snapshot, sha, write_report  # noqa: E402
from compare import compare_ingest, line_oracle  # noqa: E402

RELEVANT = ("content-type", "content-encoding", "accept", "user-agent", "authorization")


class Recorder:
    """Loopback endpoint; bodies go to files, metadata to a list."""

    def __init__(self):
        self.lock = threading.Lock()
        self.dir = None
        self.requests = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                zipped = raw[:2] == b"\x1f\x8b"
                body = gzip.decompress(raw) if zipped else raw
                path = self.path.split("?", 1)[0]
                headers = {k.lower(): v for k, v in self.headers.items()}
                meta = {"method": self.command, "path": path,
                        "headers": dict({k: headers.get(k) for k in RELEVANT}, gzip=zipped)}
                reply = {"stored": True}
                if path == "/token":
                    reply = {"access_token": "shadow-token", "expires_in": 3600}
                elif path.endswith("/ingest"):
                    value = json.loads(body)
                    seg = value["segment"]
                    meta["key"] = ["ingest", value["file"]["jsonl_path"], seg["offset"]]
                    meta["lines"] = len(seg["lines"])
                    reply = {"session_key": "sk_shadow", "next_offset": seg["end_offset"]}
                elif path.endswith("/status"):
                    reply = {"sources": ["claude", "codex"]}
                with outer.lock:
                    index = len(outer.requests)
                    target = outer.dir / ("%07d.bin" % index)
                    target.write_bytes(body)
                    os.chmod(target, 0o600)
                    meta["file"] = str(target)
                    if "key" not in meta:
                        meta["key"] = ["other", self.command, path, sha(body)]
                    outer.requests.append(meta)
                data = json.dumps(reply).encode()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_GET = do_POST = do_DELETE = _do

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def start_run(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.lock:
            self.dir, self.requests = directory, []

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def normalized_state(state: Path, start: float, end: float):
    """{format_ok, text}: the contract format (0600, sort_keys, indent=1) and the content with last_ok normalised."""
    if not state.exists():
        return None
    raw = state.read_text()
    value = json.loads(raw)
    format_ok = state.stat().st_mode & 0o777 == 0o600 and raw == json.dumps(value, sort_keys=True, indent=1)
    for entry in value.get("files", {}).values():
        stamp = entry.get("last_ok")
        if stamp:
            epoch = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()
            entry["last_ok"] = "<call-time>" if start - 1 <= epoch <= end + 1 else "<kept>"
    return {"format_ok": format_ok, "text": json.dumps(value, sort_keys=True, indent=1)}


def log_messages(log: Path) -> list:
    if not log.exists():
        return []
    out = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[1] in ("WARN", "ERROR"):
            out.append(parts[2])
    return out


def prepare_state(home: Path, mode: str, source_home: Path) -> bytes | None:
    state = home / ".claude/session-search/state.json"
    if mode == "empty":
        return None
    real = home / "state.real.json"
    value = json.loads(real.read_text())
    old, new = str(source_home) + "/", str(home) + "/"
    value["files"] = {(k.replace(old, new, 1) if k.startswith(old) else k): v for k, v in value["files"].items()}
    data = json.dumps(value, sort_keys=True, indent=1).encode()
    state.write_bytes(data)
    os.chmod(state, 0o600)
    return data


class FileBytes:
    """Whole-file reads of the frozen copy, one file cached at a time."""

    def __init__(self, home: Path):
        self.home, self.path, self.data = str(home) + "/", None, None

    def __call__(self, path: str):
        if not path.startswith(self.home):
            return None
        if path != self.path:
            try:
                self.path, self.data = path, Path(path).read_bytes()
            except OSError:
                self.path, self.data = path, None
        return self.data


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, required=True, help="snapshot HOME from snapshot.py")
    p.add_argument("--state", choices=("empty", "copy"), default="empty",
                   help="empty: ship every file from offset 0; copy: start from this host's cursors")
    p.add_argument("--source-home", type=Path, default=Path.home())
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=4 * 3600)
    p.add_argument("--keep-bodies", action="store_true")
    add_implementation_arguments(p)
    a = p.parse_args(argv)
    home = require_snapshot(a.home, a.source_home)
    work = home / ".shadow-ingest"
    server = Recorder()
    key = home / "hmac.key"
    key.write_text(secrets.token_hex(32) + "\n")
    os.chmod(key, 0o600)
    config = home / ".config/session-search/config.json"
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.write_text(json.dumps({"endpoint": server.base + "/memory/sessions/v1", "host_label": "shadow-host",
                                  "auth": {"type": "tailnet"}, "hmac_key_file": str(key)}))
    state = home / ".claude/session-search/state.json"
    initial = prepare_state(home, a.state, a.source_home.resolve())
    log = home / ".claude/session-search.log"
    env = environment(home)
    runs, timing = {}, {}
    try:
        for name, command in implementations(a).items():
            if initial is None:
                if state.exists():
                    state.unlink()
            else:
                state.write_bytes(initial)
                os.chmod(state, 0o600)
            log.write_text("")
            server.start_run(work / name)
            started = time.time()
            r = subprocess.run(command + ["ingest", "--backfill"], env=env, cwd=home,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=a.timeout)
            ended = time.time()
            timing[name] = round(ended - started, 1)
            runs[name] = {"exit": r.returncode, "stdout": r.stdout, "stderr_lines": len(r.stderr.splitlines()),
                          "state": normalized_state(state, started, ended), "warnings": log_messages(log),
                          "requests": [dict(m, body=(lambda f=m["file"]: Path(f).read_bytes())) for m in server.requests]}
        result = compare_ingest(runs["python"], runs["rust"], FileBytes(home), line_oracle().SR.load_key(str(key)))
    finally:
        server.close()
        if not a.keep_bodies:
            shutil.rmtree(work, ignore_errors=True)
    report = {"tool": "ingest", "state_mode": a.state, "elapsed_s": timing,
              "exit": {n: r["exit"] for n, r in runs.items()},
              "stderr_lines": {n: r["stderr_lines"] for n, r in runs.items()},
              "requests": {n: len(r["requests"]) for n, r in runs.items()},
              "warnings": {n: len(r["warnings"]) for n, r in runs.items()},
              "rust_panicked": runs["rust"]["exit"] == 101}
    report.update(result.report())
    write_report(a.out, report)
    print(json.dumps({"requests": report["requests"], "unexplained": report["unexplained_total"],
                      "classified": report["classified"]}))
    ok = report["unexplained_total"] == 0 and result.compared["ingest_requests"] > 0 and not report["rust_panicked"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
