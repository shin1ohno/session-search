"""Compare the function boundary against Python using identical files and state.

Compare decompressed HTTP entity bytes (gzip headers/deflate encoders differ),
selected protocol headers, exit status, stdout and exact state bytes except the
validated wall-clock last_ok. No production config, credentials or server used.
"""
import argparse
import datetime
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(REPO), str(REPO / "tests")]
from support import FakeServer, SID, SID2
import ccs
for module in ("session_redact", "session_codex"):
    spec = importlib.util.spec_from_file_location("ccs." + module, REPO / "vendor/memory-mcp" / (module + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = loaded
    spec.loader.exec_module(loaded)
    setattr(ccs, module, loaded)
from ccs import ingest

EVIDENCE = None

SECRET = "ghp_" + "A" * 36
LINE = (json.dumps({"type": "user", "message": {"content": "日本 " + SECRET}}, ensure_ascii=False) + "\n").encode()


def record_comparison(label, expected, got):
    if EVIDENCE is None:
        return
    def snapshot(result):
        result = dict(result)
        result['stdout'] = result['stdout'].decode('utf-8', 'replace')
        requests = []
        for method, path, headers, body in result['requests']:
            requests.append(dict(method=method, path=path, headers=headers, body_bytes=len(body),
                                 body_sha256=hashlib.sha256(body).hexdigest(),
                                 body=body.decode('utf-8') if len(body) < 16384 else '<digest above>'))
        result['requests'] = requests
        return result
    with EVIDENCE.open('a') as output:
        output.write(json.dumps(dict(case=label, python=snapshot(expected), rust=snapshot(got)), ensure_ascii=True) + '\n')


def python_main(args):
    try:
        return ingest.run(args[0], file_path=args[1] if args[0] == "file" else None,
                          with_subagents="--with-subagents" in args, quiet="--quiet" in args)
    except Exception as exc:
        # D6: the function adapter exposes exit 1 without leaking input in a traceback.
        print(type(exc).__name__, file=sys.stderr)
        return 1


def ok(req):
    if req["path"] == "/token":
        return 200, {"access_token": "synthetic-token", "expires_in": 3600}, {}
    if req["path"].endswith("/ingest"):
        segment = req["body"]["segment"]
        return 200, {"session_key": "sk_oracle", "next_offset": segment["end_offset"]}, {}
    if req["path"].endswith("/status"):
        return 200, {"sources": ["claude", "codex"]}, {}
    return 200, {"stored": True}, {}


class Fixture:
    def __init__(self, binary):
        self.tmp = tempfile.TemporaryDirectory(prefix="ccs-ingest-")
        self.home = Path(self.tmp.name)
        self.binary = str(binary)
        self.server = FakeServer(ok)
        self.project = self.home / ".claude/projects/-work-demo"
        self.project.mkdir(parents=True)
        self.path = self.project / (SID + ".jsonl")
        self.path.write_bytes(LINE)
        self.state = self.home / ".claude/session-search/state.json"
        self.state.parent.mkdir()
        self.key = self.home / "hmac.key"
        self.key.write_bytes(b" \t\r\n\v\fsynthetic-oracle-key\v\f\n")
        self.config = self.home / ".config/session-search/config.json"
        self.config.parent.mkdir(parents=True)
        self.settings = {"endpoint": self.server.base + "/memory/sessions/v1", "host_label": "test-host",
                         "auth": {"type": "tailnet"}, "hmac_key_file": str(self.key)}
        self.config.write_text(json.dumps(self.settings))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("CCS_", "CODEX_")) and "proxy" not in k.lower()}
        self.env.update(HOME=str(self.home), CODEX_HOME=str(self.home / ".codex"), NO_PROXY="*", no_proxy="*", PYTHONDONTWRITEBYTECODE="1")

    def close(self):
        self.server.close()
        self.tmp.cleanup()

    def commands(self, args):
        return [[sys.executable, str(Path(__file__).resolve()), "--python", *args], [self.binary, *args]]

    def normalized_state(self, start, end, previous):
        if not self.state.exists():
            return None
        assert self.state.stat().st_mode & 0o777 == 0o600, "state permission"
        raw = self.state.read_text()
        value = json.loads(raw)
        assert raw == json.dumps(value, sort_keys=True, indent=1), "state serialization"
        for entry in value["files"].values():
            stamp = entry.get("last_ok")
            if stamp and stamp != "old-stamp":
                epoch = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
                assert stamp in previous or start - 1 <= epoch <= end + 1, "last_ok outside call window"
                entry["last_ok"] = "<call-time>"
        return json.dumps(value, sort_keys=True, indent=1)

    def capture(self, command, handler, env=None, closed_stderr=False):
        self.server.requests.clear()
        self.server.handler = handler
        previous = {e.get("last_ok") for e in json.loads(self.state.read_text()).get("files", {}).values()} if self.state.exists() and isinstance(json.loads(self.state.read_text()).get("files"), dict) else set()
        started = time.time()
        result = subprocess.run(command, env=env or self.env, cwd=self.home,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                preexec_fn=(lambda: os.close(2)) if closed_stderr else None, timeout=40)
        state = self.normalized_state(started, time.time(), previous)
        requests = []
        for req in self.server.requests:
            headers = {k.lower(): v for k, v in req["headers"].items()}
            relevant = {k: headers.get(k) for k in ("content-type", "content-encoding", "accept", "user-agent", "authorization")}
            raw = req["raw"]
            zipped = raw[:2] == b"\x1f\x8b"
            if req["path"].endswith(("/ingest", "/blob")):
                assert zipped and relevant["content-encoding"] is None, "gzip transport contract"
            body = gzip.decompress(raw) if zipped else raw
            if req["path"].endswith("/ingest"):
                import hashlib
                seg = req["body"]["segment"]
                assert seg["sha256"] == hashlib.sha256(("\n".join(seg["lines"]) + "\n").encode()).hexdigest(), "segment digest"
            requests.append((req["method"], req["path"], relevant, body))
        return {"exit": result.returncode, "stdout": result.stdout, "state": state, "requests": requests}

    def pair(self, label, args=None, factory=lambda: ok, env=None, closed_stderr=False):
        args = args or ["file", str(self.path)]
        initial = self.state.read_bytes() if self.state.exists() else None
        results = []
        for command in self.commands(args):
            if initial is None:
                self.state.unlink(missing_ok=True)
            else:
                self.state.write_bytes(initial)
            results.append(self.capture(command, factory(), env, closed_stderr))
        expected, got = results
        record_comparison(label, expected, got)
        for key in expected:
            assert got[key] == expected[key], "%s: %s mismatch\nPython=%r\nRust=%r" % (label, key, repr(expected[key])[:2000], repr(got[key])[:2000])
        print("PASS", label, "requests=%d exit=%d state=%s" % (len(got["requests"]), got["exit"], "exact" if got["state"] else "absent"), flush=True)
        return got

    def reset(self):
        self.state.unlink(missing_ok=True)

    def seed(self, **changes):
        st = self.path.stat()
        entry = {"dev": st.st_dev, "inode": st.st_ino, "size": st.st_size, "offset": 0,
                 "generation": 2, "session_key": "sk_old", "last_ok": "old-stamp", "unknown": {"keep": "日本"}}
        entry.update(changes)
        self.state.write_text(json.dumps({"version": 1, "files": {str(self.path): entry}, "future": [1, "keep"]}))
        self.state.chmod(0o600)


def scripted(status, body, repeats=1):
    def factory():
        count = 0
        def handler(req):
            nonlocal count
            if req["path"].endswith("/ingest"):
                count += 1
                if count <= repeats:
                    return status, body, {}
            return ok(req)
        return handler
    return factory


def suite(binary, selected=None):
    def run(label, callback):
        if selected and selected != label:
            return
        fixture = Fixture(binary)
        try:
            callback(fixture)
        finally:
            fixture.close()

    def basics(f):
        f.path.write_bytes(LINE + b'\n \t\r\v\f\n' + b'not-json ' + SECRET.encode() + b'\xff\n' + b'{"n":NaN,"v":1e400,"same":1,"same":2}\n' + b'{"emoji":"\\ud83d\\ude00"}\n')
        f.pair("mask-record-text-invalid-utf8-nonfinite-duplicate-unicode")
        f.pair("unchanged")
        f.path.write_bytes(f.path.read_bytes() + b'partial ' + SECRET.encode())
        f.pair("partial-last-line")
        with f.path.open("ab") as stream:
            stream.write(b' completed\n')
        f.pair("completed-last-line")
    run("basics", basics)

    def diff(f):
        for name, changes in [("preserve-unknown", {}), ("dev-change", {"dev": -1}),
                              ("inode-change", {"inode": 0}), ("truncate", {"offset": 10000}),
                              ("append", {"offset": len(LINE)}), ("zero-length", {})]:
            f.path.write_bytes(b'' if name == "zero-length" else LINE * 2)
            f.seed(**changes)
            f.pair(name)
        f.state.write_text('{"version":9,"files":[]}')
        f.pair("invalid-state-reset")
        f.path.write_bytes(LINE)
        f.seed(offset=len(LINE))
        state = json.loads(f.state.read_text()); state['version'] = 1.0
        f.state.write_text(json.dumps(state))
        f.pair("numeric-state-version")
    run("diff", diff)

    def segments(f):
        f.path.write_bytes((b'{"x":"' + b'a' * 19000 + b'"}\n') * 230)
        f.pair("4MiB-segments")
        f.reset()
        f.path.write_bytes(b'x' * (4 * 1024 * 1024 + 10) + b'\n' + LINE)
        f.pair("oversize-line")
        f.reset()
        f.path.write_bytes(b'x' * (4 * 1024 * 1024 + 10))
        f.pair("oversize-partial-line")
    run("segments", segments)

    def statuses(f):
        f.path.write_bytes(LINE * 4)
        cases = [("409-resync", 409, {"expected_offset": len(LINE)}, 1),
                 ("409-beyond-eof", 409, {"expected_offset": 999999}, 1),
                 ("409-no-converge", 409, {"expected_offset": 0}, 4),
                 ("409-invalid", 409, {"expected_offset": -1}, 1),
                 ("409-missing", 409, {}, 1),
                 ("413-halving", 413, {}, 2),
                 ("422-lines-offsets", 422, {"lines": [1, 3], "kinds": ["example"]}, 1),
                 ("422-unicode-kinds", 422, {"lines": [0], "kinds": ["日本"]}, 1),
                 ("422-string-kinds", 422, {"lines": [0], "kinds": "kind"}, 1),
                 ("422-invalid-kinds", 422, {"lines": [0], "kinds": 7}, 1),
                 ("422-invalid-index", 422, {"lines": [9], "kinds": []}, 1),
                 ("422-empty", 422, {"lines": []}, 1),
                 ("422-repeated", 422, {"lines": [0]}, 3),
                 ("500-hold", 500, {"error": "rejected"}, 1),
                 ("200-invalid-next", 200, {"next_offset": -1}, 1),
                 ("200-nonstring-key", 200, {"session_key": 42}, 1)]
        for label, status, body, count in cases:
            f.reset()
            f.pair(label, factory=scripted(status, body, count))
        f.path.write_bytes(LINE)
        for label, count in [("413-single-tombstone", 1), ("413-tombstone-refused", 2)]:
            f.reset()
            f.pair(label, factory=scripted(413, {}, count))
        f.reset()
        f.pair("empty-success", factory=scripted(204, b''))
        f.reset()
        f.pair("invalid-response-json", factory=scripted(200, b'{broken'))
        f.reset()
        f.path.write_bytes(b' \t\r\n\n')
        f.pair("blank-only-segment")
    run("statuses", statuses)

    def blobs(f):
        directory = f.path.with_suffix("") / "tool-results"
        directory.mkdir(parents=True)
        blob = directory / "toolu_01ABC.txt"
        blob.write_bytes(b"blob " + SECRET.encode() + b'\xff')
        (directory / "bad name.txt").write_text("not shipped")
        (directory / "toolu_BIG.txt").write_bytes(b'x' * (4 * 1024 * 1024 + 1))
        f.pair("blob-first-mask")
        f.pair("blob-dedup")
        blob.write_text("changed " + SECRET)
        f.pair("blob-changed")
        f.seed(inode=0, blobs={blob.name: "invalid-old-hash"})
        f.pair("blob-generation-reset")
        blob.write_text("failure")
        def fail(req):
            return (503, {}, {}) if req["path"].endswith("/blob") else ok(req)
        f.pair("blob-refused", factory=lambda: fail)
        f.pair("blob-retry")
    run("blobs", blobs)

    def discovery(f):
        sub = f.path.with_suffix("") / "subagents/agent-test.jsonl"
        sub.parent.mkdir(parents=True)
        sub.write_bytes(LINE)
        older = f.project / (SID2 + ".jsonl")
        older.write_bytes(LINE)
        os.utime(older, (100, 100)); os.utime(f.path, (200, 200)); os.utime(sub, (300, 300))
        for mode in ("backfill", "sweep"):
            f.reset(); f.pair(mode, [mode])
        f.reset(); f.pair("with-subagents", ["file", str(f.path), "--with-subagents"])
        f.reset(); f.pair("subagent-alone", ["file", str(sub)])
        f.seed(); f.path.unlink()
        f.pair("gone-backfill-held", ["backfill"])
        for status in (500, 404, 200):
            f.pair("gone-sweep-%d" % status, ["sweep"], factory=lambda s=status: lambda req: (s, {}, {}) if req["path"].endswith("/state") else ok(req))
    run("discovery", discovery)

    def safety(f):
        target = f.project / (SID2 + ".jsonl")
        target.write_bytes(LINE)
        f.path.unlink(); f.path.symlink_to(target)
        f.pair("symlink-file")
        f.path.unlink(); os.mkfifo(f.path)
        f.pair("fifo-file")
        f.path.unlink(); f.path.write_bytes(LINE)
        side = f.path.with_suffix("")
        side.mkdir(); (side / "tool-results").symlink_to(f.home, target_is_directory=True)
        f.pair("symlink-blob-directory")
        f.pair("outside-root", ["file", str(f.home / "outside.jsonl")])
        f.pair("missing-transcript", ["file", str(f.project / "missing.jsonl")])
        f.reset(); f.pair("closed-stderr", closed_stderr=True)
        f.reset(); f.pair("quiet", ["file", str(f.path), "--quiet"])
    run("safety", safety)

    def configuration(f):
        f.key.unlink(); f.pair("missing-key")
        f.key.write_bytes(b' \t\r\n'); f.pair("empty-key")
        f.config.write_text('{'); f.pair("invalid-config")
        f.config.unlink(); f.pair("unconfigured")
        f.config.write_text(json.dumps(f.settings)); f.key.write_bytes(b'key')
        env = dict(f.env, HOME=f.env['HOME'] + '///')
        f.pair("home-trailing-slash", env=env)
        f.reset()
        import socket
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0))
            port = unused.getsockname()[1]
        settings = dict(f.settings, endpoint='http://127.0.0.1:%d' % port)
        f.config.write_text(json.dumps(settings))
        f.pair("unreachable-cursor-held")
    run("configuration", configuration)

    def codex(f):
        native = f.home / ".codex/sessions/2026/01/01" / ("rollout-2026-01-01T00-00-00-" + SID + ".jsonl")
        native.parent.mkdir(parents=True)
        native.write_text(json.dumps({"type": "session_meta", "payload": {"id": SID, "cwd": "/work/demo", "source": "cli"}}) + '\n' + LINE.decode())
        f.pair("codex-capability", ["file", str(native)])
        f.reset()
        f.pair("codex-deferred", ["file", str(native)], factory=lambda: lambda req: (200, {"sources": ["claude"]}, {}) if req["path"].endswith("/status") else ok(req))
        f.reset()
        f.pair("codex-capability-failed", ["file", str(native)], factory=lambda: lambda req: (503, {}, {}) if req["path"].endswith("/status") else ok(req))
    run("codex", codex)

    def surrogates(f):
        f.path.write_bytes(b'{"text":"\\ud800"}\n{"\\udfff":"v"}\n')
        f.pair("surrogates-tombstoned")
    run("surrogates", surrogates)

    def lock(f):
        path = f.state.parent / 'lock'
        with path.open('a') as holder:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            f.pair("live-python-lock-holder")
        f.pair("released-holder")
        f.reset()
        code = 'import fcntl,sys,time; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); time.sleep(30)'
        holder = subprocess.Popen([sys.executable, '-c', code, str(path)], stdout=subprocess.PIPE)
        try:
            assert holder.stdout.readline() == b'locked\n'
            holder.kill(); holder.wait(); holder.stdout.close()
            f.pair("dead-lock-holder")
        finally:
            if holder.poll() is None: holder.kill(); holder.wait()
    run("lock", lock)

    def concurrent(f):
        # Observe the lock while the first Rust/Python worker is inside HTTP.
        for first in f.commands(['file', str(f.path)]):
            f.reset()
            entered = threading.Event(); release = threading.Event()
            def slow(req):
                if len(f.server.requests) == 1:
                    entered.set()
                    assert release.wait(15), 'concurrent release timeout'
                return ok(req)
            f.server.requests.clear(); f.server.handler = slow
            process = subprocess.Popen(first, env=f.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert entered.wait(10), 'first worker did not send'
                for second in f.commands(['file', str(f.path)]):
                    result = subprocess.run(second, env=f.env, capture_output=True, timeout=5)
                    assert result.returncode == 0 and result.stdout == b'', 'concurrent worker bypassed lock'
                assert len(f.server.requests) == 1, 'concurrent duplicate request'
            finally:
                release.set()
                out, err = process.communicate(timeout=10)
            assert process.returncode == 0, (out, err)
        print('PASS concurrent-python-rust-and-rust-python receiving requests=1', flush=True)
    run("concurrent", concurrent)

    def deviations(f):
        cases = [('D2-overwritten-surrogate', b'{"v":"\\ud800","v":"ok"}\n', 'surrogate'),
                 ('D3-depth65', b'[' * 64 + b'0' + b']' * 64 + b'\n', 'too-deep'),
                 ('D3-integer4301', b'{"n":' + b'7' * 4301 + b'}\n', 'invalid-json'),
                 ('D3-recursion', b'[' * 12000 + b'0' + b']' * 12000 + b'\n', 'too-deep')]
        for label, raw, reason in cases:
            f.path.write_bytes(raw); f.reset()
            py = f.capture(f.commands(['file', str(f.path)])[0], ok)
            f.reset()
            rust = f.capture(f.commands(['file', str(f.path)])[1], ok)
            record_comparison(label, py, rust)
            assert rust['exit'] == 0 and len(rust['requests']) == 1, label
            body = json.loads(rust['requests'][0][3]); segment = body['segment']
            assert segment['lines'] == [ingest._tomb_line(reason, [], 0)], label
            assert segment['end_offset'] == len(raw), label
            assert json.loads(rust['state'])['files'][str(f.path)]['offset'] == len(raw), label
            if label == 'D3-recursion':
                assert py['exit'] == 1 and not py['requests'], label
            else:
                assert py['exit'] == 0 and len(py['requests']) == 1, label
                python_body = json.loads(py['requests'][0][3])
                # Only the guarded line and its SHA differ at this boundary.
                python_body['segment']['lines'] = segment['lines']
                python_body['segment']['sha256'] = segment['sha256']
                assert python_body == body, label
                assert py['state'] == rust['state'], label
                pstats = json.loads(py['stdout'].decode().removeprefix('ccs ingest: '))
                rstats = json.loads(rust['stdout'].decode().removeprefix('ccs ingest: '))
                assert rstats.pop('tombstones') == 1 and pstats.pop('tombstones') == 0
                assert rstats == pstats
            print('PASS', label, 'exact guarded tombstone; cursor advanced', flush=True)
        f.reset()
        f.path.write_bytes(b'[' * 80 + b'0' + b']' * 79 + b' invalid\n')
        f.pair('deep-invalid-json-text-route')
    run('deviations', deviations)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=REPO / 'target/release/examples/ingest_probe')
    parser.add_argument('--case')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    global EVIDENCE
    EVIDENCE = args.evidence
    if EVIDENCE:
        EVIDENCE.write_text('')
    suite(args.binary.resolve(), args.case)
    print('PASS ingest Python function oracle', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--python':
        raise SystemExit(python_main(sys.argv[2:]))
    main()
