"""Rust-only token file extension; enable with CCS_AUTH_DISK_CACHE=1.

These use the same CLI entrypoint as the Python HTTP contract. No cache feature
is expected in Python. The environment opt-in must be set by the Rust CI job.
"""
import concurrent.futures
import fcntl
import json
import os
import resource
import platform
import signal
from pathlib import Path
import subprocess
import sys
import time
import unittest

from . import test_auth


@unittest.skipUnless(os.environ.get("CCS_AUTH_DISK_CACHE") == "1", "Rust disk-token extension")
class TokenCacheContract(test_auth.AuthContract):
    def prime(self):
        self.setup_auth()
        result = self.good("status")
        self.assertTrue(self.cache.is_file(), "Rust did not save the JWT-shaped bearer")
        self.assert_clean(result)
        return json.loads(self.cache.read_text())

    def test_reuses_private_cache_and_persistent_lock(self):
        self.prime()
        lock = self.cdir / "token.lock"
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
        inode = lock.stat().st_ino
        self.assert_clean(self.good("status"))
        self.assertEqual(len(self.server.of("/token")), 1)
        self.assertEqual(lock.stat().st_ino, inode)

    def test_invalid_json_values_are_not_reused(self):
        original = self.prime()
        cases = [
            ("format", True), ("format", "1"), ("access_token", []),
            ("access_token", "eyJbad.\nvalue.signature"),
            ("expires_at", "999999999999"), ("expires_at", float("inf")),
            ("obtained_at", float("nan")), ("obtained_at", lambda: time.time() + 301),
            ("expires_at", time.time() + 99999), ("expires_at", time.time() - 1),
            ("endpoint", "https://different.example"), ("token_url", "https://different.example/token"),
            ("client_id", "different"), ("audience", "different"),
            ("credential_generation", "different"), ("euid", -1),
        ]
        for key, value in cases:
            with self.subTest(field=key):
                data = dict(original, **{key: value() if callable(value) else value})
                self.cache.write_text(json.dumps(data))
                before = len(self.server.of("/token"))
                self.assert_clean(self.good("status"))
                self.assertEqual(len(self.server.of("/token")), before + 1, "invalid cache reused")

    def test_wrong_mode_symlink_fifo_and_oversize_are_not_reused(self):
        self.prime()
        for case in ["mode", "symlink", "fifo", "size"]:
            with self.subTest(case=case):
                if case == "mode":
                    self.cache.chmod(0o644)
                elif case == "symlink":
                    self.cache.unlink()
                    self.cache.symlink_to(self.cdir / "nonexistent")
                elif case == "fifo":
                    self.cache.unlink()
                    os.mkfifo(str(self.cache), 0o600)
                else:
                    self.cache.write_bytes(self.cache.read_bytes().ljust(32769, b" "))
                before = len(self.server.of("/token"))
                self.assert_clean(self.good("status", timeout=8))
                self.assertEqual(len(self.server.of("/token")), before + 1)
                self.assertFalse(self.cache.is_symlink())

    def test_rotated_or_unreadable_credential_cannot_reuse_cache(self):
        self.prime()
        secret = self.cdir / "client.secret"
        secret.write_text("rotated-test-secret")
        self.assert_clean(self.good("status"))
        self.assertEqual(len(self.server.of("/token")), 2)
        secret.unlink()
        before = len(self.server.of("/status"))
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.server.of("/status")), before)
        self.assert_clean(result)

    def test_401_cache_gone_changed_or_malformed(self):
        self.prime()
        for case in ["gone", "changed", "malformed"]:
            with self.subTest(case=case):
                calls = [0]
                def reject_first(req):
                    calls[0] += 1
                    if calls[0] == 1:
                        if case == "gone":
                            self.cache.unlink()
                        elif case == "changed":
                            data = json.loads(self.cache.read_text())
                            data["access_token"] = test_auth.synthetic(500)
                            self.cache.write_text(json.dumps(data))
                        else:
                            self.cache.write_text("[]")
                        return 401, {}, {}
                    return 200, {}, {}
                self.api_handler = reject_first
                before = len(self.server.of("/token"))
                self.assert_clean(self.good("status"))
                self.assertEqual(calls[0], 2)
                self.assertEqual(len(self.server.of("/token")), before + 1)
                sent = [test_auth.headers(req)["authorization"] for req in self.server.of("/status")[-2:]]
                self.assertTrue(sent[0] != sent[1], "rejected cached token sent twice")

    def test_second_rejected_token_is_removed(self):
        self.setup_auth(lambda req: (401, {}, {}))
        result = self.run_ccs("status")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.server.of("/status")), 2)
        self.assertFalse(self.cache.exists(), "second rejected bearer remains on disk")
        self.assert_clean(result)

    def test_simultaneous_processes_share_one_grant(self):
        self.setup_auth()
        self.grant_delay = 0.15
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.run_ccs("status"), range(6)))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_clean(result)
        diagnostics = {
            "states": [[line for line in result.stdout.splitlines() if line.startswith("token:")]
                       for result in results],
            "cache_warnings": ["token cache unavailable or unsafe" in result.stderr for result in results],
            "cache_diagnostics": [[line for line in result.stderr.splitlines()
                                   if line.startswith("ccs: token cache unavailable or unsafe;")]
                                  for result in results],
            "cache_exists": self.cache.is_file(),
            "lock_inode": (self.cdir / "token.lock").stat().st_ino,
        }
        self.assertEqual(len(self.server.of("/token")), 1, "refresh stampede: %r" % diagnostics)
        self.assertEqual(len(self.server.of("/status")), 6)

    def lock_open_fault(self):
        library = Path(self.tmp) / "lock-open-fault.so"
        apple = platform.system() == "Darwin"
        command = ["cc", "-dynamiclib" if apple else "-shared", "-fPIC",
                   str(Path(__file__).with_name("lock_open_fault.c")), "-o", str(library)]
        if not apple:
            command.append("-ldl")
        compiled = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        self.env["DYLD_INSERT_LIBRARIES" if apple else "LD_PRELOAD"] = str(library)

    def test_lock_create_enoent_keeps_single_grant(self):
        self.lock_open_fault()
        self.test_simultaneous_processes_share_one_grant()
        self.assertTrue((self.cdir / ".lock-fault").is_file(), "openat injection did not run")

    def test_persistent_lock_enoent_has_bounded_fallback(self):
        self.lock_open_fault()
        self.env["CCS_TEST_PERSISTENT_LOCK_ENOENT"] = "1"
        self.setup_auth()
        started = time.monotonic()
        result = self.good("status", timeout=5)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 2)
        self.assertLess(elapsed, 4)
        self.assertEqual(len(self.server.of("/token")), 1)
        self.assertIn("operation=lock, errno=Some(2), kind=NotFound", result.stderr)
        self.assertFalse(self.cache.exists())
        self.assert_clean(result)

    def test_dead_lock_holder_and_orphan_are_recovered(self):
        self.setup_auth()
        script = '''import fcntl, os, pathlib, sys, time
root = pathlib.Path(sys.argv[1])
f = os.open(root / 'token.lock', os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(f, fcntl.LOCK_EX)
t = os.open(root / '.token.123.00000000000000000000000000000000', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.write(t, sys.stdin.buffer.readline().strip())
os.close(t)
print('ready', flush=True)
time.sleep(30)
'''
        process = subprocess.Popen([sys.executable, "-c", script, str(self.cdir)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            process.stdin.write(test_auth.synthetic(900) + "\n")
            process.stdin.close()
            self.assertEqual(process.stdout.readline().strip(), "ready")
            self.issued.append(test_auth.synthetic(900))
            inode = (self.cdir / "token.lock").stat().st_ino
            process.kill()
            process.wait(timeout=5)
            self.assert_clean(self.good("status"))
            self.assertEqual((self.cdir / "token.lock").stat().st_ino, inode)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_lock_failure_preserves_bounded_401_recovery(self):
        self.prime()
        lock = self.cdir / "token.lock"
        lock.chmod(0o000)
        rejected = test_auth.headers(self.server.of("/status")[0])["authorization"]
        self.api_handler = lambda req: (401 if test_auth.headers(req).get("authorization") == rejected else 200, {}, {})
        for _ in range(2):
            before = len(self.server.of("/status"))
            self.assert_clean(self.good("status"))
            sent = self.server.of("/status")[before:]
            self.assertEqual(len(sent), 2)
            self.assertEqual(sum(test_auth.headers(r)["authorization"] == rejected for r in sent), 1)
        self.assertEqual(len(self.server.of("/token")), 3)

    def test_lock_timeout_fetches_without_saving(self):
        self.setup_auth()
        lock = self.cdir / "token.lock"
        with open(lock, "w") as handle:
            lock.chmod(0o600)
            fcntl.flock(handle, fcntl.LOCK_EX)
            start = time.monotonic()
            self.assert_clean(self.good("status", timeout=8))
            elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 1.8)
        self.assertLess(elapsed, 7)
        self.assertFalse(self.cache.exists())

    def test_rename_failure_still_sends_new_token(self):
        self.setup_auth()
        self.cache.mkdir()
        self.assert_clean(self.good("status"))
        self.assertEqual(len(self.server.of("/status")), 1)
        self.assertTrue(self.cache.is_dir())

    def test_file_size_limit_failure_still_sends_new_token(self):
        self.setup_auth()
        def limit_writes():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        result = subprocess.run(list(self.command) + ["status"], env=self.env,
                                cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=8, preexec_fn=limit_writes)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.server.of("/status")), 1)
        self.assertFalse(self.cache.exists())
        self.assert_clean(result)
