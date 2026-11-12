"""Observable process safety and additional local-reader integration cases."""
import json
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

from contract.harness import ClientCase, FakeServer, SID, user, assistant


class LocalReading(ClientCase):
    def test_local_preview_reads_replacement_utf8_and_last_four_messages(self):
        path = self.transcript([user("old"), assistant("first"), user("second"), assistant("third"), user("fourth")])
        with open(path, "ab") as out:
            out.write(b'{"type":"assistant","message":{"role":"assistant","content":"invalid \\ufffd"}}\n'.replace(b'\\ufffd', b'\xff'))
        data = json.loads(self.good("preview", "local:" + path).stdout)
        self.assertEqual([s["fragment"] for s in data["snippets"]], ["second", "third", "fourth", "invalid \ufffd"])
        self.assertEqual(data["session"]["session_id"], SID)
        self.assertEqual(data["session"]["agent"], "claude")

    def test_casefold_local_reading_and_host_filter(self):
        record = user("Straße Σίσυφος", cwd="/work")
        record["prefilter"] = "STRASSE"
        self.transcript([record])
        self.write_config("http://127.0.0.1:9")
        data = self.local_search("STRASSE")
        self.assertEqual(len(data["sessions"]), 1)
        self.assertEqual(data["sessions"][0]["hit_count"], 1)
        self.assertEqual(self.local_search("STRASSE", "--host", "other")["sessions"], [])

    def test_structured_search_forwards_filters_and_excludes_self(self):
        srv = FakeServer(lambda req: (200, {"sessions": [
            {"session_key": "self", "session_id": SID},
            {"session_key": "other", "session_id": "other", "entrypoint": "codex-cli"}]}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        result = self.good("search", "  q  word  ", "--deep", "--semantic", "--all", "--sidechain",
                           "--here", "--host", "pro-dev", "--host", "mini", "--since", "30m", "--limit", "1",
                           env={"CLAUDE_CODE_SESSION_ID": SID})
        self.assertEqual(json.loads(result.stdout)["sessions"], [
            {"session_key": "other", "session_id": "other", "entrypoint": "codex-cli", "agent": "codex"}])
        body = srv.of("/search")[0]["body"]
        self.assertEqual({k: body[k] for k in ("q", "mode", "deep", "include_headless", "include_sidechain", "hosts", "cwd_prefix", "limit")},
                         {"q": "q  word", "mode": "hybrid", "deep": True, "include_headless": True,
                          "include_sidechain": True, "hosts": ["pro-dev", "mini"], "cwd_prefix": self.tmp, "limit": 2})
        from datetime import datetime, timezone
        since = datetime.fromisoformat(body["since"].replace("Z", "+00:00")).timestamp()
        self.assertAlmostEqual(since, time.time() - 1800, delta=5)

    def test_status_counts_lag_untracked_subagents_and_last_errors(self):
        path = self.transcript([user("hello")])
        sub = Path(path).with_suffix("") / "subagents"
        sub.mkdir(parents=True)
        (sub / "agent-abc.jsonl").write_text("{}\n")
        self.state_path.write_text(json.dumps({"version": 1, "files": {path: {"offset": 3}}}))
        self.log_path.write_text("\n".join("date WARN message%d" % i for i in range(12)) + "\n")
        output = self.good("status").stdout
        self.assertIn("cursor lag: %d bytes over 1 tracked files; 1 files never shipped" % (Path(path).stat().st_size - 3), output)
        self.assertEqual(output.split("last errors:\n")[1], "".join("  date WARN message%d\n" % i for i in range(4, 12)))

    def test_status_reads_numeric_version_and_offset_types(self):
        path = self.transcript([user("hello")])
        for version, offset, numeric in ((1.0, 3.9, 3), (True, True, 1), (1, "3", 3),
                                          (1, " +١_٠ ", 10), (1, "\u2003３\u2003", 3)):
            self.state_path.write_text(json.dumps({"version": version, "files": {path: {"offset": offset}}}))
            output = self.good("status").stdout
            self.assertIn("cursor lag: %d bytes over 1 tracked files" % (Path(path).stat().st_size - numeric), output)
        self.state_path.write_text(json.dumps({"version": 1, "files": {path: {"offset": None}}}))
        self.assertEqual(self.run_ccs("status").returncode, 1)

    def test_json_stdout_preserves_surrogateescape_and_rejects_other_surrogates(self):
        path = self.transcript([user("first")])
        for escape, expected_code, expected_byte in (("\\udc80", 0, b"\x80"), ("\\ud800", 1, None)):
            Path(path).write_text('{"type":"user","message":{"content":"title ' + escape + '"}}\n')
            result = subprocess.run(self.command + ["preview", "local:" + path], cwd=self.tmp, env=self.env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, expected_code)
            if expected_byte:
                self.assertIn(expected_byte, result.stdout)

    def test_toggle_reads_prompt_before_fallback_and_rejects_invalid_utf8(self):
        state = Path(self.tmp) / "prompt"
        state.write_bytes(b"\xff")
        result = self.run_ccs("_toggle", "s", env={"CCS_PICK_STATE": str(state), "FZF_PROMPT": "invalid"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.good("_toggle", "s", env={"CCS_PICK_STATE": str(state), "FZF_PROMPT": "ccs:d> "}).stdout,
                         "ccs:sd> \n")
        for value, expected in (({"flags": ["d"]}, "ccs:sd> \n"), ({"flags": {"a": 1}}, "ccs:sa> \n"),
                                ({"flags": 2}, None), ([], None)):
            result = self.run_ccs("_toggle", "s", env={"CCS_PICK": json.dumps(value)})
            self.assertEqual(result.returncode, 0 if expected else 1)
            if expected:
                self.assertEqual(result.stdout, expected)


class DispatchAdapter(ClientCase):
    def test_empty_ingest_file_uses_python_truthiness(self):
        from contract.test_ingest import ok_handler
        srv = FakeServer(ok_handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        self.transcript([user("dispatch fixture")])
        self.assertEqual(self.run_ccs("ingest", "--file", "", "--with-subagents").returncode, 2)
        self.assertEqual(srv.requests, [])
        self.good("ingest", "--file", "", "--quiet")
        self.assertEqual(len(srv.of("/ingest")), 1)

    def test_invalid_tool_name_warning_matches_python_repr(self):
        from contract.test_ingest import ok_handler
        srv = FakeServer(ok_handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        path = Path(self.transcript([user("blob fixture")]))
        directory = path.with_suffix("") / "tool-results"
        directory.mkdir(parents=True)
        names = [".hidden", "quote'name", "line\nbreak", "space\u00a0", "format\u200b",
                 "space\u2003", "line\u2028", "paragraph\u2029", "astral\U0001f680",
                 "private\U000f0001", "." + "a" * 100]
        for name in names:
            (directory / name).write_text("skip")
        raw_name_supported = True
        with self.subTest(filename="non-UTF-8 filesystem bytes"):
            try:
                (directory / "surrogate\udc80").write_text("skip")
            except OSError as error:
                # APFS rejects this name before either client can read it.
                self.assertEqual(sys.platform, "darwin")
                self.assertEqual(error.errno, errno.EILSEQ)
                raw_name_supported = False
                self.skipTest("filesystem rejects non-UTF-8 filename with EILSEQ; UTF-8 repr cases still run")
        self.good("ingest", "--file", str(path), "--quiet")
        lines = self.log_path.read_text().splitlines()
        for name in names:
            warning = "ingest: tool-results name %r does not match ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$; not sent" % name[:80]
            with self.subTest(name=name):
                self.assertTrue(any(line.endswith(warning) for line in lines), warning)
        if not raw_name_supported:
            self.assertFalse(any("non-UTF-8 name skipped" in line for line in lines))
        elif os.environ.get("CCS_RUST_CLIENT") == "1":
            # D5 rejects the raw non-UTF-8 filename before the repr formatter.
            self.assertEqual(sum("non-UTF-8 name skipped" in line for line in lines), 1)
        else:
            self.assertTrue(any("'surrogate\\udc80' does not match" in line for line in lines))
        self.assertEqual(srv.of("/blob"), [])


@unittest.skipUnless(os.environ.get("CCS_RUST_CLIENT") == "1", "Rust A2/D6 process boundary")
class ProcessBoundary(ClientCase):
    def test_stdout_closed_pipe_is_sigpipe_without_traceback(self):
        srv = FakeServer(lambda req: (200, {"sessions": [], "padding": "x" * 300000}, {}))
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = subprocess.run(self.command + ["search", "query"], env=self.env, cwd=self.tmp,
                                    stdout=write_fd, stderr=subprocess.PIPE, timeout=10)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode, -signal.SIGPIPE)
        self.assertEqual(result.stderr, b"")

    def test_closed_stderr_keeps_usage_status(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = subprocess.run(self.command + ["--no-such-flag"], env=self.env, cwd=self.tmp,
                                    stdout=subprocess.PIPE, stderr=write_fd, timeout=10)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode, 2)

    def test_resume_closed_stderr_pipe_preserves_internal_error_status(self):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(self.command + ["resume", "local:/nonexistent/x.jsonl"],
                                    cwd=self.tmp, env=self.env, stdout=subprocess.PIPE,
                                    stderr=writer, timeout=10)
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, 1, "resume diagnostic was terminated by SIGPIPE")

    def test_conformance_closed_stderr_pipe_preserves_failure_status(self):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            for suite in ("redact", "codex"):
                result = subprocess.run(self.command + ["_conformance", suite], input=b"",
                                        cwd=self.tmp, env=self.env, stdout=subprocess.PIPE,
                                        stderr=writer, timeout=10)
                self.assertEqual(result.returncode, 1, suite)
                self.assertEqual(result.stdout, b"")
        finally:
            os.close(writer)

    def test_core_dumps_disabled_before_credential_acquisition(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        def handler(req):
            if req["path"] != "/token":
                return 200, {"ok": True}, {}
            entered.set()
            release.wait(5)
            return 200, {"access_token": "synthetic-core-probe", "expires_in": 0}, {}
        srv = FakeServer(handler)
        self.addCleanup(srv.close)
        self.write_config(srv.base)
        directory = Path(self.tmp) / ".config/session-search"
        secret = directory / "client.secret"
        secret.write_text("synthetic-client-secret")
        config = directory / "config.json"
        data = json.loads(config.read_text())
        data["auth"] = {"type": "client_credentials", "client_id": "probe", "secret_file": str(secret), "token_url": srv.base + "/token"}
        config.write_text(json.dumps(data))
        import resource
        self.assertNotEqual(resource.getrlimit(resource.RLIMIT_CORE)[1], 0,
                            "test needs a positive inherited hard core limit")
        def enable_core_for_probe():
            _, hard = resource.getrlimit(resource.RLIMIT_CORE)
            resource.setrlimit(resource.RLIMIT_CORE, (min(1048576, hard) if hard >= 0 else 1048576, hard))
        env = dict(self.env)
        observed = Path(self.tmp) / "core-observed"
        if sys.platform == "darwin":
            # Observe the running native process at its credential-open boundary.
            # exec inheritance is a separate contract: the agent gets its soft
            # limit back only after ccs has finished using its credentials.
            source = Path(self.tmp) / "core-observer.c"
            library = Path(self.tmp) / "core-observer.dylib"
            probe = Path(self.tmp) / "core-observer-probe"
            source.write_text(r'''
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
static void observe(const char *path) {
    const char *base = strrchr(path, '/');
    if (strcmp(base ? base + 1 : path, "client.secret")) return;
    struct rlimit limit;
    if (getrlimit(RLIMIT_CORE, &limit)) return;
    /* dyld exempts the interposing image's own references from replacement. */
    int fd = open(getenv("CCS_TEST_CORE_OBSERVED"), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    char result[] = "0 0\n";
    result[0] = limit.rlim_cur == 0 ? '1' : '0';
    result[2] = limit.rlim_max == (rlim_t)strtoull(getenv("CCS_TEST_CORE_HARD"), 0, 10) ? '1' : '0';
    (void)write(fd, result, sizeof(result) - 1);
    close(fd);
}
static int observed_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    observe(path);
    return open(path, flags, mode);
}
static int observed_openat(int dir, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    observe(path);
    return openat(dir, path, flags, mode);
}
#ifndef PROBE_MAIN
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)observed_open, (const void *)open},
    {(const void *)observed_openat, (const void *)openat}
};
#else
int main(int argc, char **argv) { int fd = open(argv[1], O_RDONLY); if (fd < 0) return 2; close(fd); return 0; }
#endif
''')
            subprocess.run(["/usr/bin/clang", "-dynamiclib", str(source), "-o", str(library)], check=True)
            subprocess.run(["/usr/bin/clang", "-DPROBE_MAIN", str(source), "-o", str(probe)], check=True)
            env.update(DYLD_INSERT_LIBRARIES=str(library), CCS_TEST_CORE_OBSERVED=str(observed),
                       CCS_TEST_CORE_HARD=str(resource.getrlimit(resource.RLIMIT_CORE)[1]))
            control = subprocess.run([str(probe), str(secret)], env=env, preexec_fn=enable_core_for_probe)
            self.assertEqual(control.returncode, 0)
            self.assertEqual(observed.read_text(), "0 1\n", "observer failed to detect enabled core dumps")
            observed.unlink()
        process = subprocess.Popen(self.command + ["status"], env=env, cwd=self.tmp,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=enable_core_for_probe)
        try:
            self.assertTrue(entered.wait(5), "token endpoint was not reached")
            if sys.platform == "darwin":
                self.assertEqual(observed.read_text(), "1 1\n", "credential-reading process has wrong core limits")
            else:
                limit = next(line for line in Path("/proc/%d/limits" % process.pid).read_text().splitlines() if line.startswith("Max core file size"))
                self.assertEqual(limit.split()[4], "0", "credential-reading process can dump its memory")
                hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
                self.assertEqual(limit.split()[5], "unlimited" if hard < 0 else str(hard))
        finally:
            release.set()
            output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0)
        self.assertNotIn(b"synthetic-core-probe", output + error)
        for path in Path(self.tmp).rglob("*"):
            if path.is_file() and not path.is_symlink():
                self.assertNotIn(b"synthetic-core-probe", path.read_bytes())

    def test_zsh_completion_is_generated(self):
        result = self.good("completion", "zsh")
        self.assertIn("#compdef ccs", result.stdout)
        for command in ("search", "preview", "resume", "ingest", "status", "purge"):
            self.assertIn(command, result.stdout)
