"""Negative controls for the CI runner's skip and opt-in enforcement."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("rust_contract_runner", ROOT / "tests/contract/run_rust.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Skipped(unittest.TestCase):
    def runTest(self):
        self.skipTest("injected absence of auth coverage")

    def id(self):
        return "contract.test_auth_cache.TokenCacheContract.test_reuses_private_cache_and_persistent_lock"


def check():
    env = {"CCS_UNDER_TEST": "unused", "CCS_AUTH_DISK_CACHE": "1", "CCS_RUST_CLIENT": "1"}
    with mock.patch.dict(os.environ, env), mock.patch.object(unittest.defaultTestLoader, "discover",
                                                          return_value=unittest.TestSuite([Skipped()])):
        with contextlib.redirect_stderr(io.StringIO()) as log:
            code = runner.main()
        assert code == 1, "auth skip unexpectedly passed CI"
        assert "FAIL forbidden Rust contract skip:" in log.getvalue()
        print("PASS negative auth skip fails the real CI result gate")
    for flag in ("CCS_AUTH_DISK_CACHE", "CCS_RUST_CLIENT", "CCS_UNDER_TEST"):
        with mock.patch.dict(os.environ, dict(env, **{flag: ""})):
            try:
                runner.main()
            except SystemExit as error:
                assert flag in str(error)
            else:
                raise AssertionError("missing flag unexpectedly passed: " + flag)
        print("PASS negative missing " + flag + " is rejected")


if __name__ == "__main__":
    check()
