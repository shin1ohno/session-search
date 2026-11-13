#!/usr/bin/env python3
"""Run the real Rust CLI contract, refusing missing opt-ins and auth skips."""
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


def forbidden_skip(test_id):
    return (".test_auth" in test_id or test_id.startswith("contract.test_auth")
            or "test_helper_pool" in test_id or "ProcessBoundary" in test_id
            or "test_helper_runs_without_curl" in test_id
            or "test_bind_failure_keeps_the_process_wiring" in test_id
            or "RustReview" in test_id or "RustHelperReview" in test_id)


def main():
    if not os.environ.get("CCS_UNDER_TEST"):
        raise SystemExit("CCS_UNDER_TEST must select the real Rust binary")
    for name in ("CCS_AUTH_DISK_CACHE", "CCS_RUST_CLIENT"):
        if os.environ.get(name) != "1":
            raise SystemExit(name + " must be 1")
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/contract"), top_level_dir=str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    for test, reason in result.skipped:
        print("SKIP %s: %s" % (test.id(), reason), file=sys.stderr)
    rejected = [(test.id(), reason) for test, reason in result.skipped if forbidden_skip(test.id())]
    for name, reason in rejected:
        print("FAIL forbidden Rust contract skip: %s: %s" % (name, reason), file=sys.stderr)
    print("Rust contract: tests=%d skips=%d forbidden_skips=%d" % (result.testsRun, len(result.skipped), len(rejected)), file=sys.stderr)
    return 0 if result.wasSuccessful() and not rejected else 1


if __name__ == "__main__":
    sys.exit(main())
