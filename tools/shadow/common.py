"""Shared pieces of the S3 shadow comparison (real data, no real send).

Every report written here holds counts, reasons and sha256 digests only; no
transcript text, masked line or query string leaves the temporary directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRUB_PREFIXES = ("CCS_", "CODEX_", "FZF_")
SCRUB_NAMES = {"CLAUDE_CODE_SESSION_ID", "LC_ALL", "LC_CTYPE", "PYTHONPATH", "PYTHONHOME"}


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    return hashlib.sha256(data).hexdigest()


MARKER = ".shadow-snapshot"


def writable_ancestor(path: Path) -> Path | None:
    """The first directory from path upwards that Rust's token cache would refuse, or None.

    Mirrors crates/ccs/src/token.rs Directory::open: an ancestor owned by
    another non-root user, or group- or other-writable unless it is a
    root-owned sticky directory such as /tmp. Under such a directory Rust runs
    without its disk token cache and warns on stderr, which real hosts never do.
    """
    uid = os.getuid()
    for p in [path, *path.parents]:
        st = os.stat(p)
        sticky_root = st.st_uid == 0 and st.st_mode & 0o1000
        if st.st_uid not in (uid, 0) or (st.st_mode & 0o022 and not sticky_root):
            return p
    return None


def require_snapshot(home: Path, source_home: Path | None = None) -> Path:
    """The resolved snapshot HOME; refuses the real HOME, any directory snapshot.py did not create,
    and a location whose permissions would change Rust's behaviour."""
    home = Path(home).resolve()
    real = {Path.home().resolve(), Path(os.path.expanduser("~")).resolve()}
    if source_home is not None:
        real.add(Path(source_home).resolve())
    if home in real or not (home / MARKER).is_file():
        raise SystemExit("refusing %s: not a snapshot made by tools/shadow/snapshot.py" % sha(str(home))[:12])
    bad = writable_ancestor(home)
    if bad is not None:
        raise SystemExit("refusing: %s is writable by others (mode %o), so Rust would skip its token cache; "
                         "chmod it 0700 or move the snapshot" % (bad, os.stat(bad).st_mode & 0o7777))
    return home


def real_rg() -> str:
    """The rg executable itself; a mise shim fails once HOME points elsewhere."""
    found = os.environ.get("SHADOW_RG") or shutil.which("rg")
    if not found:
        raise SystemExit("rg not found; set SHADOW_RG")
    if os.path.basename(os.path.realpath(found)) == "mise":
        found = subprocess.run(["mise", "which", "rg"], check=True, capture_output=True, text=True).stdout.strip()
    return os.path.realpath(found)


def environment(home: Path, config: Path | None = None) -> dict:
    """The contract harness environment (tests/contract/harness.py:42-78) on a given HOME."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(SCRUB_PREFIXES) and k not in SCRUB_NAMES and "proxy" not in k.lower()}
    bindir = home / ".shadow-bin"
    bindir.mkdir(mode=0o700, exist_ok=True)
    link = bindir / "rg"
    if not link.exists():
        link.symlink_to(real_rg())
    tmp = home / ".shadow-tmp"
    tmp.mkdir(mode=0o700, exist_ok=True)
    env.update(HOME=str(home), CODEX_HOME=str(home / ".codex"), LANG="C.UTF-8", NO_PROXY="*", no_proxy="*",
               PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(tmp), PATH="%s:/usr/bin:/bin" % bindir)
    if config is not None:
        env["CCS_CONFIG"] = str(config)
    return env


def python_command(python: str, share: str) -> list:
    """The deployed Python ccs, started the way the setup launcher starts it."""
    code = ("import sys; sys.path.insert(0, %r); from ccs.cli import main; sys.exit(main(sys.argv[1:]))" % share)
    return [python, "-I", "-c", code]


def implementations(args) -> dict:
    return {"python": python_command(args.python, args.share), "rust": [str(Path(args.rust).resolve())]}


def add_implementation_arguments(parser) -> None:
    parser.add_argument("--rust", required=True, help="Rust ccs binary under test")
    parser.add_argument("--python", required=True, help="interpreter of the deployed Python ccs")
    parser.add_argument("--share", default=os.path.expanduser("~/.local/share/session-search"),
                        help="directory holding the deployed ccs/ package")


def write_report(path: Path, report: dict) -> None:
    """Write a report and refuse anything but numbers, short labels and digests."""
    check_content_free(report)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


MAX_LABEL = 96


def check_content_free(value, where="report") -> None:
    """Strings in a report are labels or hex digests, never free text from the data."""
    if isinstance(value, dict):
        for k, v in value.items():
            check_content_free(k, where)
            check_content_free(v, "%s.%s" % (where, k))
    elif isinstance(value, (list, tuple)):
        for v in value:
            check_content_free(v, where)
    elif isinstance(value, str):
        if len(value) > MAX_LABEL or "\n" in value or not value.isascii():
            raise ValueError("%s: string is not a short ASCII label" % where)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("%s: unsupported report value %s" % (where, type(value).__name__))
