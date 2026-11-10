"""Run JSON requests against the production Rust library through a test adapter."""
import functools
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[3]
_BUILD_ENV = dict(os.environ)

@functools.cache
def executable():
    override = os.environ.get("CCS_ORACLE_PROBE")
    if override:
        return override
    result = subprocess.run(["cargo", "test", "--locked", "-p", "ccs", "--test", "local_probe",
                             "--no-run", "--message-format=json"], cwd=REPO, text=True,
                            stdout=subprocess.PIPE, check=True, env=_BUILD_ENV)
    artifacts = [json.loads(line) for line in result.stdout.splitlines()]
    return next(a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact"
                and a["target"]["name"] == "local_probe" and a.get("executable"))

def run_requests(requests, env=None):
    binary = executable()
    with tempfile.TemporaryDirectory(prefix="ccs-probe-") as tmp:
        source, destination = Path(tmp) / "requests", Path(tmp) / "responses"
        source.write_text("".join(json.dumps(r) + "\n" for r in requests))
        process_env = dict(os.environ if env is None else env,
                           CCS_ORACLE_REQUESTS=str(source), CCS_ORACLE_RESPONSES=str(destination))
        subprocess.run([binary, "--ignored", "--exact", "json_probe"], env=process_env,
                       stdout=subprocess.PIPE, check=True)
        result = [json.loads(line) for line in destination.read_text().splitlines()]
        assert len(result) == len(requests), (len(result), len(requests))
        return result
