#!/usr/bin/env python3
"""Required S2 conformance gates, including rejection controls and generated mutants."""
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
BINARY=Path(sys.argv[1]).resolve()
OUT=ROOT/'target/conformance'
OUT.mkdir(parents=True,exist_ok=True)
PY=sys.executable
if sys.version_info[:2] != (3,13):
    raise SystemExit('conformance generation requires the pinned CPython 3.13 / Unicode 15.1 runtime')

def run(name,args,env=None,stdin=None,stdout=None):
    print('RUN',name,flush=True)
    with (OUT/(name+'.log')).open('w') as log:
        p=subprocess.run(args,cwd=ROOT,env=env,stdin=stdin,stdout=stdout or log,stderr=log)
    if p.returncode:
        print((OUT/(name+'.log')).read_text()[-4000:])
        raise SystemExit(name+' failed')
    print('PASS',name,flush=True)

server=ROOT/'vendor/memory-mcp'
corpus=server/'conformance/session_redact_r1.jsonl'
with corpus.open('rb') as source,(OUT/'emit.jsonl').open('wb') as output:
    run('corpus',[BINARY,'_conformance','redact','--emit'],stdin=source,stdout=output)
run('crosscheck',[PY,ROOT/'tools/check_conformance.py','--server',server,'--emit',OUT/'emit.jsonl'])
run('tables',[PY,ROOT/'tools/gen_redact_tables.py',server/'session_redact.py',OUT/'tables.rs',OUT/'mutants.json'])
assert (OUT/'tables.rs').read_bytes()==(ROOT/'crates/ccs-redact/src/tables.rs').read_bytes(),'generated tables drift'
run('streaming',[PY,HERE/'test_streaming.py'])
run('json',[PY,HERE/'json_diff.py',BINARY])
run('strict-json',[PY,HERE/'strict_json.py',BINARY])
run('lines',[PY,HERE/'line_diff.py',BINARY])
fuzz=1000000 if os.environ.get('GITHUB_EVENT_NAME') in ('schedule','workflow_dispatch') else 100000
run('differential',[PY,HERE/'differential.py',server/'session_redact.py',BINARY,OUT/'differential.jsonl',str(fuzz)])
run('negative',[PY,HERE/'negative_controls.py',OUT/'negative'])
run('build-mutants',[PY,HERE/'build_mutants.py',OUT,'--mutants',OUT/'mutants.json'])
env=dict(os.environ,CCS_MUTANT_BINARY=str(OUT/'ccs-mutants'))
run('structure',[PY,HERE/'structgen.py',server/'session_redact.py',BINARY,OUT/'mutants.json',OUT/'gate'],env=env)
run('equivalence',[PY,HERE/'classify_survivors.py',server/'session_redact.py',BINARY,OUT],env=env)
run('predicate',[PY,HERE/'predicate_soundness.py',server/'session_redact.py',BINARY,OUT],env=env)
print('PASS all conformance gates; artifacts: target/conformance',flush=True)
