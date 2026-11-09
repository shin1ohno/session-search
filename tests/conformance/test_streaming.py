#!/usr/bin/env python3
"""Require actual differences, complete equal streams, and distinct runner errors."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
binary=str(ROOT/'target/release/ccs')
source=(ROOT/'tests/conformance/structgen.py').read_text()
ns=dict(os=os,json=json,subprocess=subprocess,tempfile=tempfile,binary=binary,norm=lambda r,g:g)
start=source.index('def first_diff(')
end=source.index('\n\nt0 = ',start)
exec(compile(source[start:end],'<streaming comparison>','exec'),ns)
first_diff=ns['first_diff']
reqs=[{'mode':'text','input':'plain'} for _ in range(10000)]
payload=''.join(json.dumps(r)+'\n' for r in reqs).encode()
expected=json.dumps({'out':'plain','counts':{}},sort_keys=True)
assert first_diff((payload,reqs,[expected]*len(reqs)),None)==0
assert first_diff((payload,reqs,[json.dumps({'wrong':True})]+[expected]*(len(reqs)-1)),None)==1
with tempfile.TemporaryDirectory() as work:
    bad=Path(work)/'bad'
    for code in ['exit 0','exit 7',"printf 'not-json\\n'", "printf '{}\\n'; exit 0"]:
        bad.write_text('#!/bin/sh\n'+code+'\n');bad.chmod(0o755)
        result=first_diff((payload,reqs,[expected]*len(reqs)),{'CCS_MUTANT_BINARY':str(bad)})
        # Missing or malformed protocol rows are errors, not mutation detections.
        assert result == -1,(code,result)
print('PASS streaming comparison: equality, early witness, empty/error/malformed output')
