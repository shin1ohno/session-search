"""Frozen Python ingestion source plus the corpus's explicit D2/D3 contract."""
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SERVER=ROOT/'vendor/memory-mcp'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
G=module('line_vectors',SERVER/'conformance/gen_vectors.py')
SR=module('line_redactor',SERVER/'session_redact.py')
with (SERVER/'conformance/session_redact_r1.jsonl').open() as f: HEADER=json.loads(next(f))
ORACLE=G.line_oracle(HEADER['client_source'])
KEY=bytes.fromhex(HEADER['hmac_key_hex'])

def expected(raw,offset):
    value={'hex':raw.hex(),'offset':offset}
    py=G.line_result(ORACLE,SR,value,KEY)
    return G.rust_line_contract(ORACLE,value,py)[2]
