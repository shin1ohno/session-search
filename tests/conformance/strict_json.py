#!/usr/bin/env python3
"""Exercise the real Python extraction duplicate policy against the Rust adapter."""
import ast
import json
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
tree=ast.parse((root/'ccs/extract.py').read_text())
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in {'DuplicateKey','_no_duplicates','loads_strict'}]
assert len(nodes)==3
ns={'json':json}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<extract strict loader>','exec'),ns)
base=['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"\\ud800":1,"\\ud800":2}',
      '{"a":1,"b":2}', '[NaN,Infinity,-Infinity]', '01', '"\\ud800"']
cases=[]
for s in base:
    for depth in [0,1,5,63]: cases.append('['*depth+s+']'*depth)
request=''.join(json.dumps({'mode':'json_strict','input':s})+'\n' for s in cases)
r=subprocess.run([sys.argv[1],'_conformance','redact','--requests'],input=request,text=True,capture_output=True,check=True)
rows=[json.loads(s) for s in r.stdout.splitlines()]
assert len(rows)==len(cases)
failures=[]
for i,(s,got) in enumerate(zip(cases,rows)):
    try: want={'ok':True,'output':json.dumps(ns['loads_strict'](s),ensure_ascii=True,separators=(',',':'))}
    except ns['DuplicateKey']: want={'ok':False,'duplicate':True}
    except ValueError: want={'ok':False}
    if got!=want: failures.append(i)
print('strict JSON Python extraction comparison: cases=%d failures=%d'%(len(cases),len(failures)))
assert not failures, 'strict duplicate mismatch: '+repr(failures)
