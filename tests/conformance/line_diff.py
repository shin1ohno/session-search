#!/usr/bin/env python3
"""Exact raw-line route, output, count and cursor comparison; no network."""
import argparse
import json
import random
import subprocess
from line_oracle import expected

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('binary')
p.add_argument('--count',type=int,default=20000)
a=p.parse_args()
rng=random.Random(20261110)
cases=[]
for depth in [1,2,63,64,65,66,127,128,129,130,500]:
    for leaf in ['0','"x"','"\\ud800"','{"password":"abcdefghij"}','{}','[]']:
        for op,cl in [('[',']'),('{"k":','}')]:
            s=op*(depth-1)+leaf+cl*(depth-1)
            cases.extend([s.encode(),(s+'x').encode(),s[:-1].encode()])
for s in ['NaN','Infinity','-Infinity','1e400','-0','-0.0','1e5','1e-6','1e16','01','1.','1e+','[1,]',
          '"\\ud800"','"\\ud83d\\ude00"','{"x":"\\ud800","x":0}','{"password":"abcdefghi","password":"x"}',
          '{"$serde_json::private::Number":"123"}', '\ufeff1','\u00851','', '   ']:
    cases.append(s.encode())
for n in [4299,4300,4301]:
    for sign in ['', '-']:
        cases.append(('{"n":'+sign+'1'*n+'}').encode())
fragments=['{"password":"abcdefghijk"}','"secret=abcdefghij"','"\\ud800"','[1,2,3]','null','true','1e400','"é"','0','"x"']
for _ in range(a.count):
    s=rng.choice(fragments).encode()
    if rng.random()<0.7:
        i=rng.randrange(len(s)+1)
        s=s[:i]+bytes([rng.randrange(256)])+s[i:]
    if b'\n' not in s: cases.append(s)
req=''.join(json.dumps({'mode':'line','hex':s.hex(),'off':1000+i})+'\n' for i,s in enumerate(cases))
r=subprocess.run([a.binary,'_conformance','redact','--requests'],input=req,text=True,capture_output=True,check=True)
rows=[json.loads(x) for x in r.stdout.splitlines()]
assert len(rows)==len(cases)
bad=[]
for i,(raw,got) in enumerate(zip(cases,rows)):
    e=expected(raw,1000+i)
    want={'out':e['output'],'counts':e['counts'],'route':e['route']}
    if got!=want:
        bad.append(i)
        if len(bad)<=10: print('line mismatch: index=%d route=%s expected_route=%s'%(i,got['route'],e['route']))
# Extreme valid and malformed nesting are constructed directly; Python recursion
# limits do not determine the input's JSON grammar.
for depth in [1000,10000,100000]:
    for valid in [True,False]:
        s='['*depth+'0'+']'*depth+('' if valid else 'x')
        r=subprocess.run([a.binary,'_conformance','redact','--requests'],input=json.dumps({'mode':'line','hex':s.encode().hex(),'off':1})+'\n',text=True,capture_output=True,check=True)
        got=json.loads(r.stdout)
        assert got['route']==('tombstone' if valid else 'text')
        if valid:
            assert json.loads(got['out'])=={'type':'session-search-tombstone','reason':'too-deep','kinds':[],'line_offset':1}
            assert got['counts']=={}
print('line differential: cases=%d extreme=6 failures=%d'%(len(cases),len(bad)))
assert not bad
