#!/usr/bin/env python3
"""Compare Python JSON acceptance and canonical bytes with the built reader/writer."""
import argparse
import json
import random
import struct
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('binary')
p.add_argument('--count',type=int,default=20000)
a=p.parse_args()
rng=random.Random(20261110)
cases=['-0','-0.0','1e-5','1e16','1e400','01','-NaN','[1,]','{"a":1,"a":2}',
       '"\\ud800"','"\\ud800\\udfff"','"\\ud800\\u0000"','"\\ud800\\uZZZZ"','\ufeff1']
cases += [json.dumps(chr(i)) for i in range(256)]
for _ in range(a.count):
    f=struct.unpack('>d',rng.randbytes(8))[0]
    cases.append(json.dumps(f))
for _ in range(a.count):
    s=rng.choice(cases[:270])
    at=rng.randrange(len(s)+1)
    cases.append(s[:at]+rng.choice('0129+-.eE{}[],:"\\ \r\t\nx')+s[at:])
req=''.join(json.dumps({'mode':'json','input':s})+'\n' for s in cases)
r=subprocess.run([a.binary,'_conformance','redact','--requests'],input=req,text=True,capture_output=True,check=True)
rows=[json.loads(x) for x in r.stdout.splitlines()]
assert len(rows)==len(cases)
bad=[]
for i,(s,row) in enumerate(zip(cases,rows)):
    try:
        expected={'ok':True,'output':json.dumps(json.loads(s),ensure_ascii=True,separators=(',',':'))}
    except ValueError:
        expected={'ok':False}
    if row!=expected:
        bad.append(i)
        if len(bad)<=5: print('JSON mismatch',i,repr(s),expected,row)
print('JSON differential: cases=%d failures=%d'%(len(cases),len(bad)))
assert not bad
