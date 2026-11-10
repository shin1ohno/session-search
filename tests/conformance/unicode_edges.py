#!/usr/bin/env python3
"""Every Unicode class range edge and outside neighbour, for every redaction rule."""
import json
from pathlib import Path
import sys

source,binary,output=sys.argv[1:4]
here=Path(__file__).resolve().parent
sys.argv=['structgen.py',source,binary,output+'.unused',output+'.unicode','--no-mutants']
helpers=(here/'structgen.py').read_text().split('t0 = time.time()\nnames = list(G.TREES)')[0]
exec(compile(helpers,'structgen-helpers','exec'))


def nodes(seq,icase,ctx=()):
    for item in seq:
        op,av=item
        if op in CHAR:
            yield item,icase,ctx
        elif op in (C.MAX_REPEAT,C.MIN_REPEAT):
            yield from nodes(av[2],icase,ctx+((id(item),max(1,default_count(av[0],av[1]))),))
        elif op is C.BRANCH:
            for i,branch in enumerate(av[1]):
                yield from nodes(branch,icase,ctx+((id(item),i),))
        elif op is C.SUBPATTERN:
            yield from nodes(av[3],(icase or bool(av[1]&G.re.I)) and not (av[2]&G.re.I),ctx)


edge_cache={}
def edges(chars):
    key=id(chars)
    if key not in edge_cache:
        # Unicode sentinels also exercise exclusion in ASCII-only classes.
        points={0x1c,0x85,0xe9,0x130,0x131,0x17f,0x212a,0x301,0x200d,
                0xd7ff,0xe000,0xffff,0x10000,0x103ff,0x10ffff}
        for a,b in G.ranges(chars):
            points.update(cp for cp in (a-1,a,b,b+1) if valid(cp))
        edge_cache[key]=[chr(cp) for cp in sorted(points)]
    return edge_cache[key]


report={}
for name,(tree,icase,full) in G.TREES.items():
    strings={}
    examined=0
    for item,ic,ctx in nodes(tree,icase):
        examined+=1
        for char in edges(G.node_chars(item[0],item[1],ic)):
            ov=dict(ctx);ov[id(item)]=char
            text=render(tree,icase,ov)
            for left,right in [('', ''),(' ', ' '),('a',''),('','a'),('é',''),('','é'),('\u0301',''),('','\u0301')]:
                strings[left+text+right]=None
    strings=list(strings)
    sreq=[{'mode':'spans','rule':name,'input':s} for s in strings]
    req=[{'mode':'text','input':s} for s in strings]
    if name=='cfg-key-full': req += [{'mode':'record','input':{s:'abcdefghij'}} for s in strings]
    exp=[py(r) for r in req];sexp=[py_spans(r) for r in sreq]
    sd=diffs(sreq,sexp,run(sreq));d=diffs(req,exp,run(req))
    positive=sum(bool(x['out']) for x in sexp)
    row={'character_nodes':examined,'strings':len(strings),'span_requests':len(sreq),
         'pipeline_requests':len(req),'span_diffs':sd,'pipeline_diffs':d,'positive_spans':positive}
    report[name]=row
    print(name,json.dumps(row),flush=True)
    assert sd==0 and d==0 and positive>0,(name,row)
Path(output).write_text(json.dumps(report,indent=2)+'\n')
print('PASS Unicode edges for all',len(report),'rules')
