#!/usr/bin/env python3
"""Require one observed detection or one proved equivalence for every attempted mutation."""
import json
from pathlib import Path
import sys


def audit(manifest,gates,equivalence):
    compiled={m['mutant']:m for m in manifest['mutants']}
    rejected={m['mutant']:m for m in manifest['rejected']}
    assert len(compiled)==len(manifest['mutants']) and len(rejected)==len(manifest['rejected'])
    assert not compiled.keys() & rejected.keys()
    assert len(compiled)+len(rejected)==manifest['attempted'],'attempted mutation missing'
    results={r['mutant']:r for r in gates['results']}
    assert results.keys()==compiled.keys(),'compiled mutation missing from gate results'
    assert len(results)==len(gates['results'])
    assert gates['generator_rejections']==manifest['rejected']
    eq={r['mutant']:r for r in equivalence['items']}
    assert len(eq)==len(equivalence['items'])
    assert all(r['class'] not in ('unresolved','broken-by-hunt') and r['hunt_result']=='no difference' for r in eq.values())
    remaining=set()
    counts={'structure':0,'baseline':0,'generator':len(rejected),'equivalent':0}
    for name,row in results.items():
        if row['gate']=='structure':
            assert row['structgen_diffs']==1 and row['baseline_diffs'] is None
            counts['structure']+=1
        elif row['gate']=='baseline':
            assert row['structgen_diffs']==0 and row['baseline_diffs']==1
            counts['baseline']+=1
        else:
            assert row['structgen_diffs']==row['baseline_diffs']==0
            remaining.add(name)
    assert remaining==eq.keys(),'unaccounted mutation or ineligible equivalence'
    assert all(r['gate']=='generator' and r['reason'] for r in rejected.values())
    counts['equivalent']=len(eq)
    assert sum(counts.values())==manifest['attempted']
    return {'attempted':manifest['attempted'],'gates':counts,'accounted':sum(counts.values())}


if __name__=='__main__':
    folder=Path(sys.argv[1])
    result=audit(json.loads((folder/'mutants.json').read_text()),json.loads((folder/'gate-mutants.json').read_text()),json.loads((folder/'survivors-classified.json').read_text()))
    (folder/'mutation-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS exhaustive mutation accounting',json.dumps(result))
