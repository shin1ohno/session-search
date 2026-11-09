#!/usr/bin/env python3
"""Negative controls for event routing, per-rule assertions and mutation accounting."""
import ast
import copy
import json
from pathlib import Path
import re
import re._constants as C
import re._parser as P
import types
from event_policy import policy
from audit_mutants import audit

HERE=Path(__file__).resolve().parent

def functions(path,names,namespace,mutate=lambda s:s):
    tree=ast.parse(mutate(path.read_text()))
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)


def rejects(label,fn,reason):
    try: fn()
    except AssertionError as e:
        assert reason in str(e),(label,str(e))
        print('PASS negative:',label)
    else: raise AssertionError('control accepted: '+label)

ns={}
functions(HERE/'structgen.py',{'verify_rule_results'},ns)
valid={'a':{'diffs':0,'span_diffs':0,'python_detect_hits_on_rust_output':0,'decision_nodes':1},
       'b':{'diffs':0,'span_diffs':0,'python_detect_hits_on_rust_output':0,'decision_nodes':1}}
ns['verify_rule_results'](valid)
for key in ('diffs','span_diffs','python_detect_hits_on_rust_output'):
    broken=copy.deepcopy(valid);broken['a'][key]=-1;broken['b'][key]=1
    assert sum(r[key] for r in broken.values())==0  # the old aggregate accepted this
    rejects('cancelled per-rule '+key,lambda:ns['verify_rule_results'](broken),'per-rule comparison failure')

def verify_policy(fn):
    pr=fn({'GITHUB_EVENT_NAME':'pull_request','GITHUB_RUN_ID':'1'})
    assert pr==fn({'GITHUB_EVENT_NAME':'pull_request','GITHUB_RUN_ID':'2'}),'PR policy must be deterministic'
    w1=fn({'GITHUB_EVENT_NAME':'schedule','GITHUB_RUN_ID':'1'})
    w2=fn({'GITHUB_EVENT_NAME':'schedule','GITHUB_RUN_ID':'2'})
    assert len({w1['redactor_seed'],w2['redactor_seed'],pr['redactor_seed']})==3,'weekly seed must vary'
    assert pr['redactor_fuzz_requests']==pr['line_random_inputs']==200000,'planned PR counts'
    assert w1['redactor_fuzz_requests']==w1['line_random_inputs']==2000000,'planned weekly counts'
    assert 2*w1['redactor_random_inputs']==w1['redactor_fuzz_requests'],'weekly request count'
verify_policy(policy)
policy_ns=dict(policy.__globals__)
functions(HERE/'event_policy.py',{'policy'},policy_ns,
          lambda s:s.replace("extended=env.get('GITHUB_EVENT_NAME') in ('schedule','workflow_dispatch')","extended=False"))
rejects('weekly kept at PR seed',lambda:verify_policy(policy_ns['policy']),'weekly seed must vary')
functions(HERE/'event_policy.py',{'policy'},policy_ns,
          lambda s:s.replace("'line_random_inputs':count","'line_random_inputs':20000"))
rejects('line differential kept at 20k',lambda:verify_policy(policy_ns['policy']),'planned PR counts')
# Exercise run.py's actual adapter with the host-shaped event environment.
import os,tempfile,sys
from unittest.mock import patch
with tempfile.TemporaryDirectory() as work:
    binary=Path(work)/'ccs';binary.touch();commands=[]
    # Execute the event-to-command adapter with isolated output and a recording runner.
    tree=ast.parse((HERE/'run.py').read_text())
    tree.body=[n for n in tree.body if not (isinstance(n,ast.FunctionDef) and n.name=='run') and not isinstance(n,ast.Assert)
               and not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='print')]
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='OUT' for t in node.targets):
            node.value=ast.parse('Path(adapter_output)',mode='eval').body
    ast.fix_missing_locations(tree)
    def fake_run(name,args,**kw): commands.append((name,list(map(str,args))))
    for event,attempt in [(event,attempt) for event in ('pull_request','schedule','workflow_dispatch') for attempt in ('1','2')]:
        commands.clear()
        with patch.dict(os.environ,{'GITHUB_EVENT_NAME':event,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':attempt}),patch.object(sys,'argv',['run.py',str(binary)]):
            scope={'__file__':str(HERE/'run.py'),'run':fake_run,'adapter_output':str(Path(work)/event/attempt)}
            exec(compile(tree,str(HERE/'run.py'),'exec'),scope)
        want=policy({'GITHUB_EVENT_NAME':event,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':attempt})
        cmds=dict(commands)
        line=cmds['lines'];diff=cmds['differential']
        assert int(line[line.index('--count')+1])==want['line_random_inputs']
        assert int(line[line.index('--seed')+1])==want['line_seed']
        assert int(diff[5])==want['redactor_random_inputs']
        assert int(diff[diff.index('--seed')+1])==want['redactor_seed']
print('PASS event adapter: deterministic PR and changed weekly seeds, both planned counts')

# The actual optional-prefix predicate must refuse captured groups.
G=types.SimpleNamespace(re=re,TREES={})
def chars(op,av,ic):
    if op is C.LITERAL: return [chr(av)]
    assert op is C.IN
    return [chr(x) for o,v in av for x in (range(v[0],v[1]+1) if o is C.RANGE else [v])]
G.node_chars=chars
namespace={'G':G,'C':C,'CHAR':(C.LITERAL,C.NOT_LITERAL,C.IN,C.ANY),'re':re}
names={'resolve','has_group','next_absent','is_repeat','all_chars','subsumed_optional'}
functions(HERE/'classify_survivors.py',names,namespace)
G.TREES['case']=(P.parse(r'(?:proj-)?[a-z-]+'),False,False)
assert namespace['subsumed_optional']('case','case[0]','hi+1')
G.TREES['case']=(P.parse(r'(proj-)?[a-z-]+'),False,False)
assert not namespace['subsumed_optional']('case','case[0]','hi+1')
functions(HERE/'classify_survivors.py',names,namespace,
          lambda s:s.replace('    if has_group(G.TREES[name][0]):\n        return False\n',''))
assert namespace['subsumed_optional']('case','case[0]','hi+1')
print('PASS negative: removing capture guard admits captured optional prefix')

manifest={'attempted':2,'mutants':[{'mutant':'a'}],'rejected':[{'mutant':'b','gate':'generator','reason':'unsupported tail'}]}
gates={'results':[{'mutant':'a','gate':'baseline','structgen_diffs':0,'baseline_diffs':1}],
       'generator_rejections':manifest['rejected']}
audit(manifest,gates,{'items':[]})
broken=copy.deepcopy(manifest);broken['rejected']=[]
rejects('silently dropped generator rejection',lambda:audit(broken,gates,{'items':[]}),'attempted mutation missing')
broken=copy.deepcopy(gates);broken['results']=[]
rejects('missing compiled mutant',lambda:audit(manifest,broken,{'items':[]}),'compiled mutation missing')

coverage={}
functions(HERE.parent.parent/'tools/gen_redact_tables.py',{'verify_rule_mutations'},coverage)
coverage['verify_rule_mutations']({'anchor':None,'placeholder':None},[{'name':'anchor'},{'name':'placeholder'}],[])
rejects('skipped placeholder rule',lambda:coverage['verify_rule_mutations']({'anchor':None,'placeholder':None},[{'name':'anchor'}],[]),'rule missing')

counters={'json':json,'re':re}
functions(HERE/'negative_controls.py',{'failed_comparisons'},counters)
assert counters['failed_comparisons']('json','JSON mismatch sample\nJSON differential: cases=20 failures=10\n')==10
assert counters['failed_comparisons']('differential','{"cases": 28, "diffs": 2}\n')==2
rejects('zero failures in negative result',lambda:counters['failed_comparisons']('json','JSON differential: cases=1 failures=0'),'no observed comparison failure')
rejects('missing result header',lambda:counters['failed_comparisons']('json','JSON mismatch only'),'missing failure count')

print('PASS gate controls')
