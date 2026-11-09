#!/usr/bin/env python3
"""Compile generated rule mutants in an isolated source copy.

The installed binary never contains mutation selectors. This test-only build
uses the exact production matcher with generated one-node alternatives; the
selector merely chooses which static generated alternative to exercise.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('artifacts',type=Path)
p.add_argument('--mutants',type=Path,required=True)
a=p.parse_args()
a.artifacts.mkdir(parents=True,exist_ok=True)
copy=a.artifacts/'mutation-source'
if copy.exists(): shutil.rmtree(copy)
copy.mkdir()
for f in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'):
    shutil.copy2(ROOT/f,copy/f)
shutil.copytree(ROOT/'crates',copy/'crates')
for source in (copy/'crates').rglob('*.rs'): source.touch()
with (copy/'Cargo.toml').open('a') as f:
    f.write('\n[profile.testmut]\ninherits = "release"\nlto = false\ncodegen-units = 16\nstrip = false\n')
with (copy/'crates/ccs/Cargo.toml').open('a') as f:
    f.write('\n[[bin]]\nname = "ccs-rule-mutants"\npath = "src/main.rs"\n')
lib=copy/'crates/ccs-redact/src/lib.rs'
s=lib.read_text()
s=s.replace('mod tables;', 'mod tables;\nmod test_mutations;')
s=s.replace('    fn rule(&self, name: &str) -> Rule {', '''    fn rule(&self, name: &str) -> Rule {
        if let Some(m) = test_mutations::selected() {
            if m.0 == name { return make(m.0, m.1, m.2, m.3, m.4); }
        }''')
s=s.replace('        CLS[i]', '''        if i >= CLS.len() { test_mutations::selected().expect("test selection").5 } else { CLS[i] }''')
lib.write_text(s)
mutants=json.loads(a.mutants.read_text())
rows=[]
def guard(g):
    return 'G::NotAfter(%s)'%g.split(':')[1] if g.startswith('NotAfter:') else 'G::'+g
for m in mutants['mutants']:
    rows.append('(%s, r####"%s"####, %s, %s, &%s, &[%s]),'%(json.dumps(m['name']),m['pattern'],guard(m['start']),guard(m['end']),json.dumps(m['first']),','.join('(%d,%d)'%tuple(r) for r in m.get('extra_cls',[]))))
(copy/'crates/ccs-redact/src/test_mutations.rs').write_text('''// Generated test-only tables; never part of the product source tree.
use super::tables::G;
type Mutation = (&'static str, &'static str, G, G, &'static [u8], &'static [(u32,u32)]);
static MUTANTS: &[Mutation] = &[
'''+ '\n'.join(rows)+'''
];
pub fn selected() -> Option<&'static Mutation> {
    static SELECTED: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    SELECTED.get_or_init(|| std::env::var("CCS_TEST_MUTANT").ok().map(|s|s.parse().expect("test mutant index")))
        .map(|i| &MUTANTS[i])
}
''')
env=dict(os.environ)
env['CCS_BUILD_COMMIT']=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
# Share immutable dependency cache; preserve the actual product binary first.
shutil.copy2(ROOT/'target/release/ccs',a.artifacts/'ccs-baseline')
env['CARGO_TARGET_DIR']=str(ROOT/'target')
with (a.artifacts/'mutation-build.log').open('w') as log:
    subprocess.run(['cargo','build','--locked','--profile','testmut','--bin','ccs-rule-mutants'],cwd=copy,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
shutil.copy2(ROOT/'target/testmut/ccs-rule-mutants',a.artifacts/'ccs-mutants')
print('PASS isolated generated mutant build:',len(rows),'alternatives')
# The selector-free test build must still be the current product before any
# mutant is selected. This also catches stale path-crate build-cache reuse.
probe=[{'mode':'json','input':r'{"x":"\ud800\udfff"}'},
       {'mode':'json','input':r'{"url":"https:\/\/u:passw0rd@h"}'},
       {'mode':'json','input':'{"x":5.960464477539063e-08}'},
       {'mode':'record','input':{'K'*40+'secret'+'K'*40:'abcdefghij'}}]
payload=''.join(json.dumps(row)+'\n' for row in probe).encode()
probe_env=dict(os.environ);probe_env.pop('CCS_TEST_MUTANT',None)
def output(program):
    return subprocess.check_output([program,'_conformance','redact','--requests'],input=payload,env=probe_env)
assert output(a.artifacts/'ccs-baseline')==output(a.artifacts/'ccs-mutants'),'test build differs without a selected mutation'
print('PASS test build baseline parity on JSON and Unicode key boundaries')
