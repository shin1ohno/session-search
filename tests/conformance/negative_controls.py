#!/usr/bin/env python3
"""Build deliberately broken source copies and require first-layer rejection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('artifacts',type=Path)
p.add_argument('--only',nargs='*')
a=p.parse_args()
a.artifacts.mkdir(parents=True,exist_ok=True)
copy=a.artifacts/'negative-source'
if copy.exists(): shutil.rmtree(copy)
copy.mkdir()
for f in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'): shutil.copy2(ROOT/f,copy/f)
shutil.copytree(ROOT/'crates',copy/'crates')
with (copy/'Cargo.toml').open('a') as f:
    f.write('\n[profile.testmut]\ninherits = "release"\nlto = false\ncodegen-units = 16\nstrip = false\n')
libpath=copy/'crates/ccs-redact/src/lib.rs'
tablepath=copy/'crates/ccs-redact/src/tables.rs'
original=libpath.read_text()
tables=tablepath.read_text()
env=dict(os.environ,CCS_BUILD_COMMIT=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),CARGO_TARGET_DIR=str(ROOT/'target'))
corpus=ROOT/'vendor/memory-mcp/conformance/session_redact_r1.jsonl'
with corpus.open() as f: corpus_count=json.loads(next(f))['vectors']

def replace_once(s,old,new):
    assert s.count(old)==1,(old,s.count(old))
    return s.replace(old,new)

def mutate(name):
    s,t=original,tables
    if name=='N1':
        s=replace_once(s,'in_table(WORD, c)',r'''{ static WORD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"\A\w\z").unwrap()); WORD_RE.is_match(&c.to_string()) }''')
    elif name=='N2':
        s=replace_once(s,'in_table(WORD, c)',"c.is_ascii_alphanumeric() || c == '_'")
    elif name=='N3':
        t=re.sub(r'("cfg-json", r####").*?("####)',lambda m:m[1]+r'\x{0}UNMATCHABLE'+m[2],t)
    elif name=='N4':
        generator=(ROOT/'tools/gen_redact_tables.py').read_text()
        needle='CACHE[k] = re.compile(("(?i)" if icase else "") + src).findall(ALL)'
        generator=replace_once(generator,needle,needle+'\n        if icase: CACHE[k] = [c for c in CACHE[k] if c not in ("ſ", "K")]')
        script=a.artifacts/'gen_case_control.py'
        script.write_text(generator)
        with (a.artifacts/'N4-generation.log').open('w') as log:
            subprocess.run([sys.executable,str(script),str(ROOT/'vendor/memory-mcp/session_redact.py'),str(tablepath)],stdout=log,stderr=subprocess.STDOUT,check=True)
        t=tablepath.read_text()
    elif name=='N5':
        # Change Python's SPACE category before class expansion. Negated
        # classes must gain the removed members; deleting them from every
        # expanded class would test a different mutation.
        generator=(ROOT/'tools/gen_redact_tables.py').read_text()
        generator=replace_once(generator, 'C.CATEGORY_SPACE: r"\\s"',
            'C.CATEGORY_SPACE: r"\\t-\\r\\x1d-\\x20\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"')
        generator=replace_once(generator, 'C.CATEGORY_NOT_SPACE: r"\\S"', 'C.CATEGORY_NOT_SPACE: r"\\S\\x1c\\x85"')
        generator=replace_once(generator, 'space = re.compile(r"\\s").findall(ALL)',
            'space = [c for c in re.compile(r"\\s").findall(ALL) if ord(c) not in (0x1c,0x85)]')
        script=a.artifacts/'gen_space_control.py'
        script.write_text(generator)
        with (a.artifacts/'N5-generation.log').open('w') as log:
            subprocess.run([sys.executable,str(script),str(ROOT/'vendor/memory-mcp/session_redact.py'),str(tablepath)],stdout=log,stderr=subprocess.STDOUT,check=True)
        t=tablepath.read_text()
    elif name=='N6':
        s=s.replace('a.into_iter().rev()', 'a.into_iter()').replace('entries.into_iter().rev()', 'entries.into_iter()')
        s=s.replace('out.reverse();','').replace('done.reverse();','')
    elif name=='N7':
        at=s.index('    fn outside('); end=s.index('    fn py_strip',at)
        s=s[:at]+'''    fn outside(&self, text: &str, fun: &mut dyn FnMut(&str) -> String) -> String { fun(text) }
'''+s[end:]
    elif name=='N12':
        s=replace_once(s,'match json::parse_bounded(&cp, MAX_RECORD_DEPTH)', '''match json::parse_bounded(&cp,128).and_then(|p| if p.flags.too_deep { Err(json::Error::Depth) } else { json::parse_bounded(&cp,MAX_RECORD_DEPTH) })''')
    elif name=='N13':
        s=replace_once(s,'self.redact_record(&p.value.ok_or(Error::InvalidRecord)?, key)?','self.redact_record(&magic(p.value.ok_or(Error::InvalidRecord)?), key)?')
        s+='''
fn magic(v: Value) -> Value {
    match v {
        Value::Object(o) => {
            if o.len() == 1 && scalar(&o[0].0).unwrap() == "$serde_json::private::Number" {
                if let Ok(s) = o[0].1.as_str() { if let Ok(n @ Value::Number(_)) = json::from_str(&s) { return n; } }
            }
            Value::Object(o.into_iter().map(|(k,v)|(k,magic(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(magic).collect()),
        v => v,
    }
}
'''
    elif name=='N14':
        s=s.replace('json::parse_bounded(&cp, MAX_RECORD_DEPTH)','json::parse_bounded(&cp, 256)')
        s=s.replace('if depth > MAX_RECORD_DEPTH {','if depth > 256 {')
    elif name.startswith('passes-'):
        n=name.split('-')[1]
        s=replace_once(s,'const MAX_PASSES: usize = 8;',f'const MAX_PASSES: usize = {n};')
    elif name=='JSON-duplicate':
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text().replace('if p.flags.duplicate {', 'if false {')
        (copy/'crates/ccs-pytext/src/json.rs').write_text(j)
    elif name=='JSON-rounding':
        s=original
        path=copy/'crates/ccs-pytext/src/json.rs'
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text().replace('if integer % 2 == 1 {','if false {')
        path.write_text(j)
    else: raise ValueError(name)
    assert s!=original or t!=tables or name in ('JSON-rounding','JSON-duplicate'),name
    return s,t

controls=a.only or ['N1','N2','N3','N4','N5','N6','N7','N12','N13','N14','passes-1','passes-7','passes-9','passes-16','JSON-rounding','JSON-duplicate']
results_path=a.artifacts/'negative-controls.json'
results=json.loads(results_path.read_text()) if results_path.exists() else []
results=[r for r in results if r['control'] not in controls]
for name in controls:
    shutil.copy2(ROOT/'crates/ccs-pytext/src/json.rs',copy/'crates/ccs-pytext/src/json.rs')
    s,t=mutate(name);libpath.write_text(s);tablepath.write_text(t)
    with (a.artifacts/(name+'-build.log')).open('w') as log:
        subprocess.run(['cargo','build','--locked','--profile','testmut','--bin','ccs'],cwd=copy,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=ROOT/'target/testmut/ccs'
    if name=='JSON-duplicate':
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/strict_json.py'),str(binary)],capture_output=True,text=True)
        log=run.stdout+run.stderr
        assert 'strict duplicate mismatch' in log and run.returncode==1
        mismatches=1
    elif name=='JSON-rounding':
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/json_diff.py'),str(binary)],capture_output=True,text=True)
        log=run.stdout+run.stderr
        assert 'JSON mismatch' in log and run.returncode==1
        mismatches=log.count('JSON mismatch')
    else:
        with corpus.open('rb') as f:
            run=subprocess.run([binary,'_conformance','redact'],stdin=f,capture_output=True,text=True)
        log=run.stdout+run.stderr
        mismatches=log.count('FAIL conformance:')
        assert run.returncode==1 and mismatches>0 and ('vectors=%d'%corpus_count) in log,(name,run.returncode,log[-300:])
        if name.startswith('passes-'):
            assert 'FAIL conformance: "pass-limit/' in log
            assert 'pass_limit='+name.split('-')[1]+'\n' in log
    (a.artifacts/(name+'.log')).write_text(log)
    results.append({'control':name,'exit':run.returncode,'mismatches':mismatches,'detected':True})
    print(json.dumps(results[-1]),flush=True)
    (a.artifacts/'negative-controls.json').write_text(json.dumps(results,indent=2))
