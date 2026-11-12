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
a.artifacts=a.artifacts.resolve()
a.artifacts.mkdir(parents=True,exist_ok=True)
copy=a.artifacts/'negative-source'
if copy.exists(): shutil.rmtree(copy)
copy.mkdir()
for f in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'): shutil.copy2(ROOT/f,copy/f)
shutil.copytree(ROOT/'crates',copy/'crates')
# Mutable path crates must not reuse artifacts based on an older restored mtime.
for source in (copy/'crates').rglob('*.rs'): source.touch()
with (copy/'Cargo.toml').open('a') as f:
    f.write('\n[profile.testmut]\ninherits = "release"\nlto = false\ncodegen-units = 16\nstrip = false\n')
libpath=copy/'crates/ccs-redact/src/lib.rs'
tablepath=copy/'crates/ccs-redact/src/tables.rs'
original=libpath.read_text()
tables=tablepath.read_text()
# Cargo fingerprints can reuse a same-name path crate from a different copied
# workspace. Keep this workspace's target directory separate from rule mutants.
env=dict(os.environ,CCS_BUILD_COMMIT=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),CARGO_TARGET_DIR=str(a.artifacts/'negative-target'))
corpus=ROOT/'vendor/memory-mcp/conformance/session_redact_r1.jsonl'
with corpus.open() as f: corpus_count=json.loads(next(f))['vectors']

def replace_once(s,old,new):
    assert s.count(old)==1,(old,s.count(old))
    return s.replace(old,new)

def failed_comparisons(gate, output):
    if gate == 'differential':
        value = next(json.loads(line)['diffs'] for line in output.splitlines() if line.startswith('{"cases":'))
    else:
        label = {'json':'JSON differential:', 'lines':'line differential:',
                 'strict':'strict JSON Python extraction comparison:'}[gate]
        match = re.search('^'+re.escape(label)+r'.*failures=(\d+)$',output,re.MULTILINE)
        assert match is not None, 'missing failure count for '+gate
        value = int(match[1])
    assert value > 0, 'no observed comparison failure for '+gate
    return value


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
    elif name=='JSON-power-two':
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text()
        j=replace_once(j,' && roundtrips(integer - 1)','')
        j=replace_once(j,' && roundtrips(integer + 1)','')
        (copy/'crates/ccs-pytext/src/json.rs').write_text(j)
    elif name=='JSON-slash':
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text()
        j=replace_once(j,'0x22 | 0x5c | 0x2f => escaped','0x22 | 0x5c => escaped')
        (copy/'crates/ccs-pytext/src/json.rs').write_text(j)
    elif name=='JSON-low-surrogate':
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text()
        j=replace_once(j,'(0xdc00..=0xdfff).contains(&low)','(0xdc00..=0xdffe).contains(&low)')
        (copy/'crates/ccs-pytext/src/json.rs').write_text(j)
    elif name=='CAP-name-bytes':
        s=replace_once(s,'name.chars().count() <= MAX_KEY_NAME_CHARS','name.len() <= MAX_KEY_NAME_CHARS')
    elif name=='CAP-value-bytes':
        s=replace_once(s,'text.chars().count() > max','text.len() > max')
    elif name=='CAP-record-bytes':
        s=replace_once(s,'*used += v.chars().count();','*used += v.len();')
    elif name=='LINE-vt-ff':
        s=replace_once(s," | 0x0b | 0x0c",'')
    elif name=='RECORD-collision-third':
        s=replace_once(s,'while seen.contains(&format!("{nk}#{i}"))','while false && seen.contains(&format!("{nk}#{i}"))')
    elif name=='RECORD-rust-trim':
        s=replace_once(s,'v.trim_matches(|c| in_table(SPACE, c))','v.trim()')
    elif name=='JSON-duplicate':
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text().replace('if p.flags.duplicate {', 'if false {')
        (copy/'crates/ccs-pytext/src/json.rs').write_text(j)
    elif name=='JSON-rounding':
        s=original
        path=copy/'crates/ccs-pytext/src/json.rs'
        j=(ROOT/'crates/ccs-pytext/src/json.rs').read_text().replace('if integer % 2 == 1 {','if false {')
        path.write_text(j)
    elif name=='HMAC-key32':
        s=replace_once(s,'ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key)',
            'ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key[..key.len().min(32)])')
    else: raise ValueError(name)
    assert s!=original or t!=tables or name in ('JSON-rounding','JSON-duplicate','JSON-power-two','JSON-slash','JSON-low-surrogate'),name
    return s,t

controls=a.only or ['N1','N2','N3','N4','N5','N6','N7','N12','N13','N14','passes-1','passes-7','passes-9','passes-16','JSON-rounding','JSON-duplicate','JSON-power-two','JSON-slash','JSON-low-surrogate',
    'CAP-name-bytes','CAP-value-bytes','CAP-record-bytes','LINE-vt-ff','RECORD-collision-third','RECORD-rust-trim','HMAC-key32']
results_path=a.artifacts/'negative-controls.json'
results=json.loads(results_path.read_text()) if results_path.exists() else []
results=[r for r in results if r['control'] not in controls]
for name in controls:
    (copy/'crates/ccs-pytext/src/json.rs').write_bytes((ROOT/'crates/ccs-pytext/src/json.rs').read_bytes())
    s,t=mutate(name);libpath.write_text(s);tablepath.write_text(t)
    with (a.artifacts/(name+'-build.log')).open('w') as log:
        subprocess.run(['cargo','build','--locked','--profile','testmut','--bin','ccs'],cwd=copy,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=Path(env['CARGO_TARGET_DIR'])/'testmut/ccs'
    gate_failures={}
    review_cases={'JSON-low-surrogate':'surrogate-last','CAP-name-bytes':'key-chars-',
                  'CAP-value-bytes':'value-chars-','CAP-record-bytes':'record-',
                  'LINE-vt-ff':'skip-vt','RECORD-collision-third':'collision-third','RECORD-rust-trim':'python-strip'}
    if name=='HMAC-key32':
        output=a.artifacts/'hmac-keys'
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/hmac_keys.py'),str(binary),str(output)],capture_output=True,text=True)
        log=run.stdout+run.stderr
        summary=json.loads((output/'hmac-keys.json').read_text())
        assert run.returncode==1 and summary['exit']==1 and summary['hmac_mismatches']>0,log[-2000:]
        # Short raw keys are the positive control; longer normalized keys must
        # fail for both redactor APIs, including the production-length key.
        failed=set(summary['failed_ids'])
        for length in (31,32):
            assert not any(x.startswith('hmac-key/%d/direct/'%length) for x in failed)
            assert not any(x.startswith('hmac-key/%d/file-padded/'%length) for x in failed)
        for length in (33,64,128):
            for source in ('direct','file-padded'):
                for op in ('redact_text','redact_record'):
                    assert 'hmac-key/%d/%s/aws-key/%s'%(length,source,op) in failed
        mismatches=summary['hmac_mismatches']
        gate_failures['hmac-keys']=mismatches
    elif name in review_cases or name=='JSON-slash':
        checks=['differential']
        if name in ('JSON-slash','JSON-low-surrogate','LINE-vt-ff','RECORD-collision-third','RECORD-rust-trim'):
            checks.append('lines')
        if name=='JSON-slash': checks.append('json')
        log=''
        for check in checks:
            if check=='differential':
                cmd=[sys.executable,str(ROOT/'tests/conformance/differential.py'),str(ROOT/'vendor/memory-mcp/session_redact.py'),str(binary),str(a.artifacts/(name+'.jsonl')),'--regressions-only']
            elif check=='lines':
                cmd=[sys.executable,str(ROOT/'tests/conformance/line_diff.py'),str(binary),'--regressions-only']
            else:
                cmd=[sys.executable,str(ROOT/'tests/conformance/json_diff.py'),str(binary),'--count','0']
            run=subprocess.run(cmd,capture_output=True,text=True)
            output=run.stdout+run.stderr
            marker='JSON mismatch' if check=='json' else 'line mismatch' if check=='lines' else 'differential mismatch'
            assert run.returncode==1 and marker in output,(name,check,output[-1000:])
            if check!='json': assert review_cases.get(name,'slash-') in output,(name,output[-1000:])
            gate_failures[check]=failed_comparisons(check,output)
            log+='GATE '+check+'\n'+output
        mismatches=sum(gate_failures.values())
    elif name=='JSON-power-two':
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/json_diff.py'),str(binary),'--count','0'],capture_output=True,text=True)
        log=run.stdout+run.stderr
        assert run.returncode==1 and 'JSON mismatch' in log and '5.960464477539063e-08' in log
        mismatches=failed_comparisons('json',log)
        gate_failures['json']=mismatches
    elif name=='JSON-duplicate':
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/strict_json.py'),str(binary)],capture_output=True,text=True)
        log=run.stdout+run.stderr
        assert 'strict duplicate mismatch' in log and run.returncode==1
        mismatches=failed_comparisons('strict',log)
        gate_failures['strict']=mismatches
    elif name=='JSON-rounding':
        run=subprocess.run([sys.executable,str(ROOT/'tests/conformance/json_diff.py'),str(binary)],capture_output=True,text=True)
        log=run.stdout+run.stderr
        assert 'JSON mismatch' in log and run.returncode==1
        mismatches=failed_comparisons('json',log)
        gate_failures['json']=mismatches
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
    results.append({'control':name,'exit':run.returncode,'mismatches':mismatches,
                    'gate_failures':gate_failures or {'corpus':mismatches},'detected':True})
    print(json.dumps(results[-1]),flush=True)
    (a.artifacts/'negative-controls.json').write_text(json.dumps(results,indent=2))
