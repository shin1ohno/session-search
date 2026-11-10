import datetime, importlib.util, json, os, pathlib, random, re, shutil, subprocess, sys, tempfile
from probe import REPO, run_requests
sys.path.insert(0,str(REPO))
import ccs
spec=importlib.util.spec_from_file_location('ccs.session_codex',REPO/'vendor/memory-mcp/session_codex.py')
sc=importlib.util.module_from_spec(spec);sys.modules[spec.name]=sc;spec.loader.exec_module(sc);ccs.session_codex=sc
from ccs import util,extract,codex,fallback
cases=[]
def add(label,req,expect):cases.append((label,req,json.loads(json.dumps(expect))))
def snap(s):
 d=dict(vars(s));d.update(interactive=s.interactive,resume_cwd=s.resume_cwd);return d
for v in map(json.loads,open(REPO/'vendor/memory-mcp/conformance/session_codex_v1.jsonl')):
 if 'op' in v: add(v['id'],v,v['expect'])
rng=random.Random(42)
for _ in range(1200):
 dt=datetime.datetime(rng.randrange(1,9999),rng.randrange(1,13),rng.randrange(1,28),rng.randrange(24),rng.randrange(60),rng.randrange(60),rng.randrange(1000000))
 for date in (dt.strftime('%Y-%m-%d').zfill(10),dt.isoformat()[:10].replace('-',''),f'{dt.isocalendar().year:04}-W{dt.isocalendar().week:02}-{dt.isoweekday()}'):
  for clock in (dt.isoformat()[11:],dt.isoformat()[11:].replace(':','')):
   s=date+'T'+clock+rng.choice(['','Z','+09:00','-07:30:15.123456'])
   add('timestamp',dict(op='parse_ts',input=s),util.parse_ts(s))
for s in ['2024-01-01T12.5','2024-01-01T12:30.5','2024-W01','2024W011','2024-01-01T00:00:00+00:00:00.5','2024-01-01T12:00Zextra','2024-01-01T12:60','2024-01-01T12:00:00.123456789Z','☃','2024-01-01\n12:00','2024-01-01T12:00:00+23:99','2024-01-01T12:00:00+01:99']:
 add('timestamp-edge',dict(op='parse_ts',input=s),util.parse_ts(s))
for s in ['{"cwd":"/a","cwd":"/b"}','{"x":{"a":1,"\\u0061":2}}','{"x":NaN}', '{"a": 1, "b": 2}', '[{}', '[1,2]']:
 try: expect=extract.loads_strict(s)
 except ValueError: expect={'error':True}
 add('strict',dict(op='strict',input=s),expect)
with tempfile.TemporaryDirectory(prefix='ccs-oracle-') as home:
 os.environ['HOME']=home;os.environ['CODEX_HOME']=home+'/.codex'
 projects=pathlib.Path(home)/'.claude/projects';proj=projects/util.encode_cwd('/work/日本');proj.mkdir(parents=True)
 native=pathlib.Path(codex.sessions_dir())/'2026/10/25';native.mkdir(parents=True)
 sid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
 def write(path,rows,tail=b''):
  path.write_bytes(b''.join((json.dumps(r,ensure_ascii=False)+'\n').encode() for r in rows)+tail);os.utime(path,(1800000000,1800000000))
 def user(text,**kw):return dict(type='user',cwd='/old',relocatedCwd='/work/日本',entrypoint='cli',message={'content':text},**kw)
 base=[user('<system-reminder>hidden</system-reminder> Straße needle'),dict(type='ai-title',aiTitle='\x1c A\u2003title '),dict(type='assistant',message={'content':[{'type':'text','text':'needle reply'},{'type':'tool_use','text':'ignored'}]}),dict(type='attachment',content='hidden needle')]
 path=proj/(sid+'.jsonl');write(path,base,b'{"type":"user","message":{"content":"partial needle"}}')
 alias=proj/'alias.jsonl';alias.symlink_to(path)
 for p in [path,alias]:
  for q in ['', 'needle', 'STRASSE']:
   add('scan-claude',dict(op='scan',input=str(p),query=q),snap(extract.scan(str(p),q)))
 npath=native/('rollout-2026-10-25T00-00-00-'+sid+'.jsonl')
 nrows=[{'type':'session_meta','payload':{'id':sid,'cwd':'/codex','source':'cli','forked_from_id':'parent'}}, {'type':'response_item','payload':{'type':'message','role':'user','content':'inherited needle'}},{'type':'event_msg','payload':{'type':'thread_settings_applied','thread_id':sid}}, {'type':'response_item','payload':{'type':'message','role':'user','content':'own needle'}},{'type':'response_item','payload':{'type':'message','role':'assistant','channel':'analysis','content':'hidden needle'}}]
 write(npath,nrows)
 for q in ['', 'needle','inherited','hidden']:
  add('scan-codex',dict(op='scan',input=str(npath),query=q),snap(extract.scan(str(npath),q)))
 add('classify',dict(op='classify',input=str(npath)),codex.classify(str(npath)))
 add('find-local',dict(op='find_local',input=sid,hint=str(npath)),codex.find_local(sid,str(npath)))
 # An independent per-agent budget keeps Claude text hits despite many Codex context matches.
 for i in range(205):
  p=native/('rollout-2026-10-25T00-00-00-%08d-0000-0000-0000-000000000000.jsonl'%i)
  write(p,[{'type':'session_meta','payload':{'id':'%08d-0000-0000-0000-000000000000'%i,'cwd':'/codex','source':'cli'}},{'type':'event_msg','payload':{'text':'needle'}}]);os.utime(p,(1800001000+i,1800001000+i))
 for q in ['needle','STRASSE','','a','hidden']:
  for headless in [False,True]:
   opts=dict(query=q,include_headless=headless)
   add('search',dict(op='search',input=opts),[snap(s) for s in fallback.search(q,include_headless=headless)])
 for limit in ['/work','/old','/ol',None]:
  opts=dict(query='needle',cwd_prefix=limit,exclude_session_id='not-this',since_epoch=1799999999)
  add('filter',dict(op='search',input=opts),[snap(s) for s in fallback.search(**opts)])
 add('agent-budget',dict(op='search',input=dict(query='needle')),[snap(s) for s in fallback.search('needle')])
 actual=run_requests([req for _,req,_ in cases])
 def equal(a,b):
  if isinstance(a,float) and isinstance(b,float):
   if a!=a and b!=b:return True
   return a==b
  if type(a)!=type(b) and not isinstance(a,(float,int)):return False
  if isinstance(a,dict):return list(a)==list(b) and all(equal(a[k],b[k]) for k in a)
  if isinstance(a,list):return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
  return a==b
 assert len(actual)==len(cases),(len(actual),len(cases))
 failures=[]
 for (label,req,expected),got in zip(cases,actual):
  if not equal(expected,got):failures.append((label,req,expected,got))
 from collections import Counter
 print('Failure groups:',dict(Counter(row[0] for row in failures)))
 for row in failures[:15]:print('FAIL',repr(row)[:1800])
 print('adapter cases=%d pass=%d fail=%d; codex corpus=154; Python=%s'%(len(cases),len(cases)-len(failures),len(failures),sys.version.split()[0]))
 raise SystemExit(bool(failures))
