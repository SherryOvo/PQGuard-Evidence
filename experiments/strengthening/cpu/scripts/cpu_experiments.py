#!/usr/bin/env python3
"""CPU-only experiments on frozen R11 modules plus explicitly labeled extensions.
No torch/vLLM/CUDA import. No host services or previous experiment files altered.
"""
from __future__ import annotations
import argparse,concurrent.futures,contextlib,hashlib,hmac,json,multiprocessing as mp,os,random,shutil,signal,socket,socketserver,sqlite3,subprocess,sys,threading,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vendor'))
from r7_crypto_profiles import build_profile,canonical,sha256
from r11_durable_lifecycle import DurableLifecycleStore
from conventional_store import ConventionalStrongStore
from r7_witness import WitnessStore,witness_message
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def atomic(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(v,sort_keys=True,indent=2));os.replace(t,p)
def row(p,v):
 with Path(p).open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n');f.flush()
def check(v,msg):
 if not v:raise AssertionError(msg)
def digestfile(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()
class LocalWitness:
 def __init__(self,path,profile,stream):
  self.store=WitnessStore(Path(path),{stream:{'algorithm':profile.audit_algorithm,'public_key_hex':profile.audit_public.hex()}})
 def publish(self,stream,counter,digest,signature):return self.store.publish(dict(stream=stream,counter=counter,digest=digest,signature_hex=signature.hex()))
 def close(self):self.store.db.close()
def make(out,profile,kind='cbas',name='store'):
 stream=name;w=LocalWitness(out/(name+'_witness.sqlite'),profile,stream)
 s=(DurableLifecycleStore if kind=='cbas' else ConventionalStrongStore)(out/(name+'.sqlite'),profile,stream,w)
 return s,w
def records(store):
 result=[]
 for a in store.db.execute('SELECT sid,seq,prompt_hash,policy_digest,receipt FROM admissions ORDER BY seq'):
  full=store.db.execute('SELECT * FROM completions WHERE sid=? AND seq=?',a[:2]).fetchone();b=(full[3],full[5],full[6],full[7])
  q=store.db.execute('SELECT stream,signature FROM witness_outbox WHERE counter=?',(b[2],)).fetchone()
  result.append({'admission':dict(kind='admission',sid=a[0],seq=a[1],prompt_hash=a[2],policy=a[3]),'admission_signature':bytes(a[4]).hex(),'completion':json.loads(bytes(b[0])),'completion_signature':bytes(b[1]).hex(),'publication':dict(stream=q[0],counter=b[2],digest=b[3]),'publication_signature':bytes(q[1]).hex()})
 return result
def component_ok(p,r):
 return p.verify_identity(canonical(r['admission']),bytes.fromhex(r['admission_signature'])) and p.verify_audit(canonical(r['completion']),bytes.fromhex(r['completion_signature'])) and p.verify_audit(witness_message(**r['publication']),bytes.fromhex(r['publication_signature']))
def relation_ok(p,r):
 if not component_ok(p,r):return False
 a,b,q=r['admission'],r['completion'],r['publication']
 return all(a[k]==b[k] for k in ['sid','seq','prompt_hash','policy']) and a['policy']==p.policy_digest and q['digest']==sha256(canonical(dict(previous=b['previous'],entry=sha256(canonical(b)+bytes.fromhex(r['completion_signature'])),counter=q['counter'])))

def binding(out,p,seed,cfg):
 n=cfg['binding_records'];counts={}
 for kind in ['cbas','conventional']:
  s,w=make(out,p,kind,kind)
  for i in range(n):
   sid='session-'+str(i%2);hp=sha256(canonical({'seed':seed,'request':i}));s.admit(sid,i,hp,p.policy_digest);s.complete(sid,i,sha256(b'response'+str(i).encode()))
  rec=records(s);atomic(out/(kind+'_fixtures.json'),{'public':p.export_public(),'records':rec})
  for label in ['clean','completion_splice','publication_splice','signature_corruption']:
   hit=bad=0
   for i,original in enumerate(rec):
    r=json.loads(json.dumps(original));other=rec[(i+1)%n]
    if label=='completion_splice':
     for k in ['completion','completion_signature','publication','publication_signature']:r[k]=other[k]
    elif label=='publication_splice':
     for k in ['publication','publication_signature']:r[k]=other[k]
    elif label=='signature_corruption':
     b=bytearray.fromhex(r['completion_signature']);b[0]^=1;r['completion_signature']=b.hex()
    c=component_ok(p,r);bound=relation_ok(p,r);expected_c=label!='signature_corruption';expected_b=label=='clean'
    row(out/'raw.jsonl',dict(implementation=kind,case=label,index=i,component_signatures_valid=c,lifecycle_relation_valid=bound,expected_component=expected_c,expected_relation=expected_b));check(c==expected_c and bound==expected_b,'binding decision mismatch');hit+=c;bad+=bound
   counts[kind+'/'+label]={'trials':n,'component_accepts':hit,'relation_accepts':bad}
  s.close();w.close()
 return {'counts':counts,'scope':'offline signed-evidence composition ablation with both actual store sources; not an online exploit or novelty proof'}

class VersionGate:
 def __init__(self,path,p):
  self.p=p;self.db=sqlite3.connect(path);self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('CREATE TABLE IF NOT EXISTS floor(authority TEXT PRIMARY KEY,version INTEGER NOT NULL)');self.db.commit();self.authority=sha256(p.policy_public)
 def accept(self,d,sig,retained=None):
  if not self.p._validate_policy(d,sig,int(time.time())):return 'invalid_certificate'
  self.db.execute('BEGIN IMMEDIATE');r=self.db.execute('SELECT version FROM floor WHERE authority=?',(self.authority,)).fetchone();floor=r[0] if r else 0
  if retained:
   obj=retained['value'];valid=self.p.verify_audit(canonical(obj),bytes.fromhex(retained['signature']))
   if not valid or obj['authority']!=self.authority:self.db.rollback();return 'invalid_reference'
   if floor<obj['version']:self.db.rollback();return 'local_floor_rollback'
  if d['version']<floor:self.db.rollback();return 'older_version'
  self.db.execute('INSERT INTO floor VALUES(?,?) ON CONFLICT(authority) DO UPDATE SET version=MAX(version,excluded.version)',(self.authority,d['version']));self.db.commit();return 'accepted'
 def close(self):self.db.close()
def version_floor(out,p,seed,cfg):
 d1=dict(p.policy_descriptor,version=1);d2=dict(p.policy_descriptor,version=2);s1=p.sign_policy(canonical(d1));s2=p.sign_policy(canonical(d2));db=out/'floor.sqlite'
 g=VersionGate(db,p);check(g.accept(d1,s1)=='accepted','v1 initial');g.close();shutil.copyfile(db,out/'old_snapshot.sqlite')
 g=VersionGate(db,p);check(g.accept(d2,s2)=='accepted','upgrade');g.close()
 for i in range(24):
  # A separate interpreter process opens and checks the durable floor. It has only public material.
  result=subprocess.run([sys.executable,str(Path(__file__)),'--read-floor',str(db),'--authority',sha256(p.policy_public)],capture_output=True,text=True)
  check(result.returncode==0 and int(result.stdout.strip().splitlines()[-1])==2,'fresh-process floor');g=VersionGate(db,p);decision=g.accept(d1,s1);g.close();row(out/'raw.jsonl',dict(case='restart_reject_old',trial=i,decision=decision));check(decision=='older_version','old accepted')
 refobj=dict(kind='policy_floor_reference_v1',authority=sha256(p.policy_public),version=2,policy_digest=p.policy_digest);ref={'value':refobj,'signature':p.sign_audit(canonical(refobj)).hex()};atomic(out/'public_fixtures.json',dict(public=p.export_public(),v1=d1,s1=s1.hex(),v2=d2,s2=s2.hex(),reference=ref))
 shutil.copyfile(out/'old_snapshot.sqlite',out/'rolled.sqlite');g=VersionGate(out/'rolled.sqlite',p);bare=g.accept(d1,s1);anchored=g.accept(d1,s1,ref);g.close();check(bare=='accepted' and anchored=='local_floor_rollback','rollback distinction')
 row(out/'raw.jsonl',dict(case='snapshot_rollback',local_only=bare,separately_retained_reference=anchored))
 return {'restart_old_rejections':24,'local_only_snapshot_rollback_accepts_old':True,'retained_reference_detects_rollback':True,'scope':'new persistent-floor extension; logical separately retained reference, not whole-host or malicious-authority tolerance'}

class RetirementStore(DurableLifecycleStore):
 def __init__(self,*args):
  super().__init__(*args);self.db.execute('CREATE TABLE IF NOT EXISTS session_state(sid TEXT PRIMARY KEY,status TEXT NOT NULL)');self.db.commit()
 def register(self,sid):self.db.execute("INSERT OR IGNORE INTO session_state VALUES(?,'active')",(sid,));self.db.commit()
 def admit(self,sid,seq,prompt_hash,policy_digest):
  self.flush_witness_outbox();start=time.perf_counter_ns();msg=canonical(dict(kind='admission',sid=sid,seq=seq,prompt_hash=prompt_hash,policy=policy_digest));sig=self.profile.sign_identity(msg)
  with self.lock:
   self.db.execute('BEGIN IMMEDIATE')
   try:
    st=self.db.execute('SELECT status FROM session_state WHERE sid=?',(sid,)).fetchone()
    if st!=('active',):raise RuntimeError('session retired or unregistered')
    self.db.execute('INSERT INTO admissions VALUES(?,?,?,?,?,?)',(sid,seq,prompt_hash,policy_digest,sig,'pending'));self.db.commit()
   except BaseException:self.db.rollback();raise
  return sig,time.perf_counter_ns()-start
 def retire(self,sid):
  with self.lock:
   self.db.execute('BEGIN IMMEDIATE')
   if self.db.execute("SELECT COUNT(*) FROM admissions WHERE sid=? AND status='pending'",(sid,)).fetchone()[0]:self.db.rollback();return False
   self.db.execute("UPDATE session_state SET status='retired' WHERE sid=?",(sid,));self.db.commit();return True
def retention(out,p,seed,cfg):
 sizes=cfg['capacity_sizes'];s,w=make(out,p,name='capacity');last=0
 for n in sizes:
  t=time.perf_counter_ns()
  for i in range(last,n):s.admit('capacity-session',i,sha256(str(i).encode()),p.policy_digest)
  wall=time.perf_counter_ns()-t;s.db.execute('PRAGMA wal_checkpoint(FULL)');lookup=time.perf_counter_ns()
  for _ in range(200):s.db.execute('SELECT 1 FROM admissions WHERE sid=? AND seq=?',('capacity-session',n//2)).fetchone()
  row(out/'raw.jsonl',dict(case='capacity',records=n,new_admissions=n-last,wall_ns=wall,lookup_200_ns=time.perf_counter_ns()-lookup,db_bytes=(out/'capacity.sqlite').stat().st_size));last=n
 s.close();w.close();w=LocalWitness(out/'retire_witness.sqlite',p,'retire');s=RetirementStore(out/'retirement.sqlite',p,'retire',w);s.register('live');s.admit('live',0,sha256(b'a'),p.policy_digest);check(not s.retire('live'),'pending retired');s.complete('live',0,sha256(b'b'));check(s.retire('live'),'retire failed');s.close();w.close()
 w=LocalWitness(out/'retire_witness.sqlite',p,'retire');s=RetirementStore(out/'retirement.sqlite',p,'retire',w)
 for seq in [0,1,999]:
  try:s.admit('live',seq,sha256(b'a'),p.policy_digest);raise AssertionError('retired accepted')
  except RuntimeError:row(out/'raw.jsonl',dict(case='retired_reject',seq=seq,rejected=True))
 check(s.db.execute('SELECT COUNT(*) FROM admissions').fetchone()[0]==1,'audit admission deleted');s.close();w.close()
 return {'capacity_sizes':sizes,'retired_rejections':3,'audit_rows_deleted':0,'scope':'exact replay-state capacity and retirement extension; no claim of full audit garbage collection or bounded memory'}

def io_inner(out,p,seed,cfg):
 uid=int(os.environ['PQ_LAB_UID']);gid=int(os.environ['PQ_LAB_GID']);mount=out/'private_tmpfs';mount.mkdir()
 subprocess.run(['mount','-t','tmpfs','-o','size=24m','pqguard_io_test',str(mount)],check=True);os.chown(mount,uid,gid);os.setgid(gid);os.setuid(uid)
 results=[]
 for stage in ['admission','completion','witness']:
  test=out/stage;test.mkdir();target=mount/stage;target.mkdir();stream=stage
  w=LocalWitness((target if stage=='witness' else test)/'witness.sqlite',p,stream);s=DurableLifecycleStore((test if stage=='witness' else target)/'lifecycle.sqlite',p,stream,w)
  if stage!='admission':s.admit('io',0,sha256(b'prompt'),p.policy_digest)
  filler=mount/'filler';oserr=None
  try:
   with filler.open('wb',buffering=0) as f:
    while True:f.write(b'x'*4096)
  except OSError as e:oserr=e.errno
  check(oserr==28,'did not reach actual ENOSPC');released=False;err=None
  try:
   if stage=='admission':s.admit('io',0,sha256(b'prompt'),p.policy_digest)
   else:s.complete('io',0,sha256(b'response'));released=True
  except Exception as e:err={'type':type(e).__name__,'sqlite_error':getattr(e,'sqlite_errorname',None)}
  filler.unlink();check(err is not None and not released,'disk-full returned success')
  state=s.integrity();check(state['integrity']=='ok','producer corrupt');check(w.store.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','witness corrupt')
  if stage=='witness':check(state['pending_witness_publications']==1,'lost outbox');s.flush_witness_outbox();check(s.integrity()['pending_witness_publications']==0,'not recovered')
  for db,n in [(s.db,'producer_after.sqlite'),(w.store.db,'witness_after.sqlite')]:
   dest=sqlite3.connect(test/n);db.backup(dest);dest.close()
  s.close();w.close();row(out/'raw.jsonl',dict(case=stage,os_errno=oserr,error=err,response_released=released,state_after_space_recovery=state));results.append(stage)
  shutil.rmtree(target)
 return {'actual_ENOSPC_cases':results,'scope':'actual private-tmpfs ENOSPC at declared API boundaries; no power-loss or GPU recovery claim'}
def io_failure(out,p,seed,cfg):
 env=os.environ.copy();env['PQ_LAB_UID']=str(os.getuid());env['PQ_LAB_GID']=str(os.getgid())
 kept={k:env[k] for k in ['PQ_LAB_UID','PQ_LAB_GID','OQS_INSTALL_PATH','LD_LIBRARY_PATH','PYTHONPATH','PYTHONDONTWRITEBYTECODE'] if k in env}
 cmd=['sudo','-n','unshare','--mount','--propagation','private','env']+[k+'='+v for k,v in kept.items()]+[sys.executable,str(Path(__file__)),'--module','io_inner','--profile',p.name,'--seed',str(seed),'--out',str(out/'actual')]
 log=(out/'io_child.log').open('w');q=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT);log.close();check(q.returncode==0,'private mount/I/O child failed; see retained log')
 r=json.loads((out/'actual/SUMMARY.json').read_text());check(r['passed'],'I/O test failed');return r['result']

def privacy(out,p,seed,cfg):
 # Public deterministic vector permits algorithm replay; secret experiment key is RAM-only.
 key=os.urandom(32);messages=[f'test-prompt-{i}'.encode() for i in range(1000)];dictionary={sha256(m):i for i,m in enumerate(messages)};public_hits=hidden_hits=0
 for i,m in enumerate(messages[:100]):
  a=sha256(m);b=hmac.digest(key,b'audit-prompt-v1\0'+m,'sha256').hex();public_hits+=a in dictionary;hidden_hits+=b in dictionary
  check(hmac.compare_digest(bytes.fromhex(b),hmac.digest(key,b'audit-prompt-v1\0'+m,'sha256')),'authorized verify')
  check(not hmac.compare_digest(bytes.fromhex(b),hmac.digest(key,b'audit-response-v1\0'+m,'sha256')),'domain separation')
  row(out/'raw.jsonl',dict(index=i,unkeyed_digest=a,keyed_commitment=b,public_dictionary_match=a in dictionary,keyed_value_in_unkeyed_dictionary=b in dictionary))
 check(public_hits==100 and hidden_hits==0,'exposure counts');public_key=b'public-functional-test-key';vector=hmac.digest(public_key,b'audit-prompt-v1\0test','sha256').hex();atomic(out/'public_vector.json',dict(test_key_hex=public_key.hex(),message_hex=b'audit-prompt-v1\0test'.hex(),expected=vector))
 return {'dictionary_targets':100,'public_hash_recovered':public_hits,'keyed_in_unkeyed_dictionary':hidden_hits,'scope':'CPU commitment extension and limited dictionary-exposure diagnostic; not semantic-security proof; secret experiment key not retained'}

def writer_worker(path,profile,barrier,queue,groups):
 try:
  stream=Path(path).stem;w=LocalWitness(Path(path).parent/('unused_'+str(os.getpid())+'.sqlite'),profile,stream);s=DurableLifecycleStore(Path(path),profile,stream,w)
  for g in range(groups):
   barrier.wait(timeout=60);ok=False
   try:s.admit('same-session',g,sha256(str(g).encode()),profile.policy_digest);ok=True
   except sqlite3.IntegrityError:pass
   queue.put((g,ok,os.getpid()))
  s.close();w.close()
 except BaseException as e:queue.put(('error',type(e).__name__,os.getpid()));raise
def multiwriter(out,p,seed,cfg):
 ctx=mp.get_context('fork');n=cfg['multiwriter_processes'];groups=cfg['multiwriter_groups'];counts={}
 for label in ['shared_store','independent_stores']:
  paths=[out/(('shared' if label=='shared_store' else 'independent_'+str(i))+'.sqlite') for i in range(n)]
  for path in set(paths):s,w=make(out,p,name=path.stem);s.close();w.close()
  b=ctx.Barrier(n);q=ctx.Queue();workers=[ctx.Process(target=writer_worker,args=(str(paths[i]),p,b,q,groups)) for i in range(n)]
  for w in workers:w.start()
  result=[q.get(timeout=300) for _ in range(n*groups)]
  for w in workers:w.join(timeout=60);check(w.exitcode==0,'writer failed')
  check(all(r[0]!='error' for r in result),'writer exception');accept={g:sum(r[1] for r in result if r[0]==g) for g in range(groups)}
  for g,ok,pid in result:row(out/'attempts.jsonl',dict(case=label,group=g,accepted=ok,worker_pid=pid))
  check(set(accept.values())==({1} if label=='shared_store' else {n}),'wrong domain uniqueness');counts[label]=accept
  for g,total in accept.items():row(out/'raw.jsonl',dict(case=label,group=g,accepted=total,attempted=n))
 return {'groups_per_condition':groups,'processes':n,'accept_counts':counts,'scope':'actual cross-process SQLite admission; independent stores are an explicit negative control, not a consensus implementation'}

def proxy_diagnostic(out,p,seed,cfg):
 results=[];rng=random.Random(seed)
 conditions=[(delay,c,deadline) for delay in [0,.05] for c in [1,32,64] for deadline in [.03,.5]];rng.shuffle(conditions)
 for ci,(delay,concurrency,deadline) in enumerate(conditions):
  cd=out/f'cell_{ci:02}';cd.mkdir();session=p.establish_session(canonical(dict(test='proxy',seed=seed,cell=ci)));s,w=make(cd,p,name='server');log_lock=threading.Lock();live=peak=0;counter=0
  class Handler(socketserver.StreamRequestHandler):
   def handle(self):
    nonlocal live,peak
    active=False
    try:
     obj=json.loads(self.rfile.readline(500000));seq=obj['seq'];start=time.perf_counter_ns()
     with log_lock:live+=1;peak=max(peak,live);active=True
     time.sleep(delay);key,nonce=p.record_material(session,'request',seq);aad=p.associated_data(session,'request',seq);prompt=AESGCM(key).decrypt(nonce,bytes.fromhex(obj['cipher']),aad)
     s.admit(session.sid,seq,sha256(prompt),p.policy_digest);s.complete(session.sid,seq,sha256(b'ack'));self.wfile.write(b'{"ok":true}\n')
    except Exception as e:
     with log_lock:row(cd/'server.jsonl',dict(error_type=type(e).__name__))
    finally:
     with log_lock:
      if active:live-=1;row(cd/'server.jsonl',dict(seq=seq,server_processing_ns=time.perf_counter_ns()-start))
  class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=False;request_queue_size=128
  server=Server(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start();event=threading.Event();n=max(cfg['proxy_requests'],concurrency)
  def client(i):
   event.wait();start=time.perf_counter_ns();ok=False;error=None;payload=b'x'*65536;key,nonce=p.record_material(session,'request',i);cipher=AESGCM(key).encrypt(nonce,payload,p.associated_data(session,'request',i))
   try:
    with socket.create_connection(server.server_address,timeout=deadline) as conn:
     conn.settimeout(deadline);conn.sendall(canonical(dict(seq=i,cipher=cipher.hex()))+b'\n');ok=json.loads(conn.makefile('rb').readline())['ok']
   except Exception as e:error=type(e).__name__
   return dict(index=i,ok=ok,error=error,total_ns=time.perf_counter_ns()-start)
  with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
   futures=[pool.submit(client,i) for i in range(n)];begin=time.perf_counter_ns();event.set();rows=[x.result() for x in futures];wall=time.perf_counter_ns()-begin
  server.shutdown();server.server_close();thread.join();check(len(rows)==n,'lost diagnostic rows')
  for r in rows:row(cd/'raw.jsonl',r)
  results.append(dict(cell=ci,delay_seconds=delay,client_deadline_seconds=deadline,concurrency=concurrency,requests=n,successes=sum(x['ok'] for x in rows),timeouts=sum(x['error'] in ['TimeoutError','timeout'] for x in rows),max_server_inflight=peak,wall_ns=wall));s.close();w.close();atomic(cd/'SUMMARY.json',results[-1])
 return {'cells':results,'scope':'new loopback encrypted-service delay/deadline diagnostic; not a reproduction or causal attribution of historical P3 and not TCP loss/netem'}

def io_attribution(out,p,seed,cfg):
 n=cfg['io_sample_mib']*1024*1024;data=(hashlib.sha256(str(seed).encode()).digest()*32768);path=out/'synthetic_input.bin'
 with path.open('wb') as f:
  for i in range(n//len(data)):f.write(data)
 memory=path.read_bytes();check(len(memory)==n,'input length');v=[]
 for rep in range(3):
  advised=False
  with path.open('rb') as f:
   if hasattr(os,'posix_fadvise'):
    try:os.posix_fadvise(f.fileno(),0,0,os.POSIX_FADV_DONTNEED);advised=True
    except OSError:pass
  t=time.perf_counter_ns();a=digestfile(path);read_ns=time.perf_counter_ns()-t;t=time.perf_counter_ns();b=sha256(memory);hash_ns=time.perf_counter_ns()-t;check(a==b,'digest mismatch');r=dict(rep=rep,bytes=n,read_digest_ns=read_ns,memory_digest_ns=hash_ns,eviction_advised=advised,strict_cold_cache=False,sha256=a);row(out/'raw.jsonl',r);v.append(r)
 path.unlink();return {'runs':v,'scope':'bounded synthetic specimen diagnostic; not model startup reproduction or guaranteed cold-cache isolation'}

MODS=dict(binding=binding,version_floor=version_floor,retention=retention,io_failure=io_failure,io_inner=io_inner,privacy=privacy,multiwriter=multiwriter,proxy_diagnostic=proxy_diagnostic,io_attribution=io_attribution)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--module',choices=MODS);ap.add_argument('--profile',choices=['classical','post_quantum']);ap.add_argument('--seed',type=int,default=20261124);ap.add_argument('--out',type=Path);ap.add_argument('--read-floor',type=Path);ap.add_argument('--authority');a=ap.parse_args()
 if a.read_floor:
  db=sqlite3.connect('file:'+str(a.read_floor)+'?mode=ro',uri=True);print(db.execute('SELECT version FROM floor WHERE authority=?',(a.authority,)).fetchone()[0]);db.close();return
 a.out.mkdir(parents=True,exist_ok=False)
 if a.module=='io_inner' and os.geteuid()==0:os.chown(a.out,int(os.environ['PQ_LAB_UID']),int(os.environ['PQ_LAB_GID']))
 start=time.time();cfg=json.loads((ROOT/'config/experiment.json').read_text())['cpu'];profile=build_profile(a.profile,sha256(b'PQGuard review strengthening branch v1'));atomic(a.out/'public_material.json',profile.export_public())
 try:
  result=MODS[a.module](a.out,profile,a.seed,cfg);atomic(a.out/'SUMMARY.json',dict(passed=True,module=a.module,profile=a.profile,seed=a.seed,started_unix_s=start,finished_unix_s=time.time(),elapsed_s=time.time()-start,result=result));print(json.dumps({'module':a.module,'profile':a.profile,'passed':True}),flush=True)
 except BaseException as e:
  (a.out/'ERROR.txt').write_text(traceback.format_exc());atomic(a.out/'SUMMARY.json',dict(passed=False,module=a.module,profile=a.profile,seed=a.seed,elapsed_s=time.time()-start,error_type=type(e).__name__,error=str(e)));raise
if __name__=='__main__':main()
