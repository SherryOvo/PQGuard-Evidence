#!/usr/bin/env python3
"""Additional isolated state-extension tests, separate from frozen 48-task batch.
No GPU import. This extension is NOT claimed to exist in the submitted code.
"""
import argparse,concurrent.futures,hashlib,json,multiprocessing,os,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'vendor'),str(ROOT/'scripts')]
from r7_crypto_profiles import build_profile,canonical,sha256
from verify_artifacts import verify_sig
from runtime import atomic

class Gate:
 def __init__(self,path,original):
  self.db=sqlite3.connect(path,timeout=30);self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
  self.db.execute('CREATE TABLE IF NOT EXISTS state(lineage TEXT PRIMARY KEY,algorithm TEXT,pk TEXT,floor INTEGER,descriptor TEXT)');self.db.execute('INSERT OR IGNORE INTO state VALUES(?,?,?,?,?)',('research-policy',original.identity_algorithm,original.policy_public.hex(),0,''));self.db.commit();self.expected=original.policy_digest
 def accept(self,descriptor,sig,crash=None):
  self.db.execute('BEGIN IMMEDIATE')
  alg,pk,floor,prior=self.db.execute('SELECT algorithm,pk,floor,descriptor FROM state').fetchone();msg=canonical(descriptor)
  try:verify_sig(alg,pk,msg,sig)
  except Exception:self.db.rollback();return 'invalid_signature'
  if descriptor['policy_digest']!=self.expected:self.db.rollback();return 'wrong_digest'
  now=int(time.time())
  if not descriptor['valid_from']<=now<=descriptor['valid_until']:self.db.rollback();return 'expired_or_not_yet_valid'
  if not isinstance(descriptor.get('version'),int) or isinstance(descriptor['version'],bool):self.db.rollback();return 'invalid_version'
  version=descriptor['version'];fingerprint=sha256(msg)
  if version<floor:self.db.rollback();return 'old_version'
  if version==floor and prior and fingerprint!=prior:self.db.rollback();return 'same_version_conflict'
  self.db.execute('UPDATE state SET floor=?,descriptor=?',(version,fingerprint))
  if crash=='before_commit':os._exit(73)
  self.db.commit()
  if crash=='after_commit':os._exit(74)
  return 'accepted'
 def rotate(self,message,old_sig,new_sig):
  self.db.execute('BEGIN IMMEDIATE');alg,pk,floor,prior=self.db.execute('SELECT algorithm,pk,floor,descriptor FROM state').fetchone()
  try:
   assert message['kind']=='authority_rotation_v1' and message['lineage']=='research-policy' and message['old_public_key']==pk and message['floor']==floor
   verify_sig(alg,pk,canonical(message),old_sig);verify_sig(message['new_algorithm'],message['new_public_key'],canonical(message),new_sig)
  except Exception:self.db.rollback();return 'invalid_rotation'
  self.db.execute('UPDATE state SET algorithm=?,pk=?',(message['new_algorithm'],message['new_public_key']));self.db.commit();return 'accepted'
 def close(self):self.db.close()

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--profile',required=True);ap.add_argument('--seed',type=int,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=False)
 p=build_profile(a.profile,sha256(b'new state-edge extension'));p2=build_profile(a.profile,p.policy_digest);atomic(a.out/'public_material.json',dict(original=p.export_public(),rotated=p2.export_public()));raw=[];fixtures=[]
 def record(case,actual,expected):
  x=dict(case=case,actual=actual,expected=expected,passed=actual==expected);raw.append(x)
  with (a.out/'raw.jsonl').open('a') as f:f.write(json.dumps(x)+'\n')
  assert x['passed'],x
 def signed(version,**kw):
  d=dict(p.policy_descriptor,version=version,**kw);sig=p.sign_policy(canonical(d));fixtures.append(dict(descriptor=d,signature=sig.hex(),signer='original'));return d,sig
 path=a.out/'version.sqlite';d1,s1=signed(1);d2,s2=signed(2);g=Gate(path,p);record('initial',g.accept(d1,s1),'accepted');record('upgrade',g.accept(d2,s2),'accepted');record('old_valid',g.accept(d1,s1),'old_version');record('same_exact',g.accept(d2,s2),'accepted')
 conflict,sc=signed(2,annotation='different admitted material');record('same_version_different_material',g.accept(conflict,sc),'same_version_conflict');wrong,sw=signed(3,policy_digest=sha256(b'wrong'));record('wrong_digest',g.accept(wrong,sw),'wrong_digest')
 expired,se=signed(3,valid_until=int(time.time())-1);record('expired',g.accept(expired,se),'expired_or_not_yet_valid');bad=bytearray(s2);bad[0]^=1;record('invalid_signature',g.accept(d2,bytes(bad)),'invalid_signature');g.close()
 # Threaded independent connections contend on one actual SQLite transaction store.
 candidates=[signed(i) for i in range(3,11)]
 def worker(pair):
  gate=Gate(path,p)
  try:return gate.accept(*pair)
  finally:gate.close()
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:decisions=list(pool.map(worker,reversed(candidates)))
 d=sqlite3.connect(path);record('concurrent_floor_max',d.execute('SELECT floor FROM state').fetchone()[0],10);d.close()
 for i,decision in enumerate(decisions):assert decision in ['accepted','old_version']
 atomic(a.out/'concurrent.json',dict(versions=list(range(10,2,-1)),decisions=decisions,expected_final_floor=10))
 # Child exits before/after SQLite commit, no graceful store close.
 for point,target,expected in [('before_commit',11,10),('after_commit',12,12)]:
  desc,sig=signed(target);pid=os.fork()
  if pid==0:
   gate=Gate(path,p);gate.accept(desc,sig,point);os._exit(99)
  _,status=os.waitpid(pid,0);record(point+'_exit',os.waitstatus_to_exitcode(status),73 if point=='before_commit' else 74)
  d=sqlite3.connect(path);record(point+'_durable_floor',d.execute('SELECT floor FROM state').fetchone()[0],expected);record(point+'_db_integrity',d.execute('PRAGMA integrity_check').fetchone()[0],'ok');d.close()
 # Rotation must be authorized by both old and new authority; floor is preserved.
 g=Gate(path,p);rotation=dict(kind='authority_rotation_v1',lineage='research-policy',old_public_key=p.policy_public.hex(),new_algorithm=p2.identity_algorithm,new_public_key=p2.policy_public.hex(),floor=12);ro=p.sign_policy(canonical(rotation));rn=p2.sign_policy(canonical(rotation));bad=bytearray(ro);bad[0]^=1;record('unauthorized_rotation',g.rotate(rotation,bytes(bad),rn),'invalid_rotation');record('authorized_rotation',g.rotate(rotation,ro,rn),'accepted');record('old_authority_after_rotation',g.accept(d2,s2),'invalid_signature')
 new=dict(p2.policy_descriptor,version=13);ns=p2.sign_policy(canonical(new));record('new_authority_upgrade',g.accept(new,ns),'accepted');g.close()
 g=Gate(path,p);record('restart_reject_old_authority',g.accept(d2,s2),'invalid_signature');record('restart_same_new_certificate',g.accept(new,ns),'accepted');g.close()
 fixtures.append(dict(descriptor=new,signature=ns.hex(),signer='rotated'));atomic(a.out/'fixtures.json',dict(certificates=fixtures,rotation=rotation,old_signature=ro.hex(),new_signature=rn.hex()))
 # Independent public-key check of every exported valid certificate/rotation.
 public={'original':p.export_public(),'rotated':p2.export_public()};verified=0
 for f in fixtures:
  pub=public[f['signer']];verify_sig(pub['identity'],pub['policy_public_key'],canonical(f['descriptor']),bytes.fromhex(f['signature']));verified+=1
 for pub,sig in [(public['original'],ro),(public['rotated'],rn)]:verify_sig(pub['identity'],pub['policy_public_key'],canonical(rotation),sig);verified+=1
 summary=dict(passed=all(x['passed'] for x in raw),checks=len(raw),profile=a.profile,seed=a.seed,public_signatures_verified=verified,scope='new persistent-floor/rotation mechanism; process-exit SQLite recovery, not power-loss or whole-host rollback resistance; independent from original 48-task campaign')
 atomic(a.out/'SUMMARY.json',summary);print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
