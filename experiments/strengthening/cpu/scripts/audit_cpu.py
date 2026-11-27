#!/usr/bin/env python3
"""Public-key/raw-data audit; does not import CPU experiment implementation."""
import argparse,hashlib,hmac,json,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from verify_artifacts import verify_sig,enc,h
from runtime import atomic

def rows(p):return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
def dbopen(p):
 d=sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True);assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok';return d

def audit_db(path,public):
 d=dbopen(path);n=0
 for sid,seq,hp,pol,sig,status in d.execute('SELECT * FROM admissions'):
  assert pol==public['policy_descriptor']['policy_digest'];verify_sig(public['identity'],public['identity_public_key'],enc(dict(kind='admission',sid=sid,seq=seq,prompt_hash=hp,policy=pol)),bytes(sig));n+=1
 tables={x[0] for x in d.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 if 'completions' in tables:
  previous='genesis'
  for sid,seq,rh,entry,digest,sig,counter,wd in d.execute('SELECT * FROM completions ORDER BY witness_counter'):
   x=json.loads(entry);assert x['previous']==previous and x['sid']==sid and x['seq']==seq and x['response_hash']==rh
   a=d.execute('SELECT prompt_hash,policy_digest FROM admissions WHERE sid=? AND seq=?',(sid,seq)).fetchone();assert a==(x['prompt_hash'],x['policy']);verify_sig(public['audit'],public['audit_public_key'],bytes(entry),bytes(sig));assert h(bytes(entry)+bytes(sig))==digest
   assert h(enc(dict(previous=previous,entry=digest,counter=counter)))==wd
   st,dd,ss,status=d.execute('SELECT stream,digest,signature,status FROM witness_outbox WHERE counter=?',(counter,)).fetchone();assert dd==wd;verify_sig(public['audit'],public['audit_public_key'],b'PQGUARD-WITNESS-V1\0'+enc(dict(stream=st,counter=counter,digest=dd)),bytes(ss));previous=wd;n+=2
 d.close();return n

def audit_one(path,module,cfg):
 q=json.loads((path/'SUMMARY.json').read_text());assert q['passed'];p=json.loads((path/'public_material.json').read_text());v=0;data=rows(path/'raw.jsonl') if (path/'raw.jsonl').exists() else []
 if module=='binding':
  assert len(data)==2*4*cfg['binding_records']
  for kind in ['cbas','conventional']:
   f=json.loads((path/(kind+'_fixtures.json')).read_text());rs=f['records'];assert len(rs)==cfg['binding_records']
   for x in rs:
    verify_sig(p['identity'],p['identity_public_key'],enc(x['admission']),bytes.fromhex(x['admission_signature']));verify_sig(p['audit'],p['audit_public_key'],enc(x['completion']),bytes.fromhex(x['completion_signature']));verify_sig(p['audit'],p['audit_public_key'],b'PQGUARD-WITNESS-V1\0'+enc(x['publication']),bytes.fromhex(x['publication_signature']));v+=3
   for x in [d for d in data if d['implementation']==kind]:
    i=x['index'];a=rs[i];other=rs[(i+1)%len(rs)];label=x['case'];b=other['completion'] if label=='completion_splice' else a['completion'];pub=other['publication'] if label in ['completion_splice','publication_splice'] else a['publication'];sig=other['completion_signature'] if label=='completion_splice' else a['completion_signature']
    components=label!='signature_corruption';bound=components and all(a['admission'][k]==b[k] for k in ['sid','seq','prompt_hash','policy']) and pub['digest']==h(enc(dict(previous=b['previous'],entry=h(enc(b)+bytes.fromhex(sig)),counter=pub['counter'])))
    assert x['component_signatures_valid']==components and x['lifecycle_relation_valid']==bound and bound==(label=='clean')
   v+=audit_db(path/(kind+'.sqlite'),p)
 elif module=='version_floor':
  f=json.loads((path/'public_fixtures.json').read_text())
  for k in ['1','2']:verify_sig(p['identity'],p['policy_public_key'],enc(f['v'+k]),bytes.fromhex(f['s'+k]));v+=1
  verify_sig(p['audit'],p['audit_public_key'],enc(f['reference']['value']),bytes.fromhex(f['reference']['signature']));v+=1
  assert len(data)==25 and all(x['decision']=='older_version' for x in data[:-1]);assert data[-1]['local_only']=='accepted' and data[-1]['separately_retained_reference']=='local_floor_rollback'
  d=dbopen(path/'floor.sqlite');assert d.execute('SELECT version FROM floor').fetchone()==(2,);d.close()
 elif module=='retention':
  assert [x['records'] for x in data if x['case']=='capacity']==cfg['capacity_sizes'];assert sum(x['case']=='retired_reject' for x in data)==3
  d=dbopen(path/'capacity.sqlite');assert d.execute('SELECT count(*) FROM admissions').fetchone()[0]==max(cfg['capacity_sizes']);d.close();v+=audit_db(path/'capacity.sqlite',p);v+=audit_db(path/'retirement.sqlite',p)
  d=dbopen(path/'retirement.sqlite');assert d.execute('SELECT status FROM session_state').fetchone()==('retired',);assert d.execute('SELECT count(*) FROM admissions').fetchone()==(1,);d.close()
 elif module=='io_failure':
  inner=path/'actual';data=rows(inner/'raw.jsonl');pub=json.loads((inner/'public_material.json').read_text());assert {x['case'] for x in data}=={'admission','completion','witness'}
  for x in data:
   assert x['os_errno']==28 and not x['response_released'] and x['error'] is not None;v+=audit_db(inner/x['case']/'producer_after.sqlite',pub);d=dbopen(inner/x['case']/'witness_after.sqlite');d.close()
  d=dbopen(inner/'witness/producer_after.sqlite');assert d.execute("SELECT count(*) FROM witness_outbox WHERE status!='published'").fetchone()==(0,);d.close()
 elif module=='privacy':
  assert len(data)==100 and all(x['public_dictionary_match'] and not x['keyed_value_in_unkeyed_dictionary'] for x in data)
  dictionary={h(('test-prompt-'+str(i)).encode()) for i in range(1000)}
  for x in data:assert x['unkeyed_digest']==h(('test-prompt-'+str(x['index'])).encode()) and x['keyed_commitment'] not in dictionary
  f=json.loads((path/'public_vector.json').read_text());assert hmac.digest(bytes.fromhex(f['test_key_hex']),bytes.fromhex(f['message_hex']),'sha256').hex()==f['expected']
 elif module=='multiwriter':
  a=rows(path/'attempts.jsonl');n=cfg['multiwriter_processes'];g=cfg['multiwriter_groups'];assert len(a)==2*n*g and len(data)==2*g
  for cond,expected in [('shared_store',1),('independent_stores',n)]:
   aa=[x for x in a if x['case']==cond];assert len({x['worker_pid'] for x in aa})==n
   for group in range(g):
    subset=[x for x in aa if x['group']==group];assert len(subset)==n and sum(x['accepted'] for x in subset)==expected
  for name,count in [('shared',g)]+[('independent_'+str(i),g) for i in range(n)]:
   d=dbopen(path/(name+'.sqlite'));assert d.execute('SELECT count(*) FROM admissions').fetchone()==(count,);d.close();v+=audit_db(path/(name+'.sqlite'),p)
 elif module=='proxy_diagnostic':
  cells=q['result']['cells'];assert len(cells)==12
  for c in cells:
   raw=rows(path/f"cell_{c['cell']:02}"/'raw.jsonl');assert len(raw)==max(cfg['proxy_requests'],c['concurrency']) and c['successes']==sum(x['ok'] for x in raw);assert all(x['total_ns']>0 for x in raw)
   assert c['timeouts']==sum(x['error'] in ['TimeoutError','timeout'] for x in raw)
   v+=audit_db(path/f"cell_{c['cell']:02}"/'server.sqlite',p)
 elif module=='io_attribution':
  n=cfg['io_sample_mib']*1024*1024;chunk=hashlib.sha256(str(q['seed']).encode()).digest()*32768;hh=hashlib.sha256()
  for _ in range(n//len(chunk)):hh.update(chunk)
  assert len(data)==3 and all(x['bytes']==n and x['sha256']==hh.hexdigest() and x['read_digest_ns']>0 and x['memory_digest_ns']>0 and not x['strict_cold_cache'] for x in data)
 else:raise ValueError(module)
 return dict(module=module,signatures_verified=v,raw_rows=len(data),passed=True)

def main():
 cfg=json.loads((ROOT/'config/experiment.json').read_text())['cpu'];s=json.loads((ROOT/'state/CPU_STATUS.json').read_text());assert s['expected']==48 and s['finished']==48 and s['status']=='COMPLETE' and s['passed']==48
 source=json.loads((ROOT/'evidence/CPU_SOURCE_SHA256.json').read_text());changed=[name for name,value in source.items() if h((ROOT/name).read_bytes())!=value];assert not changed,changed
 by={x['key']:x for x in s['entries']};results=[];errors=[]
 for mod in cfg['modules']:
  for profile in cfg['profiles']:
   for seed in cfg['seeds']:
    key=f'{mod}__{profile}__{seed}'
    try:
     item=by[key];assert item['passed'];p=ROOT/item['summary'];result=audit_one(p.parent,mod,cfg);result.update(key=key,summary=item['summary']);results.append(result)
    except Exception as e:errors.append(dict(key=key,error_type=type(e).__name__,error=str(e)))
 report=dict(passed=len(results)==48 and not errors,expected=48,verified=len(results),errors=errors,results=results,finished_unix_s=time.time(),scope='raw counts, public signatures and SQLite state; finite component tests, not full AKE/consensus/attestation; private commitment key intentionally not exported')
 atomic(ROOT/'evidence/CPU_INDEPENDENT_AUDIT.json',report)
 if report['passed']:atomic(ROOT/'evidence/CPU_DONE.json',dict(passed=True,independent_audit=True,quick=False,tasks=48,signatures_verified=sum(x['signatures_verified'] for x in results),audit_sha256=h((ROOT/'evidence/CPU_INDEPENDENT_AUDIT.json').read_bytes()),finished_unix_s=time.time()))
 print(json.dumps({k:report[k] for k in ['passed','expected','verified','errors']}));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
