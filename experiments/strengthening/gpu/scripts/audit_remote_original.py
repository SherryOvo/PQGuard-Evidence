#!/usr/bin/env python3
"""Compare the actual Oracle witness export with producer evidence and ACK logs.
Uses public keys only. No measurement driver/profile/store module is imported.
"""
import hashlib,json,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from verify_artifacts import verify_sig,enc
from runtime import atomic
def message(stream,counter,digest):
 return b'PQGUARD-WITNESS-V1\0'+enc(dict(stream=stream,counter=counter,digest=digest))
def main():
 original=ROOT/'remote_original'
 for name,value in json.loads((original/'SHA256.json').read_text()).items():assert hashlib.sha256((original/name).read_bytes()).hexdigest()==value,name
 registry=json.loads((original/'registry.json').read_text());db=sqlite3.connect('file:'+str(original/'witness_original.sqlite')+'?mode=ro',uri=True);assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
 heads={}
 for stream,counter,digest,sig,algorithm in db.execute('SELECT stream,counter,digest,signature,algorithm FROM heads'):
  pk=registry[stream];assert pk['algorithm']==algorithm;verify_sig(algorithm,pk['public_key_hex'],message(stream,counter,digest),bytes(sig));heads[stream]=[stream,counter,digest,bytes(sig).hex(),algorithm]
 db.close();acks=set();rpc_rows=0
 for line in (original/'rpc.jsonl').read_text().splitlines():
  r=json.loads(line);rpc_rows+=1;reply=r.get('reply',{})
  if r.get('op')=='publish' and reply.get('ok'):
   assert reply['counter']==r['counter'];acks.add((r['stream'],reply['counter'],reply['digest']))
 audit=json.loads((ROOT/'analysis/GPU_INDEPENDENT_AUDIT.json').read_text());assert audit['passed'];results=[];checkpoint_total=0
 for item in audit['results']:
  if item['placement']!='remote':continue
  case=ROOT/item['case'];pub=json.loads((case/'public_material.json').read_text());snapshot=json.loads((case/'remote_snapshot.json').read_text());row=snapshot['row'];stream=row[0];assert snapshot['ok'] and row==heads[stream],item['case'];assert registry[stream]==dict(algorithm=pub['audit'],public_key_hex=pub['audit_public_key'])
  producer=sqlite3.connect('file:'+str(case/'lifecycle.sqlite')+'?mode=ro',uri=True);tables={x[0] for x in producer.execute("SELECT name FROM sqlite_master WHERE type='table'")};checkpoints=[]
  if 'batches' in tables:
   for counter,header,sig,digest,wsig,status,*rest in producer.execute('SELECT * FROM batches ORDER BY counter'):
    assert json.loads(header)['stream']==stream and status=='published';checkpoints.append((counter,digest,bytes(wsig)))
  else:
   for st,counter,digest,sig,status in producer.execute('SELECT stream,counter,digest,signature,status FROM witness_outbox ORDER BY counter'):
    assert st==stream and status=='published';checkpoints.append((counter,digest,bytes(sig)))
  producer.close();assert [x[0] for x in checkpoints]==list(range(1,len(checkpoints)+1))
  for counter,digest,sig in checkpoints:
   verify_sig(pub['audit'],pub['audit_public_key'],message(stream,counter,digest),sig);assert (stream,counter,digest) in acks,(item['case'],counter)
  assert checkpoints and (checkpoints[-1][0],checkpoints[-1][1])==(row[1],row[2]);checkpoint_total+=len(checkpoints)
  results.append(dict(case=item['case'],stream=stream,checkpoints=len(checkpoints),actual_original_head_matches=True,all_signed_publications_have_remote_ack=True))
 assert len(results)==24 and len({x['stream'] for x in results})==24
 report=dict(passed=True,actual_remote_heads_verified=len(heads),formal_remote_cells=24,formal_publication_signatures_verified=checkpoint_total,formal_publications_with_remote_ack=checkpoint_total,rpc_rows=rpc_rows,results=results,finished_unix_s=time.time(),scope='actual separately retrieved Oracle SQLite backup and RPC ACK coverage; not Byzantine-witness tolerance or a cross-host clock-order proof')
 atomic(ROOT/'analysis/REMOTE_ORIGINAL_WITNESS_AUDIT.json',report)
 ready=json.loads((ROOT/'evidence/READY_TO_RELEASE_GPU.json').read_text());ready['remote_original_db_verified']=True;ready['scope']='GPU compute and original remote DB verification complete; local final archive transfer/checksums pending';atomic(ROOT/'evidence/READY_TO_RELEASE_GPU.json',ready)
 print(json.dumps({k:v for k,v in report.items() if k!='results'}))
if __name__=='__main__':main()
