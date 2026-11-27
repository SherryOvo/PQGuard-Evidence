#!/usr/bin/env python3
"""Experiment-only loopback RPC agent. Original signed witness state machine unchanged."""
import argparse,json,os,socketserver,sqlite3,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from r7_witness import WitnessStore
from r7_crypto_profiles import canonical
from runtime import atomic
ap=argparse.ArgumentParser();ap.add_argument('--port',type=int,default=0);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True)
registry=json.loads((a.out/'registry.json').read_text()) if (a.out/'registry.json').exists() else {};lock=threading.RLock();store=WitnessStore(a.out/'witness.sqlite',registry)
class H(socketserver.StreamRequestHandler):
 def handle(self):
  try:
   r=json.loads(self.rfile.readline(8_000_000));op=r.get('op')
   with lock:
    if op=='init':
     s=r['stream'];v=dict(algorithm=r['algorithm'],public_key_hex=r['public_key_hex'])
     if s in registry and registry[s]!=v:raise ValueError('stream key conflict')
     registry[s]=v;atomic(a.out/'registry.json',registry);ans={'ok':True}
    elif op=='publish':ans=store.publish(r)
    elif op=='fetch':ans=store.fetch(r['stream'])
    elif op=='snapshot':
     x=store.db.execute('SELECT stream,counter,digest,signature,algorithm FROM heads WHERE stream=?',(r['stream'],)).fetchone()
     ans={'ok':x is not None,'row':([x[0],x[1],x[2],bytes(x[3]).hex(),x[4]] if x else None),'provenance':'logical filtered snapshot of actual remote SQLite; full original DB retained separately'}
    elif op=='cpu_status':
     done=ROOT/'evidence/CPU_DONE.json';audit=ROOT/'evidence/CPU_INDEPENDENT_AUDIT.json'
     ans={'ok':done.exists() and audit.exists(),'done':json.loads(done.read_text()) if done.exists() else None,'audit':json.loads(audit.read_text()) if audit.exists() else None,'audit_text':audit.read_text() if audit.exists() else None}
    elif op=='health':ans={'ok':True,'pid':os.getpid(),'scope':'experiment-only original R7 witness over SSH forwarding'}
    else:ans={'ok':False,'reason':'unknown_operation'}
    with (a.out/'rpc.jsonl').open('a') as f:f.write(json.dumps({'utc':time.time(),'op':op,'stream':r.get('stream'),'counter':r.get('counter'),'reply':ans},sort_keys=True)+'\n')
   self.wfile.write(canonical(ans)+b'\n')
  except Exception as e:
   with lock:
    if store.db.in_transaction:store.db.rollback()
   self.wfile.write(canonical({'ok':False,'reason':type(e).__name__})+b'\n')
class S(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
server=S(('127.0.0.1',a.port),H);atomic(a.out/'READY.json',{'port':server.server_address[1],'pid':os.getpid()});server.serve_forever()
