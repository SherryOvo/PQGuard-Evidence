import json,socket,sqlite3,os
from pathlib import Path
from runtime import atomic,WitnessProcess
ROOT=Path(__file__).resolve().parents[1]
class PinnedLocalWitness(WitnessProcess):
 def start(self):
  super().start()
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(self.proc.pid,{min(os.sched_getaffinity(0))})
class RemoteWitness:
 def __init__(self,case,public,stream):
  self.case,self.stream=Path(case),stream;self.port=json.loads((ROOT/'private/link.json').read_text())['local_forward_port']
  atomic(self.case/'registry.json',{stream:dict(algorithm=public['audit'],public_key_hex=public['audit_public_key'])})
  ans=self.request(dict(op='init',stream=stream,algorithm=public['audit'],public_key_hex=public['audit_public_key']));assert ans['ok'],ans
  atomic(self.case/'witness_ready.json',{'host':'127.0.0.1','port':self.port,'placement':'remote_host_over_pinned_SSH'})
 def request(self,value):
  with socket.create_connection(('127.0.0.1',self.port),timeout=90) as c:
   c.settimeout(90);c.sendall(json.dumps(value).encode()+b'\n');f=c.makefile('rb');return json.loads(f.readline(8_000_000))
 def publish(self,stream,counter,digest,signature):return self.request(dict(op='publish',stream=stream,counter=counter,digest=digest,signature_hex=signature.hex()))
 def close(self):
  ans=self.request(dict(op='snapshot',stream=self.stream));assert ans['ok'],ans
  x=ans['row'];p=self.case/'witness.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE heads(stream TEXT PRIMARY KEY,counter INTEGER NOT NULL,digest TEXT NOT NULL,signature BLOB NOT NULL,algorithm TEXT NOT NULL)');db.execute('INSERT INTO heads VALUES(?,?,?,?,?)',(x[0],x[1],x[2],bytes.fromhex(x[3]),x[4]));db.commit();db.close();atomic(self.case/'remote_snapshot.json',ans)
