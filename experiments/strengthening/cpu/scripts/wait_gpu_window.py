#!/usr/bin/env python3
"""Wait for CPU independent audit and user-enabled GPU; never enable/rent GPU."""
import datetime,fcntl,hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'vendor'))
from runtime import atomic
def rpc(value):
 import socket
 c=json.loads((ROOT/'private/link.json').read_text())
 with socket.create_connection(('127.0.0.1',c['local_forward_port']),timeout=10) as s:
  s.settimeout(10);s.sendall(json.dumps(value).encode()+b'\n');f=s.makefile('rb');return json.loads(f.readline(2_000_000))
def main():
 lock=(ROOT/'state/waiter.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 gate=datetime.datetime.fromisoformat(json.loads((ROOT/'config/experiment.json').read_text())['gpu']['not_before_utc']);deadline=time.monotonic()+12*3600;last_error=None
 while time.monotonic()<deadline:
  if (ROOT/'state/GPU_STATUS.json').exists():
   state=json.loads((ROOT/'state/GPU_STATUS.json').read_text());atomic(ROOT/'state/GPU_WAIT_STATUS.json',dict(status='EXISTING_GPU_RUN_NO_DUPLICATE',gpu_status=state.get('status')));return 0
  done=False
  try:
   a=rpc({'op':'cpu_status'})
   if a['ok']:
    d=a['done'];report=a['audit'];assert d['passed'] and d['independent_audit'] and not d['quick'] and d['tasks']==48
    assert report['passed'] and report['verified']==48 and not report['errors'];assert hashlib.sha256(a['audit_text'].encode()).hexdigest()==d['audit_sha256']
    p=ROOT/'evidence/CPU_INDEPENDENT_AUDIT.json';tmp=p.with_suffix('.tmp');tmp.write_text(a['audit_text']);os.replace(tmp,p);atomic(ROOT/'evidence/CPU_DONE.json',d);done=True
  except Exception as e:last_error=type(e).__name__+': '+str(e)[:200]
  now=datetime.datetime.now(datetime.timezone.utc)
  if not done:status='WAITING_CPU_INDEPENDENT_AUDIT'
  elif now<gate:status='WAITING_1430_CST'
  elif not (ROOT/'evidence/GPU_PREPARED.json').exists():status='WAITING_MODEL_HASHES'
  else:
   q=subprocess.run([sys.executable,str(ROOT/'scripts/gpu_time_gate.py')],capture_output=True,text=True)
   if q.returncode:status='WAITING_USER_ENABLED_A800'
   else:
    subprocess.run([sys.executable,str(ROOT/'scripts/preflight_joint_cpu.py')],check=True)
    atomic(ROOT/'state/GPU_WAIT_STATUS.json',dict(status='STARTING_AFTER_TIME_AND_AUDIT_GATES',started_utc=now.isoformat()))
    return subprocess.run([sys.executable,'-u',str(ROOT/'scripts/run_gpu_joint.py')]).returncode
  atomic(ROOT/'state/GPU_WAIT_STATUS.json',dict(status=status,not_before_utc=gate.isoformat(),cpu_independent_done=done,last_observation_error=last_error,checked_utc=now.isoformat()));time.sleep(60)
 atomic(ROOT/'state/GPU_WAIT_STATUS.json',dict(status='STOPPED_WAIT_LIMIT',last_observation_error=last_error));return 1
if __name__=='__main__':raise SystemExit(main())
