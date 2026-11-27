#!/usr/bin/env python3
"""Bounded server-side controller; no retries of completed measurements."""
import datetime,fcntl,json,os,subprocess,sys,time,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'));from runtime import atomic
def main():
 cfg=json.loads((ROOT/'config/experiment.json').read_text())['gpu'];assert datetime.datetime.now(datetime.timezone.utc)>=datetime.datetime.fromisoformat(cfg['not_before_utc'])
 subprocess.run([sys.executable,str(ROOT/'scripts/gpu_time_gate.py')],check=True)
 import hashlib
 sources=json.loads((ROOT/'evidence/GPU_SOURCE_SHA256.json').read_text());assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value for name,value in sources.items()),'Frozen GPU source changed'
 (ROOT/'state').mkdir(exist_ok=True);lock=(ROOT/'state/gpu.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 # Also honor the old campaign lock to avoid competing with an unfinished old job.
 old=Path('/root/autodl-tmp/pqguard_gpu_batch_20261123/work/gpu_campaign.lock')
 if old.exists():
  oldlock=old.open('r');fcntl.flock(oldlock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 assert json.loads((ROOT/'evidence/CPU_DONE.json').read_text()).get('passed')
 run='joint_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');entries=[]
 for phase,seeds in [('pilot',[20261122]),('formal',cfg['seeds'])]:
  for k,seed in enumerate(seeds):
   for place in (['local','remote'] if k%2==0 else ['remote','local']):
    rid=run+'_'+phase+'_'+place;out=ROOT/'runs'/rid/('seed_'+str(seed));log=ROOT/'logs'/f'{rid}_{seed}.log';cmd=[sys.executable,str(ROOT/'scripts/gpu_joint.py'),'--seed',str(seed),'--run-id',rid,'--placement',place]+(['--pilot'] if phase=='pilot' else [])
    atomic(ROOT/'state/GPU_STATUS.json',dict(status='RUNNING',run_id=run,phase=phase,placement=place,seed=seed,entries=entries))
    with log.open('w') as f:
     try:
      child=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,start_new_session=True);rc=child.wait(timeout=21600)
     except subprocess.TimeoutExpired:
      os.killpg(child.pid,signal.SIGTERM)
      try:child.wait(timeout=30)
      except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
      rc=124
    done=json.loads((out/'DONE.json').read_text()) if (out/'DONE.json').exists() else {};passed=rc==0 and done.get('all_performance_pass',False)
    item=dict(phase=phase,placement=place,seed=seed,returncode=rc,passed=passed,output=str(out.relative_to(ROOT)));entries.append(item)
    if not passed:
     atomic(ROOT/'state/GPU_STATUS.json',dict(status='STOPPED_FAILURE',entries=entries,reason='No failed measured cells are rerun or overwritten; inspect retained attempts first'));return 1
 atomic(ROOT/'state/GPU_STATUS.json',dict(status='COMPUTE_COMPLETE_PENDING_INDEPENDENT_AUDIT',entries=entries,expected_formal_cells=48,expected_measured=6144));return subprocess.run([sys.executable,str(ROOT/'scripts/audit_gpu.py')]).returncode
if __name__=='__main__':raise SystemExit(main())
