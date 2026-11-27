#!/usr/bin/env python3
"""Bounded, restartable CPU campaign. Completed attempts are never overwritten."""
import argparse,datetime,fcntl,hashlib,json,os,subprocess,sys,time,traceback,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def atomic(p,v):
 p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(v,indent=2,sort_keys=True));os.replace(t,p)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');a=ap.parse_args();(ROOT/'state').mkdir(exist_ok=True);lock=(ROOT/'state/cpu.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 cfg=json.loads((ROOT/'config/experiment.json').read_text())['cpu'];modules=cfg['modules'];seeds=cfg['seeds'][:1] if a.quick else cfg['seeds'];profiles=['classical'] if a.quick else cfg['profiles']
 entries=[];expected=len(modules)*len(seeds)*len(profiles);run='cpu_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');(ROOT/'logs').mkdir(exist_ok=True)
 atomic(ROOT/'evidence/CPU_SOURCE_SHA256.json',{str(p.relative_to(ROOT)):sha(p) for d in ['scripts','vendor','config'] for p in (ROOT/d).rglob('*') if p.is_file() and p.suffix not in ['.pyc']})
 for module in modules:
  for profile in profiles:
   for seed in seeds:
    key=f'{module}__{profile}__{seed}';base=ROOT/'raw/cpu'/key;base.mkdir(parents=True,exist_ok=True);existing=sorted(base.glob('attempt_*/SUMMARY.json'))
    valid=[p for p in existing if json.loads(p.read_text()).get('passed')]
    if valid:
     entries.append({'key':key,'summary':str(valid[-1].relative_to(ROOT)),'passed':True,'reused':True});continue
    attempt=len(list(base.glob('attempt_*')))+1
    if attempt>2:entries.append({'key':key,'passed':False,'error':'retry_limit'});continue
    out=base/f'attempt_{attempt:02}';log=ROOT/'logs'/f'{key}_attempt_{attempt:02}.log';cmd=[sys.executable,str(ROOT/'scripts/cpu_experiments.py'),'--module',module,'--profile',profile,'--seed',str(seed),'--out',str(out)]
    atomic(ROOT/'state/CPU_STATUS.json',dict(status='RUNNING',run_id=run,expected=expected,finished=len(entries),current=key,attempt=attempt,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),entries=entries))
    start=time.monotonic()
    with log.open('w') as f:
     try:
      child=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,start_new_session=True);rc=child.wait(timeout=900)
     except subprocess.TimeoutExpired:
      os.killpg(child.pid,signal.SIGTERM)
      try:child.wait(timeout=10)
      except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
      rc=124
    result=json.loads((out/'SUMMARY.json').read_text()) if (out/'SUMMARY.json').exists() else {'passed':False,'error':'no_summary','returncode':rc}
    item={'key':key,'summary':str((out/'SUMMARY.json').relative_to(ROOT)),'passed':bool(rc==0 and result.get('passed')),'returncode':rc,'elapsed_s':time.monotonic()-start,'log':str(log.relative_to(ROOT))};entries.append(item);print(json.dumps(item),flush=True)
    with (ROOT/'evidence/CPU_COMMANDS.jsonl').open('a') as f:f.write(json.dumps({'command':cmd,'result':item})+'\n')
 atomic(ROOT/'state/CPU_STATUS.json',dict(status='COMPLETE' if all(x['passed'] for x in entries) else 'COMPLETE_WITH_FAILURES',expected=expected,finished=len(entries),passed=sum(x['passed'] for x in entries),entries=entries))
 if all(x['passed'] for x in entries):atomic(ROOT/'evidence/CPU_RUN_COMPLETE.json',dict(passed=True,tasks=len(entries),quick=a.quick,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='component strengthening tests, not full AKE/attestation/consensus or GPU measurement'))
 return 0 if all(x['passed'] for x in entries) else 1
if __name__=='__main__':raise SystemExit(main())
