import datetime,json,subprocess,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
g=json.loads((ROOT/'config/experiment.json').read_text())['gpu']
assert datetime.datetime.now(datetime.timezone.utc)>=datetime.datetime.fromisoformat(g['not_before_utc']),'Before 14:30 CST'
assert json.loads((ROOT/'evidence/CPU_DONE.json').read_text()).get('independent_audit'),'CPU independent audit has not passed'
assert json.loads((ROOT/'evidence/GPU_PREPARED.json').read_text())['model_hashes_passed'],'Model hashes pending'
cores=len(os.sched_getaffinity(0))
v1=Path('/sys/fs/cgroup/cpu/cpu.cfs_quota_us');v2=Path('/sys/fs/cgroup/cpu.max')
if v1.exists():
 quota=int(v1.read_text());period=int(v1.with_name('cpu.cfs_period_us').read_text())
 if quota>0:cores=min(cores,quota/period)
elif v2.exists():
 quota,period=v2.read_text().split()
 if quota!='max':cores=min(cores,int(quota)/int(period))
mem=Path('/sys/fs/cgroup/memory/memory.limit_in_bytes');mem2=Path('/sys/fs/cgroup/memory.max');limit=int(mem.read_text()) if mem.exists() else int(mem2.read_text()) if mem2.exists() and mem2.read_text().strip()!='max' else int(os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES'))
assert cores>=14 and limit>=120*1024**3, f'Need >=14 CPU quota and >=120 GiB, observed {cores} CPU/{limit} bytes'
r=subprocess.run(['nvidia-smi','--query-gpu=name,memory.total','--format=csv,noheader,nounits'],capture_output=True,text=True);assert r.returncode==0 and 'A800' in r.stdout and int(r.stdout.split(',')[-1].strip())>75000,'A800 80GB not available'
active=subprocess.run(['nvidia-smi','--query-compute-apps=pid','--format=csv,noheader,nounits'],capture_output=True,text=True)
assert active.returncode==0 and not active.stdout.strip(),'Existing GPU compute job: do not compete'
p=ROOT/'evidence/GPU_RESOURCE_GATE.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(dict(cpu_quota=cores,memory_limit_bytes=limit,gpu=r.stdout.strip(),checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()),indent=2));os.replace(t,p)
print('TIME_AND_RESOURCE_GATE_PASS')
