#!/usr/bin/env python3
"""Independent recomputation. Pilot excluded; all failures remain visible."""
import csv,hashlib,json,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from verify_artifacts import verify_case
from runtime import atomic
def lines(p):return [json.loads(s) for s in p.read_text().splitlines() if s.strip()]
def main():
 s=json.loads((ROOT/'state/GPU_STATUS.json').read_text());assert s['status']=='COMPUTE_COMPLETE_PENDING_INDEPENDENT_AUDIT'
 c=json.loads((ROOT/'config/experiment.json').read_text())['gpu'];result=[];errors=[];totals=dict(cells=0,measured=0,warmups=0,failures=0,signatures=0,proofs=0);seen=set()
 for run in s['entries']:
  if run['phase']!='formal':continue
  out=ROOT/run['output'];expected={tuple(x) for x in json.loads((out/'schedule.json').read_text())};assert len(expected)==8
  completed=list(out.glob('*/COMPLETE.json'));assert len(completed)==8
  for p in completed:
   try:
    a=json.loads(p.read_text());key=(run['placement'],a['seed'],a['workload'],a['concurrency'],a['mode']);assert key not in seen;seen.add(key)
    assert (a['workload'],a['concurrency'],a['mode']) in expected
    raw=lines(p.parent/'requests.jsonl');measured=[x for x in raw if x['phase']=='measured'];warm=[x for x in raw if x['phase']=='warmup'];assert len(measured)==128 and len(warm)==8
    ok=[x for x in measured if x['success']];fail=len(measured)-len(ok);assert a['failures']==fail and a['successes']==len(ok);assert a['throughput_requests_s']==len(ok)/(a['wall_ns']/1e9)
    x=sorted(t['total_ns']/1e6 for t in ok);i=(len(x)-1)*.5;med=x[int(i)]+(x[min(int(i)+1,len(x)-1)]-x[int(i)])*(i-int(i));assert abs(a['latency_p50_ms']-med)<1e-8
    v=verify_case(p.parent);assert v['raw_bindings_verified']==sum(x['success'] for x in raw);assert a['max_client_inflight']<=a['concurrency'];assert a['actual_scheduler'], 'scheduler evidence absent'
    if run['placement']=='remote':assert (p.parent/'remote_snapshot.json').exists()
    totals['cells']+=1;totals['measured']+=len(measured);totals['warmups']+=len(warm);totals['failures']+=fail;totals['signatures']+=v['signatures_verified'];totals['proofs']+=v['inclusion_proofs']
    result.append(dict(placement=run['placement'],seed=a['seed'],workload=a['workload'],concurrency=a['concurrency'],mode=a['mode'],measured=len(measured),failures=fail,latency_p50_ms=med,throughput_requests_s=len(ok)/(a['wall_ns']/1e9),max_client_inflight=a['max_client_inflight'],scheduler=a['actual_scheduler'],case=str(p.parent.relative_to(ROOT))))
   except Exception as e:errors.append(dict(case=str(p.parent.relative_to(ROOT)),error_type=type(e).__name__,error=str(e)))
 assert totals['cells']==c['expected_cells'] and totals['measured']==c['expected_measured_requests'] and totals['warmups']==c['expected_warmups'] and not errors,errors
 r=dict(passed=True,totals=totals,results=result,errors=errors,finished_unix_s=time.time(),scope='GPU compute/raw/signature/proof audit; original remote witness DB still requires separate retrieval and head comparison; local/remote placement contrast confounds architecture/storage/SSH transport; three seed processes, no unsupported causal or paired-request CI')
 (ROOT/'analysis').mkdir(exist_ok=True);atomic(ROOT/'analysis/GPU_INDEPENDENT_AUDIT.json',r)
 fields=[k for k in result[0] if k!='scheduler']
 with (ROOT/'analysis/gpu_cells.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(result)
 atomic(ROOT/'evidence/READY_TO_RELEASE_GPU.json',dict(compute_finished=True,independent_gpu_counts_passed=True,failures=totals['failures'],local_transfer_verified=False,remote_original_db_verified=False,scope='GPU may be released retaining instance and data disk; collection/CPU-only remote DB verification remain'))
 print(json.dumps(totals))
if __name__=='__main__':main()
