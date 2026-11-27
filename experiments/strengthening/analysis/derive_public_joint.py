#!/usr/bin/env python3
"""Portable raw-record reanalysis. No GPU, network or private keys required."""
import argparse,csv,json,statistics
from pathlib import Path
def pct(v,q):
 a=sorted(v);z=(len(a)-1)*q;i=int(z);return a[i]+(a[min(i+1,len(a)-1)]-a[i])*(z-i)
def main():
 p=argparse.ArgumentParser();p.add_argument('--gpu-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
 index=json.loads((a.gpu_root/'analysis/GPU_INDEPENDENT_AUDIT.json').read_text())
 for x in index['results']:
  case=a.gpu_root/x['case'];raw=[json.loads(v) for v in (case/'requests.jsonl').read_text().splitlines()];m=[v for v in raw if v['phase']=='measured'];s=json.loads((case/'COMPLETE.json').read_text());assert len(m)==128
  ok=[v for v in m if v['success']];rows.append(dict(placement=x['placement'],seed=x['seed'],workload=x['workload'],concurrency=x['concurrency'],mode=x['mode'],measured=len(m),warmups=sum(v['phase']=='warmup' for v in raw),failures=len(m)-len(ok),p50_ms=pct([v['total_ns']/1e6 for v in ok],.5),p95_ms=pct([v['total_ns']/1e6 for v in ok],.95),throughput_requests_s=len(ok)/(s['wall_ns']/1e9),scheduler_max_running=s['actual_scheduler']['max_running'],source_case=x['case']))
 assert len(rows)==48 and sum(v['measured'] for v in rows)==6144
 with (a.output/'gpu_joint_cells.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 effects=[]
 for place in ['local','remote']:
  for workload in ['short','long']:
   for c in [1,32]:
    full={v['seed']:v for v in rows if (v['placement'],v['workload'],v['concurrency'],v['mode'])==(place,workload,c,'submitted_full')};merkle={v['seed']:v for v in rows if (v['placement'],v['workload'],v['concurrency'],v['mode'])==(place,workload,c,'merkle8')};assert len(full)==len(merkle)==3
    ratio=[merkle[s]['throughput_requests_s']/full[s]['throughput_requests_s'] for s in full];delta=[merkle[s]['p50_ms']-full[s]['p50_ms'] for s in full];effects.append(dict(placement=place,workload=workload,concurrency=c,mean_seed_ratio=statistics.mean(ratio),ratio_range=[min(ratio),max(ratio)],mean_paired_median_difference_ms=statistics.mean(delta),difference_range_ms=[min(delta),max(delta)]))
 (a.output/'effects.json').write_text(json.dumps(dict(statistical_unit='seed-cell statistic; observed ranges, not confidence intervals',effects=effects),indent=2));print(json.dumps(dict(cells=48,measured=6144,failures=sum(v['failures'] for v in rows))))
if __name__=='__main__':main()
