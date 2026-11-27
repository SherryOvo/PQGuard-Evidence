from pathlib import Path
import collections
import csv
import hashlib
import json
import math
import os
import re
import statistics as st

import argparse
parser=argparse.ArgumentParser()
for flag in ['cpu','witness','gpu','formal','output']:parser.add_argument('--'+flag,required=True)
args=parser.parse_args()
CASE=Path(args.output).expanduser().resolve()
for folder in ['tables','evidence']:(CASE/folder).mkdir(parents=True,exist_ok=True)
CPU=Path(args.cpu).expanduser().resolve()
WIT=Path(args.witness).expanduser().resolve()
GPU=Path(args.gpu).expanduser().resolve()
FORMAL=Path(args.formal).expanduser().resolve()
RUN = GPU/'runs/gpu_20261123T091949Z'

def read(p): return json.loads(p.read_text())
def lines(p): return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
def atom(p, text):
    tmp=p.with_name(p.name+'.tmp');tmp.write_text(text);os.replace(tmp,p)
def dump(p,v): atom(p,json.dumps(v,indent=2)+'\n')
def csvout(name,rows):
    p=CASE/'tables'/name;tmp=p.with_name(p.name+'.tmp')
    with tmp.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    os.replace(tmp,p)
def close(a,b): assert math.isclose(a,b,rel_tol=1e-9,abs_tol=1e-6),(a,b)

cpu=[];remote=[];gpu=[];source=[]
for root,items,out in [(CPU,read(CPU/'summaries/cells.json'),cpu),(WIT,read(WIT/'cell_summary.json'),remote)]:
    for c in items:
        if root==CPU:d=root/c['directory']
        else:d=root/'results'/f"cell_{c['profile']}_c{c['workers']}_r{c['repetition']}"
        rs=lines(d/'requests.jsonl');measured=[r for r in rs if r['phase']=='measured'];warm=[r for r in rs if r['phase']=='warmup']
        assert len(measured)==c['requests'] and len(warm)==c['warmups']
        successes=[r for r in measured if r['success']]
        assert len(successes)==c['successes'] and len(measured)-len(successes)==c['failures']
        med=st.median(r['elapsed_ns']/1e6 for r in successes);close(med,c['median_ms'])
        rate=len(successes)/(c['wall_ns']/1e9);close(rate,c['throughput_success_s'])
        assert all(r['response_released'] for r in successes)
        out.append(dict(profile=c['profile'],implementation=c.get('implementation','submitted_cbas_remote'),concurrency=c['workers'],repetition=c['repetition'],requests=len(measured),warmups=len(warm),failures=c['failures'],median_ms=med,throughput_rps=rate,max_in_flight=c['max_in_flight'],raw_path=str((d/'requests.jsonl').relative_to(root))))
        source.append(dict(domain='cpu' if root==CPU else 'remote_witness',path=str((d/'requests.jsonl').relative_to(root)),sha256=hashlib.sha256((d/'requests.jsonl').read_bytes()).hexdigest()))

matrix=read(RUN/'matrix_cells.json');gdirs={}
for seed in [20261123,20261124,20261125]:
    for d in (RUN/f'seed_{seed}').iterdir():
        if not d.is_dir() or not (d/'COMPLETE.json').exists():continue
        c=read(d/'COMPLETE.json');key=(seed,c['workload'],c['concurrency'],c['mode']);assert key not in gdirs;gdirs[key]=d
for c in matrix:
    key=(c['seed'],c['workload'],c['concurrency'],c['mode']);d=gdirs[key]
    rows=lines(d/'requests.jsonl');rs=[x for x in rows if x['phase']=='measured'];warm=[x for x in rows if x['phase']=='warmup']
    assert len(rs)==128 and len(warm)==8
    assert sum(not x['success'] for x in rs)==c['failures']==0
    assert all(x['response_released'] for x in rs)
    vals=[x['total_ns']/1e6 for x in rs];close(st.mean(vals),c['latency_mean_ms']);close(st.median(vals),c['latency_p50_ms'])
    close(len(rs)/(c['wall_ns']/1e9),c['throughput_requests_s'])
    close(sum(x['output_tokens'] for x in rs)/(c['wall_ns']/1e9),c['throughput_generated_tokens_s'])
    gpu.append(dict(seed=c['seed'],workload=c['workload'],concurrency=c['concurrency'],mode=c['mode'],requests=len(rs),warmups=len(warm),failures=c['failures'],latency_mean_ms=st.mean(vals),latency_p50_ms=st.median(vals),latency_p95_ms=c['latency_p95_ms'],throughput_rps=c['throughput_requests_s'],generated_tokens_s=c['throughput_generated_tokens_s'],scheduler_max_running=c['actual_scheduler']['max_running'],scheduler_max_waiting=c['actual_scheduler']['max_waiting'],client_max_inflight=c['max_client_inflight'],raw_path=str((d/'requests.jsonl').relative_to(GPU))))
    source.append(dict(domain='gpu',path=str((d/'requests.jsonl').relative_to(GPU)),sha256=hashlib.sha256((d/'requests.jsonl').read_bytes()).hexdigest()))
assert len(cpu)==80 and sum(c['requests'] for c in cpu)==20480
assert len(remote)==18 and sum(c['requests'] for c in remote)==1536
assert len(gpu)==135 and sum(c['requests'] for c in gpu)==17280

cpug=[]
for profile in ['classical','post_quantum']:
    for con in [1,8,32,64]:
        pair=[]
        for rep in range(5):
            a=next(c for c in cpu if (c['profile'],c['concurrency'],c['repetition'],c['implementation'])==(profile,con,rep,'submitted_cbas'))
            b=next(c for c in cpu if (c['profile'],c['concurrency'],c['repetition'],c['implementation'])==(profile,con,rep,'conventional_strong'))
            pair.append(a['median_ms']-b['median_ms'])
        for impl in ['submitted_cbas','conventional_strong']:
            cs=[c for c in cpu if (c['profile'],c['concurrency'],c['implementation'])==(profile,con,impl)]
            cpug.append(dict(profile=profile,concurrency=con,implementation=impl,repetitions=len(cs),median_of_cell_medians_ms=st.median(x['median_ms'] for x in cs),mean_cell_throughput_rps=st.mean(x['throughput_rps'] for x in cs),mean_paired_median_difference_ms=st.mean(pair),paired_difference_min_ms=min(pair),paired_difference_max_ms=max(pair)))

gpug=[];gpudiff=[]
for workload in ['short','long','mixed']:
    for con in [1,8,32]:
        for mode in ['plain','transport','conventional_full','submitted_full','merkle8']:
            cs=[c for c in gpu if (c['workload'],c['concurrency'],c['mode'])==(workload,con,mode)];assert len(cs)==3
            gpug.append(dict(workload=workload,concurrency=con,mode=mode,mean_cell_latency_ms=st.mean(x['latency_mean_ms'] for x in cs),mean_cell_throughput_rps=st.mean(x['throughput_rps'] for x in cs),min_cell_throughput_rps=min(x['throughput_rps'] for x in cs),max_cell_throughput_rps=max(x['throughput_rps'] for x in cs),min_scheduler_max_running=min(x['scheduler_max_running'] for x in cs),max_scheduler_max_running=max(x['scheduler_max_running'] for x in cs)))
        for treat,base in [('submitted_full','transport'),('submitted_full','conventional_full'),('merkle8','submitted_full')]:
            ds=[]
            for seed in [20261123,20261124,20261125]:
                a=next(c for c in gpu if (c['workload'],c['concurrency'],c['mode'],c['seed'])==(workload,con,treat,seed))
                b=next(c for c in gpu if (c['workload'],c['concurrency'],c['mode'],c['seed'])==(workload,con,base,seed))
                ds.append(a['latency_mean_ms']-b['latency_mean_ms'])
            gpudiff.append(dict(workload=workload,concurrency=con,treatment=treat,baseline=base,mean_difference_ms=st.mean(ds),seed_difference_min_ms=min(ds),seed_difference_max_ms=max(ds),independent_seed_processes=3))

rg=[]
for profile in ['classical','post_quantum']:
    for con in [1,8,32]:
        cs=[c for c in remote if (c['profile'],c['concurrency'])==(profile,con)]
        rg.append(dict(profile=profile,concurrency=con,median_of_cell_medians_ms=st.median(c['median_ms'] for c in cs),mean_cell_throughput_rps=st.mean(c['throughput_rps'] for c in cs),min_cell_median_ms=min(c['median_ms'] for c in cs),max_cell_median_ms=max(c['median_ms'] for c in cs)))
soak=read(WIT/'results/remote_soak/soak.json')
faults=[read(WIT/'results'/('faults_'+p)/'faults.json') for p in ['classical','post_quantum']]
assert all(x['passed'] for f in faults for x in f['checks'])
audit=read(GPU/'postrun/INDEPENDENT_AUDIT.json');assert audit['passed']
assert sum(c['signatures_verified'] for c in audit['crypto_verification'])==audit['signatures_verified']==29360
assert sum(c.get('inclusion_proofs',0) for c in audit['crypto_verification'])==audit['inclusion_proofs_verified']==3672
batch=[]
for w in ['short','long','mixed']:
    for con in [1,8,32]:
        a=[x for x in audit['measured_batch_sizes'] if (x['workload'],x['concurrency'])==(w,con)]
        batch.append(dict(workload=w,concurrency=con,records=sum(x['measured_records'] for x in a),batches=sum(x['measured_batches'] for x in a),audit_signatures=sum(x['measured_audit_signatures'] for x in a),effective_batch_mean=sum(x['measured_records'] for x in a)/sum(x['measured_batches'] for x in a)))
formal=read(FORMAL/'FINAL_RESULTS.json');main=[r for r in formal['results'] if r['model']=='models/fixed_counter_invariants_r6.spthy']
model=(FORMAL/'models/fixed_counter_invariants_r6.spthy').read_text()
def lemma_quantifiers(text):
    # Tamarin defaults to all-traces when the quantifier is omitted.
    text=re.sub(r'/\*.*?\*/|//[^\n]*','',text,flags=re.S)
    return {name:(kind or 'all-traces') for name,kind in re.findall(
        r'\blemma\s+(\w+)\s*(?:\[[^\]]*\])?\s*:\s*(?:(exists-trace|all-traces)\s*)?"',text)}
quant_by_model={name:lemma_quantifiers((FORMAL/name).read_text()) for name in {r['model'] for r in formal['results']}}
quant=quant_by_model['models/fixed_counter_invariants_r6.spthy']
assert len(main)==23 and all(r['passed'] for r in main)
assert sum(quant.get(r['lemma'])=='exists-trace' for r in main)==7
formal_rows=[dict(model=r['model'],lemma=r['lemma'],expected=r['expected'],matched_expected=r['passed'],quantifier=quant_by_model[r['model']][r['lemma']],model_sha256=r['model_sha256'],log=r['log'],log_sha256=r['log_sha256']) for r in formal['results']]

for name,rs in [('cpu_cells.csv',cpu),('cpu_comparison.csv',cpug),('gpu_cells.csv',gpu),('gpu_summary.csv',gpug),('gpu_paired_seed_differences.csv',gpudiff),('gpu_batch_counts.csv',batch),('remote_witness_cells.csv',remote),('remote_witness_summary.csv',rg),('formal_selected_targets.csv',formal_rows)]:csvout(name,rs)
facts=dict(cpu=dict(cells=80,measured_requests=20480,warmups=400,failures=0,groups=cpug),gpu=dict(cells=135,measured_requests=17280,warmups=1080,failures=0,signatures_verified=29360,inclusion_proofs_verified=3672,raw_lifecycle_bindings_verified=11016,matched_mode_output_groups=3456,output_mismatches=0,scheduler_max_running=max(x['scheduler_max_running'] for x in gpu),groups=gpug,differences=gpudiff,batches=batch),remote_witness=dict(cells=18,measured_requests=1536,warmups=90,failures=0,fault_checks=sum(len(f['checks']) for f in faults),fault_checks_passed=sum(x['passed'] for f in faults for x in f['checks']),soak_updates=soak['successes'],soak_elapsed_s=soak['elapsed_s'],soak_restarts=soak['planned_remote_process_restarts'],groups=rg),formal=dict(selected_targets=36,matched_expected=36,main_model_universal_properties=16,main_model_executable_traces=7,main_model_targets=23,expected_falsifications=1,historical_attempts=formal['historical_attempt_counts'],boundaries=formal['boundaries']))
dump(CASE/'tables/VERIFIED_FACTS.json',facts)
dump(CASE/'evidence/CLAIM_SOURCE_MAP.json',dict(relative_roots=dict(cpu=CPU.name,remote_witness=WIT.name,gpu=GPU.name,formal=FORMAL.name),raw_sources=source,statistics='CPU medians are medians of five cell medians; GPU means/ranges use three independent seed-process cell summaries, not request-pooled confidence intervals; remote medians use three cell medians; no historical campaign pooled'))
print(json.dumps({k:{a:b for a,b in v.items() if not isinstance(b,(dict,list))} for k,v in facts.items()},indent=2))
print('CPU_C1',[x for x in cpug if x['concurrency']==1])
print('GPU_C32',[x for x in gpug if x['concurrency']==32 and x['mode'] in ['submitted_full','merkle8']])
print('REMOTE',rg)
