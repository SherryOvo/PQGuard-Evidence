#!/usr/bin/env python3
"""Gate before any GPU import; reuse the frozen serving driver with documented adapters."""
import argparse,datetime,importlib.util,json,os,sys,asyncio,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'));sys.path.insert(0,str(ROOT/'scripts'))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--seed',type=int,required=True);ap.add_argument('--run-id',required=True);ap.add_argument('--placement',choices=['local','remote'],required=True);ap.add_argument('--pilot',action='store_true');a=ap.parse_args()
 gate=json.loads((ROOT/'config/experiment.json').read_text())['gpu'];now=datetime.datetime.now(datetime.timezone.utc);assert now>=datetime.datetime.fromisoformat(gate['not_before_utc']),'GPU experiment time gate: before 14:30 CST'
 assert json.loads((ROOT/'evidence/CPU_DONE.json').read_text()).get('passed'),'CPU campaign not verified complete'
 assert json.loads((ROOT/'evidence/GPU_PREPARED.json').read_text()).get('model_hashes_passed'),'model not independently checked'
 src=(ROOT/'vendor/gpu_campaign.py').read_text();needle='stream = f"gpu-{args.seed}-{cell_index}"';assert src.count(needle)==1;src=src.replace(needle,'stream = f"{args.run_id}-{args.seed}-{cell_index}"')
 spec=importlib.util.spec_from_loader('frozen_joint_serving',loader=None);m=importlib.util.module_from_spec(spec);m.__file__=str(ROOT/'vendor/gpu_campaign.py');exec(compile(src,m.__file__,'exec'),m.__dict__)
 from joint_witness import RemoteWitness,PinnedLocalWitness
 m.WitnessProcess=RemoteWitness if a.placement=='remote' else PinnedLocalWitness
 asyncio.run(m.main(a))
if __name__=='__main__':main()
