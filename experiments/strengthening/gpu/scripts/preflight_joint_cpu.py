#!/usr/bin/env python3
"""Actual signed remote witness test without GPU, not inference measurement."""
import json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'vendor'),str(ROOT/'scripts')]
from joint_witness import RemoteWitness
from r7_crypto_profiles import build_profile,sha256
from r11_durable_lifecycle import DurableLifecycleStore
from merkle_store import MerkleStore
from verify_artifacts import verify_case
from runtime import atomic
out=ROOT/'work'/('remote_preflight_'+str(time.time_ns()));out.mkdir()
results=[]
for mode,cls in [('submitted_full',DurableLifecycleStore),('merkle8',MerkleStore)]:
 case=out/mode;case.mkdir();p=build_profile('post_quantum',sha256(b'cpu-only remote integration preflight'));atomic(case/'public_material.json',p.export_public());stream='preflight-'+str(time.time_ns())+'-'+mode
 w=RemoteWitness(case,p.export_public(),stream);extra=dict(batch_size=8,max_wait_ms=50) if mode=='merkle8' else {};s=cls(case/'lifecycle.sqlite',p,stream,w,**extra)
 for i in range(2):s.admit('preflight',i,sha256(str(i).encode()),p.policy_digest);s.complete('preflight',i,sha256(b'cpu-result'))
 s.close();w.close();r=verify_case(case);assert r['passed'];r['mode']=mode;results.append(r)
atomic(out/'RESULT.json',dict(passed=True,gpu_used=False,results=results));atomic(ROOT/'evidence/REMOTE_WITNESS_PREFLIGHT.json',dict(passed=True,gpu_used=False,output=str(out.relative_to(ROOT)),results=results));print(json.dumps(results))
