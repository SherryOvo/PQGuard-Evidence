#!/usr/bin/env python3
"""Recheck exported artifacts without importing the state extension."""
import hashlib,json,sqlite3,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from verify_artifacts import verify_sig,enc
from runtime import atomic
result=[];signatures=0;checks=0
for profile in ['classical','post_quantum']:
 for seed in [20261124,20261125,20261126]:
  case=ROOT/'raw/state_edges'/f'{profile}__{seed}';summary=json.loads((case/'SUMMARY.json').read_text());assert summary['passed'] and summary['checks']==21
  raw=[json.loads(x) for x in (case/'raw.jsonl').read_text().splitlines()];assert len(raw)==21 and all(x['actual']==x['expected'] and x['passed'] for x in raw);checks+=len(raw)
  pub=json.loads((case/'public_material.json').read_text());fixtures=json.loads((case/'fixtures.json').read_text());n=0
  for f in fixtures['certificates']:
   p=pub[f['signer']];verify_sig(p['identity'],p['policy_public_key'],enc(f['descriptor']),bytes.fromhex(f['signature']));n+=1
  for name,sig in [('original','old_signature'),('rotated','new_signature')]:
   p=pub[name];verify_sig(p['identity'],p['policy_public_key'],enc(fixtures['rotation']),bytes.fromhex(fixtures[sig]));n+=1
  assert n==18;signatures+=n
  d=sqlite3.connect('file:'+str(case/'version.sqlite')+'?mode=ro',uri=True);assert d.execute('PRAGMA integrity_check').fetchone()==('ok',);floor,pk=d.execute('SELECT floor,pk FROM state').fetchone();assert floor==13 and pk==pub['rotated']['policy_public_key'];d.close()
  c=json.loads((case/'concurrent.json').read_text());assert c['expected_final_floor']==10 and set(c['decisions'])<= {'accepted','old_version'};result.append(dict(profile=profile,seed=seed,checks=21,public_signatures=n,passed=True))
for name,value in json.loads((ROOT/'evidence/STATE_EDGES_SOURCE_SHA256.json').read_text()).items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value
report=dict(passed=True,tasks=6,checks=checks,public_signatures_verified=signatures,results=result,scope='isolated newly implemented extension; process-exit rather than physical power-loss faults')
atomic(ROOT/'evidence/STATE_EDGES_INDEPENDENT_AUDIT.json',report);print(json.dumps({k:v for k,v in report.items() if k!='results'}))
