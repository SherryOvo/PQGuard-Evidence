#!/usr/bin/env python3
"""Reconstruct all valid-signature splices/corruptions from public fixtures."""
import copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'vendor'))
from verify_artifacts import verify_sig,enc,h
from runtime import atomic
counts={};total=0
for path in sorted((ROOT/'raw/cpu').glob('binding__*/attempt_01')):
 data=[json.loads(x) for x in (path/'raw.jsonl').read_text().splitlines()]
 for kind in ['cbas','conventional']:
  fixture=json.loads((path/(kind+'_fixtures.json')).read_text());pub=fixture['public'];records=fixture['records']
  for x in [r for r in data if r['implementation']==kind]:
   i=x['index'];case=x['case'];r=copy.deepcopy(records[i]);other=records[(i+1)%len(records)]
   if case=='completion_splice':
    for key in ['completion','completion_signature','publication','publication_signature']:r[key]=other[key]
   elif case=='publication_splice':
    for key in ['publication','publication_signature']:r[key]=other[key]
   elif case=='signature_corruption':
    sig=bytearray.fromhex(r['completion_signature']);sig[0]^=1;r['completion_signature']=sig.hex()
   valid=True
   try:
    verify_sig(pub['identity'],pub['identity_public_key'],enc(r['admission']),bytes.fromhex(r['admission_signature']))
    verify_sig(pub['audit'],pub['audit_public_key'],enc(r['completion']),bytes.fromhex(r['completion_signature']))
    verify_sig(pub['audit'],pub['audit_public_key'],b'PQGUARD-WITNESS-V1\0'+enc(r['publication']),bytes.fromhex(r['publication_signature']))
   except Exception:valid=False
   a,b,q=r['admission'],r['completion'],r['publication'];bound=valid and all(a[k]==b[k] for k in ['sid','seq','prompt_hash','policy']) and q['digest']==h(enc(dict(previous=b['previous'],entry=h(enc(b)+bytes.fromhex(r['completion_signature'])),counter=q['counter'])))
   assert valid==x['component_signatures_valid'] and bound==x['lifecycle_relation_valid'];key=kind+'/'+case;c=counts.setdefault(key,dict(trials=0,component_accepts=0,relation_accepts=0));c['trials']+=1;c['component_accepts']+=valid;c['relation_accepts']+=bound;total+=1
assert total==1536
report=dict(passed=True,mutated_and_clean_cases=total,counts=counts,scope='independent public-key verification of reconstructed offline controls, not online attack exploitability')
atomic(ROOT/'evidence/BINDING_CONTROLS_INDEPENDENT_AUDIT.json',report);print(json.dumps(dict(passed=True,cases=total,counts=counts)))
