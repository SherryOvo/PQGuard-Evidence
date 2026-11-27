#!/usr/bin/env python3
"""Hash reused model using bounded buffers; no torch or model import."""
import hashlib,json,os,platform,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def atomic(p,v):
 t=p.with_suffix(p.suffix+'.tmp');t.write_text(json.dumps(v,indent=2,sort_keys=True));os.replace(t,p)
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(2*1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 old=Path('/root/autodl-tmp/pqguard_gpu_batch_20261123');ready=json.loads((old/'evidence/MODEL_READY.json').read_text());expected={}
 for line in (ROOT/'evidence/EXPECTED_MODEL_SHA256.txt').read_text().splitlines():
  if line.strip():value,name=line.split(None,1);expected[name.strip().lstrip('*')]=value
 assert len(expected)==15 and len(ready['files'])==15
 results=[];start=time.time()
 for item in ready['files']:
  name=item['file'];p=old/'model/Qwen2.5-14B-Instruct'/name;actual=digest(p)
  assert p.stat().st_size==item['bytes'] and actual==item['sha256']==expected[name],name
  results.append(dict(file=name,sha256=actual,bytes=p.stat().st_size));atomic(ROOT/'state/MODEL_HASH_PROGRESS.json',dict(checked=len(results),expected=15,latest=name))
 model=ROOT/'model';model.mkdir(exist_ok=True);target=model/'Qwen2.5-14B-Instruct'
 if not target.exists():target.symlink_to(old/'model/Qwen2.5-14B-Instruct',target_is_directory=True)
 assert target.resolve()==(old/'model/Qwen2.5-14B-Instruct').resolve()
 atomic(ROOT/'evidence/MODEL_READY.json',ready)
 atomic(ROOT/'evidence/GPU_PREPARED.json',dict(model_hashes_passed=True,files=results,python=sys.version,platform=platform.platform(),gpu_loaded=False,elapsed_s=time.time()-start,prepared_unix_s=time.time(),scope='model/source preparation only; GPU availability and actual engine load remain gated'))
 print('MODEL_HASHES_PASS 15/15',flush=True)
if __name__=='__main__':main()
