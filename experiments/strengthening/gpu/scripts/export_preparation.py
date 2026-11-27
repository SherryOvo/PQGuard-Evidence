#!/usr/bin/env python3
"""Export reproducible GPU preparation, never private access keys or weights."""
import datetime,hashlib,json,os,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert not (ROOT/'state/GPU_STATUS.json').exists(), 'Preparation export must precede GPU measurements'
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');names=[]
for folder in ['scripts','vendor','config','environment','evidence']:
 names.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and not p.is_symlink() and p.suffix!='.pyc' and '__pycache__' not in p.parts)
names.append(ROOT/'config.json')
for preflight in (ROOT/'work').glob('remote_preflight_*'):
 names.extend(p for p in preflight.rglob('*') if p.is_file() and not p.is_symlink())
names.extend(p for p in (ROOT/'logs').glob('*') if p.is_file() and not p.is_symlink())
for name in ['GPU_WAIT_STATUS.json','TUNNEL_STATUS.json']:
 source=ROOT/'state'/name;target=ROOT/'evidence'/('PREPARATION_'+stamp+'_'+name);target.write_bytes(source.read_bytes());names.append(target)
manifest={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(names))};p=ROOT/'evidence'/('PREPARATION_EXPORT_'+stamp+'_SHA256.json');p.write_text(json.dumps(manifest,indent=2,sort_keys=True));names=list(sorted(set(names)))+[p]
out=ROOT/'work'/('GPU_PREPARATION_'+stamp+'.tar.gz');tmp=out.with_suffix('.tmp')
with tarfile.open(tmp,'w:gz') as tar:
 for p in names:tar.add(p,arcname=str(p.relative_to(ROOT)),recursive=False)
os.replace(tmp,out);digest=hashlib.sha256(out.read_bytes()).hexdigest();out.with_suffix('.gz.sha256').write_text(digest+'  '+out.name+'\n');report=dict(archive=out.name,files=len(names),bytes=out.stat().st_size,sha256=digest,manifest=str(p.relative_to(ROOT)),private_access_and_weights_excluded=True)
(ROOT/'evidence/LATEST_PREPARATION_EXPORT.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
