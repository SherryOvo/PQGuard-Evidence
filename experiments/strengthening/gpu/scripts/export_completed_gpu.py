#!/usr/bin/env python3
"""Internal evidence export, excluding access keys and model weights."""
import hashlib,json,os,tarfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def write(p,b):
 t=p.with_suffix(p.suffix+'.tmp');t.write_bytes(b);os.replace(t,p)
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 audit=json.loads((ROOT/'analysis/GPU_INDEPENDENT_AUDIT.json').read_text());remote=json.loads((ROOT/'analysis/REMOTE_ORIGINAL_WITNESS_AUDIT.json').read_text());assert audit['passed'] and remote['passed'];assert audit['totals']['cells']==48 and audit['totals']['measured']==6144
 frozen=json.loads((ROOT/'evidence/GPU_SOURCE_SHA256.json').read_text());assert all(digest(ROOT/name)==value for name,value in frozen.items()),'measurement source changed'
 names=[]
 for folder in ['scripts','vendor','config','environment','evidence','analysis','remote_original','logs']:
  names.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and not p.is_symlink() and p.suffix!='.pyc' and '__pycache__' not in p.parts)
 for folder in (ROOT/'runs').glob('joint_20261124T063851Z_*'):
  names.extend(p for p in folder.rglob('*') if p.is_file() and not p.is_symlink())
 for folder in (ROOT/'work').glob('remote_preflight_*'):
  names.extend(p for p in folder.rglob('*') if p.is_file() and not p.is_symlink())
 names.append(ROOT/'config.json')
 # Preserve the run's state without rewriting its historical pending-audit label.
 for name in ['GPU_STATUS.json','GPU_WAIT_STATUS.json','TUNNEL_STATUS.json']:
  source=ROOT/'state'/name;target=ROOT/'evidence'/('FINAL_'+name);write(target,source.read_bytes());names.append(target)
 report=dict(status='SERVER_AUDIT_COMPLETE_LOCAL_TRANSFER_PENDING',totals=audit['totals'],remote_formal_cells=remote['formal_remote_cells'],remote_acknowledged_publications=remote['formal_publications_with_remote_ack'],pilot_not_mixed_into_formal=True,measurement_source_unchanged=True,access_keys_and_weights_excluded=True,finished_unix_s=time.time(),scope='internal raw evidence package; not an anonymized journal-upload release; new data do not retroactively change historical experiments or establish a new primitive/full AKE/attestation')
 p=ROOT/'analysis/DELIVERY_STATUS.json';write(p,json.dumps(report,indent=2).encode());names.append(p);names=sorted(set(names))
 arcnames={p:str(p.relative_to(ROOT)) for p in names}
 historical=[]
 for p in names:
  if p.parent==ROOT/'evidence' and (p.name in ['DEPLOYMENT_SHA256.json','GPU_SOURCE_SHA256.pre_resource_gate.json','LATEST_PREPARATION_EXPORT.json'] or p.name.startswith('PREPARATION_')):
   arcnames[p]='provenance/preparation_ledgers/'+p.name;historical.append(arcnames[p])
 for pattern in ['GPU_PREPARATION_*.tar.gz','GPU_PREPARATION_*.tar.gz.sha256','source_stage_2.tar.gz']:
  for p in (ROOT/'work').glob(pattern):
   names.append(p);arcnames[p]='provenance/preparation_archives/'+p.name
 scope=dict(active_release_manifest='GPU_FINAL_SHA256.json (relative to archive root)',active_measurement_source_manifest='evidence/GPU_SOURCE_SHA256.json (relative to archive root)',active_wrapper_manifest='evidence/CRYPTO_WRAPPER_SHA256.json (relative to archive root)',original_witness_manifest='remote_original/SHA256.json (relative to remote_original)',historical_ledgers=historical,historical_ledger_scope='Pre-GPU preparation snapshots, not manifests of the final mutable working directory; retained with preparation archives instead of relabeling them as current checksums',model_hash_scope='Expected model hashes describe read-only external weights; weights and private access keys are excluded',local_receipt_scope='Server export is immutable and necessarily precedes local verification. The separate local final receipt references the final archive hash; pending local flags inside server snapshots are not rewritten after transfer',publication_scope='Internal audit delivery, not an anonymized journal-upload package')
 scope_path=ROOT/'analysis/INTEGRITY_SCOPES.json';write(scope_path,json.dumps(scope,indent=2).encode());names.append(scope_path);arcnames[scope_path]='analysis/INTEGRITY_SCOPES.json';names=sorted(set(names))
 manifest={arcnames[p]:digest(p) for p in names};mp=ROOT/'GPU_FINAL_SHA256.json';write(mp,json.dumps(manifest,sort_keys=True,indent=2).encode());names.append(mp);arcnames[mp]='GPU_FINAL_SHA256.json'
 out=ROOT/'work/GPU_JOINT_FINAL_20261124.tar.gz';assert not out.exists(),'Never overwrite a previous final archive';tmp=out.with_suffix('.partial')
 with tarfile.open(tmp,'w:gz') as tar:
  for p in names:tar.add(p,arcname=arcnames[p],recursive=False)
 os.replace(tmp,out);sha=digest(out);write(out.with_suffix('.gz.sha256'),(sha+'  '+out.name+'\n').encode());metadata=dict(archive=out.name,files=len(names),uncompressed_bytes=sum(p.stat().st_size for p in names),compressed_bytes=out.stat().st_size,sha256=sha)
 p=ROOT/'evidence/GPU_FINAL_EXPORT.json';write(p,json.dumps(metadata,indent=2).encode());print(json.dumps(metadata))
if __name__=='__main__':main()
