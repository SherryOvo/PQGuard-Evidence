"""Read-only ZIP/CRC/SHA verifier. Does not run measurements, load a model or use SSH."""
from pathlib import Path
import argparse,hashlib,json,shutil,tempfile,zipfile

def sha(path):
    d=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):d.update(b)
    return d.hexdigest()

def verify_zip(path,meta,out):
    with zipfile.ZipFile(path) as z:
        names=z.namelist();assert len(names)==len(set(names)), 'duplicate ZIP members'
        for info in z.infolist():
            p=Path(info.filename)
            assert not p.is_absolute() and '..' not in p.parts,info.filename
            assert ((info.external_attr>>16)&0o170000)!=0o120000,'symlink member'
        assert z.testzip() is None,'CRC mismatch'
        z.extractall(out)
    count=0
    if meta.get('bundle_root'):
        root=out/meta['bundle_root'];manifest=root/'SHA256SUMS'
        assert manifest.is_file(),'missing file manifest'
        listed=[]
        for line in manifest.read_text().splitlines():
            h,n=line.split('  ',1);p=Path(n);assert not p.is_absolute() and '..' not in p.parts
            assert sha(root/p)==h,n;listed.append(n);count+=1
        actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p!=manifest}
        assert actual==set(listed),'unlisted or missing extracted members'
    else:
        for n,h in meta.get('files_sha256',{}).items():assert sha(out/n)==h,n;count+=1
    return dict(central_directory=True,crc=True,full_extraction=True,manifest_files=count)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--manifest',required=True);ap.add_argument('--extract-to');ap.add_argument('--name',action='append');ap.add_argument('--report');a=ap.parse_args()
    root=Path(a.root).expanduser().resolve();manifest=json.loads(Path(a.manifest).read_text());rows=[]
    for name,meta in manifest['files'].items():
        if a.name and name not in a.name:continue
        p=root/name;assert p.is_file(),name;assert sha(p)==meta['sha256'],name
        row=dict(file=name,sha256=True,bytes=p.stat().st_size)
        if p.suffix=='.zip':
            if a.extract_to:
                out=Path(a.extract_to)/p.stem;assert not out.exists(),str(out);out.mkdir(parents=True)
                row.update(verify_zip(p,meta,out))
            else:
                with tempfile.TemporaryDirectory(prefix='pqguard_verify_') as tmp:row.update(verify_zip(p,meta,Path(tmp)))
        rows.append(row);print(json.dumps(row),flush=True)
    report=dict(passed=True,files=rows,measurements_started=False,gpu_used=False)
    if a.report:Path(a.report).write_text(json.dumps(report,indent=2)+'\n')
    return report
if __name__=='__main__':main()
