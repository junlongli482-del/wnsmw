"""Retain the early top-level REA/package indexes in a small supplemental volume."""
from pathlib import Path
import hashlib, json, zipfile

ROOT=Path(__file__).resolve().parents[1]
def main():
    manifest=ROOT/'backup/snapshot-manifest.json'
    m=json.loads(manifest.read_text(encoding='utf-8-sig'))
    files=sorted((ROOT/'output').glob('camscanner-*.json'))+sorted((ROOT/'output').glob('camscanner-*.txt'))+sorted((ROOT/'output').glob('rea-*.json'))
    name='research-indexes.zip';archive=ROOT/'backup/assets'/name
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,strict_timestamps=False) as z:
        for p in files:z.write(p,p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for p in files:assert hashlib.sha256(z.read(p.relative_to(ROOT).as_posix())).digest()==hashlib.sha256(p.read_bytes()).digest()
    m['files']=[x for x in m['files'] if x['archive']!=name]
    m['archives']=[x for x in m['archives'] if x['name']!=name]
    m['parts']=[x for x in m['parts'] if x['archive']!=name]
    for p in files:m['files'].append({'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'archive':name})
    data=archive.read_bytes();sha=hashlib.sha256(data).hexdigest()
    m['archives'].append({'name':name,'bytes':len(data),'sha256':sha})
    part=archive.with_name(name+'.001');part.write_bytes(data)
    m['parts'].append({'name':part.name,'bytes':len(data),'sha256':sha,'archive':name})
    manifest.write_text(json.dumps(m,ensure_ascii=False,indent=2),encoding='utf-8')
    report={'passed':True,'files_verified':len(files),'archive':name,'sha256':sha,'method':'ZIP CRC and each decoded member SHA-256 matched original top-level research index bytes.'}
    (ROOT/'backup/supplement-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))

if __name__=='__main__':main()
