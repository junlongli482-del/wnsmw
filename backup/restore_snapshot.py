"""Download, verify and safely restore the fixed research Release (Python standard library)."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, shutil, subprocess, zipfile

ROOT=Path(__file__).resolve().parents[1]
REPO='junlongli482-del/wnsmw'
TAG='research-backup-2026-10-17'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--download',action='store_true',help='Download missing assets with GitHub CLI')
    p.add_argument('--verify-only',action='store_true',help='Verify archives without extracting')
    args=p.parse_args()
    manifest=json.loads((ROOT/'backup/snapshot-manifest.json').read_text(encoding='utf-8-sig'))
    assets=ROOT/'backup/assets';assets.mkdir(parents=True,exist_ok=True)
    for part in manifest['parts']:
        path=assets/part['name']
        if not path.exists() and args.download:
            subprocess.run(['gh','release','download',TAG,'--repo',REPO,'--pattern',part['name'],'--dir',str(assets)],check=True)
        if not path.exists():raise SystemExit(f'Missing {path}; run with --download or download from Release')
        if path.stat().st_size!=part['bytes'] or sha(path)!=part['sha256']:
            raise SystemExit(f'Checksum failed: {path}')
        print('Verified part:',part['name'],flush=True)
    for archive in manifest['archives']:
        target=assets/archive['name']
        if not target.exists() or sha(target)!=archive['sha256']:
            with target.open('wb') as out:
                for part in manifest['parts']:
                    if part['archive']==archive['name']:
                        with (assets/part['name']).open('rb') as source:shutil.copyfileobj(source,out,8*1024*1024)
        if target.stat().st_size!=archive['bytes'] or sha(target)!=archive['sha256']:
            raise SystemExit(f'Archive checksum failed: {target}')
        with zipfile.ZipFile(target) as z:
            for item in z.infolist():
                rel=PurePosixPath(item.filename)
                dest=(ROOT/str(rel)).resolve()
                if rel.is_absolute() or '..' in rel.parts or not dest.is_relative_to(ROOT):
                    raise SystemExit('Unsafe archive path: '+item.filename)
            if args.verify_only:
                bad=z.testzip()
                if bad:raise SystemExit('CRC failed: '+bad)
            else:z.extractall(ROOT)
        print('Verified archive:',archive['name'],flush=True)
    if not args.verify_only:
        for item in manifest['files']:
            path=ROOT/item['path']
            if not path.is_file() or path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:
                raise SystemExit('Restored file checksum failed: '+str(path))
        print('All restored research files match the snapshot manifest.')

if __name__=='__main__':main()
