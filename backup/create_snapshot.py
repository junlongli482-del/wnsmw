"""Create a portable research snapshot; excludes unrelated platform documents and secrets."""
from pathlib import Path
import hashlib, json, zipfile, time

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'backup/assets'
DEST.mkdir(parents=True, exist_ok=True)
GROUPS = {
    'research-state.zip': ['output/camscanner-reverse', 'output/ghidra-projects', 'output/scans',
        '.work/camscanner', '.work/android-research-build', '.work/shell-probe-build',
        '.work/stack-probe-build', '.work/wechat-page-fixtures'],
    'research-environment.zip': ['.work/reverse-python', '.work/scanner-python',
        'frida_binding.node', '.work/rea-tools/jadx-verified.jar',
        '.work/rea-tools/frida-server-17.23.2-android-x86',
        '.work/rea-tools/frida-java-bridge', '.work/rea-tools/esbuild-win',
        '.work/rea-tools/trace-android-arm-compat.js',
        '.work/rea-tools/trace-android-java-bundle.js',
        '.work/rea-tools/trace-java-compat-minimal.js',
        '.work/rea-runtime/package.json', '.work/rea-runtime/pnpm-lock.yaml',
        'backup/assets/rea-source.bundle'],
}
SKIP = {'.keystore', '.jks', '.pem', '.p12', '.pfx', '.pyc'}

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024), b''):h.update(b)
    return h.hexdigest()

def main():
    index={'format':1, 'created_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
           'files':[], 'archives':[], 'parts':[], 'excluded':'Private signing keys, credentials, unrelated teaching-platform documents, downloadable SDK/tool caches, Python bytecode.'}
    for name, roots in GROUPS.items():
        files=[]
        for rel in roots:
            p=ROOT/rel
            if p.exists():files.extend([p] if p.is_file() else sorted(p.rglob('*')))
        files=sorted(set(p for p in files if p.is_file() and p.suffix.lower() not in SKIP and '__pycache__' not in p.parts))
        archive=DEST/name
        print(f'Packing {name}: {len(files)} files',flush=True)
        with zipfile.ZipFile(archive,'a' if archive.exists() else 'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True,strict_timestamps=False) as z:
            existing=set(z.namelist())
            for n,p in enumerate(files):
                rel=p.relative_to(ROOT).as_posix()
                if rel not in existing:z.write(p,rel)
                index['files'].append({'path':rel,'bytes':p.stat().st_size,'sha256':digest(p),'archive':name})
                if n%250==0:print(f'{name}: {n}/{len(files)}',flush=True)
        index['archives'].append({'name':name,'bytes':archive.stat().st_size,'sha256':digest(archive)})
        print(f'Verifying {name}',flush=True)
        with zipfile.ZipFile(archive) as z:
            bad=z.testzip()
            if bad:raise RuntimeError('ZIP CRC failed: '+bad)
        # Each GitHub Release asset stays below its 2 GiB limit.
        with archive.open('rb') as f:
            i=1
            while True:
                chunk=f.read(900*1024*1024)
                if not chunk:break
                part=DEST/f'{name}.{i:03d}'
                part.write_bytes(chunk)
                index['parts'].append({'name':part.name,'bytes':len(chunk),'sha256':hashlib.sha256(chunk).hexdigest(),'archive':name})
                i+=1
        (ROOT/'backup/snapshot-manifest.json').write_text(json.dumps(index,ensure_ascii=False,indent=2),encoding='utf-8')
        print(f'Finished {name}: {archive.stat().st_size} bytes',flush=True)
    print('Snapshot complete',flush=True)

if __name__=='__main__':main()
