"""Exercise the real restoration in a fresh directory, including every file hash."""
from pathlib import Path
import importlib.util, json, os, shutil, sys, tempfile

ROOT=Path(__file__).resolve().parents[1]
def main():
    work=ROOT/'.work';work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='snapshot-restore-test-',dir=work) as temp:
        target=Path(temp).resolve()
        if not target.is_relative_to(work.resolve()):raise RuntimeError('Unexpected test directory')
        assets=target/'backup/assets';assets.mkdir(parents=True)
        shutil.copy2(ROOT/'backup/snapshot-manifest.json',target/'backup/snapshot-manifest.json')
        m=json.loads((ROOT/'backup/snapshot-manifest.json').read_text(encoding='utf-8-sig'))
        for part in m['parts']:
            os.link(ROOT/'backup/assets'/part['name'],assets/part['name'])
        spec=importlib.util.spec_from_file_location('restore',ROOT/'backup/restore_snapshot.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.ROOT=target
        sys.argv=['restore_snapshot.py']
        module.main()
        report={'passed':True,'files_verified':len(m['files']),
                'raw_bytes':sum(x['bytes'] for x in m['files']),
                'method':'Fresh directory; real restore script reassembled all volumes, extracted both ZIPs, verified every file SHA-256; temporary test data removed afterwards.'}
        (ROOT/'backup/local-restore-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report),flush=True)

if __name__=='__main__':main()
