"""Compare GitHub's uploaded asset SHA-256 metadata with this snapshot manifest."""
from pathlib import Path
import hashlib, json, subprocess

ROOT=Path(__file__).resolve().parents[1]
def main():
    m=json.loads((ROOT/'backup/snapshot-manifest.json').read_text(encoding='utf-8-sig'))
    repo='junlongli482-del/wnsmw';tag='research-backup-2026-10-17'
    url=subprocess.check_output(['gh','release','view',tag,'--repo',repo,'--json','apiUrl','--jq','.apiUrl'],text=True).strip()
    release=json.loads(subprocess.check_output(['gh','api',url],text=True,encoding='utf-8'))
    assets={a['name']:a for a in release['assets']}
    expected=list(m['parts'])
    for name,path in [('snapshot-manifest.json',ROOT/'backup/snapshot-manifest.json'),
                      ('scanner-native-restored-research.apk',ROOT/'output/camscanner-reverse/scanner-native-restored-research.apk'),
                      ('restored-algorithm-review.html',ROOT/'output/camscanner-reverse/恢复原算法效果核对.html')]:
        data=path.read_bytes()
        expected.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    checks=[]
    for entry in expected:
        a=assets.get(entry['name'])
        passed=bool(a and a['state']=='uploaded' and a['size']==entry['bytes'] and a.get('digest')=='sha256:'+entry['sha256'])
        checks.append({'name':entry['name'],'bytes':entry['bytes'],'sha256':entry['sha256'],'passed':passed})
    report={'repo':repo,'tag':tag,'release_url':f'https://github.com/{repo}/releases/tag/{tag}',
            'checks':checks,'passed':all(c['passed'] for c in checks),
            'verification':'GitHub uploaded asset size and server-computed SHA-256 matched to local bytes; snapshot archive CRC and restored file hashes validated separately.'}
    (ROOT/'backup/remote-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
