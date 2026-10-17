"""Resumable official-release download with per-range and final SHA verification."""
import concurrent.futures, hashlib, json, sys, time, urllib.request
from pathlib import Path

url, destination, total, digest = sys.argv[1:]
total=int(total)
dest=Path(destination)
parts=dest.with_suffix(dest.suffix+'.parts')
parts.mkdir(parents=True,exist_ok=True)
chunk=4*1024*1024
def fetch(index):
    start=index*chunk
    end=min(total,start+chunk)-1
    part=parts/str(index)
    if part.exists() and part.stat().st_size==end-start+1:
        return
    for attempt in range(10):
        try:
            request=urllib.request.Request(url+'?rea_part='+str(index)+'&attempt='+str(attempt),headers={'Range':f'bytes={start}-{end}','User-Agent':'Codex','Accept':'application/octet-stream'})
            with urllib.request.urlopen(request,timeout=25) as response:
                if response.status!=206:
                    raise ValueError('Server did not honor Range')
                data=response.read()
            if len(data)!=end-start+1:
                raise ValueError('Incomplete range')
            part.write_bytes(data)
            print(f'Range {index+1}/{(total+chunk-1)//chunk} received',flush=True)
            return
        except Exception as exc:
            print(f'Range {index} attempt {attempt+1}: {str(exc)[:160]}',flush=True)
    raise RuntimeError(f'Range {index} failed')
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(fetch,range((total+chunk-1)//chunk)))
with dest.open('wb') as output:
    for index in range((total+chunk-1)//chunk):
        output.write((parts/str(index)).read_bytes())
actual=hashlib.sha256(dest.read_bytes()).hexdigest()
if actual!=digest:
    raise ValueError('Final SHA256 mismatch: '+actual)
print('VERIFIED '+str(dest),flush=True)
