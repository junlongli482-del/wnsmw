"""Verify every retained original parser hash-map record against decoded ajm.

Uses a documented offline mixed-execution snapshot, not a live ART process.
"""
from pathlib import Path
import struct,json,os
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
stem='.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.parser500m.hostzlib.constructors'
b=Path(stem+'.bin').read_bytes();h=Path(stem+'.heap.bin').read_bytes()
def rd(a,n):
 data,start=(h,0x30000000) if a>=0x30000000 else (b,0x1000000)
 off=a-start
 if off<0 or off+n>len(data):raise ValueError(hex(a))
 return data[off:off+n]
def u(a):return struct.unpack('<I',rd(a,4))[0]
p=u(0x112ed90);table=u(p);nodes={};seen=set()
for ptr in struct.unpack('<'+'I'*u(p+4),rd(table,u(p+4)*4)):
 while ptr:
  if ptr in seen:raise ValueError('node cycle or duplicate')
  seen.add(ptr);key,hashval,value,nextptr=struct.unpack('<4I',rd(ptr,16));nodes[key]=value;ptr=nextptr
expected=Path('output/camscanner-reverse/ajm-records/ajm-expanded-validated.bin').read_bytes();cursor=0;matched=0
for i in range(403522):
 first,second,n=struct.unpack_from('<3I',expected,cursor);key=(first-0xad7d)&0xffffffff;ptr=nodes[key]
 actual=rd(ptr,12+n);wanted=struct.pack('<I',key)+expected[cursor+4:cursor+12+n]
 if actual!=wanted:raise ValueError('record differs '+str(i))
 cursor+=12+n;matched+=1
result={'map_nodes':len(nodes),'matched_records':matched,'all_payload_bytes_equal_except_normalized_key':True,'key_subtracted':'0xad7d','scope':'Retained original parser map verified against every independently decompressed record. Offline counterfactual/mixed zlib model; no DEX or ART verification.'}
Path('output/camscanner-reverse/shell-ajm-map-all-records-check.json').write_text(json.dumps(result,indent=2));print(result)
