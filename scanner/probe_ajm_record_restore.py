"""Execute original record restore against initialized offline index snapshot."""
from pathlib import Path
import sys,struct,json,hashlib,os
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0,'.work/reverse-python')
from unicorn import *
from unicorn.x86_const import *
stem='.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.parser500m.hostzlib.constructors'
b=Path(stem+'.bin').read_bytes();h=Path(stem+'.heap.bin').read_bytes();expanded=Path('output/camscanner-reverse/ajm-records/ajm-expanded-validated.bin').read_bytes();u=Uc(UC_ARCH_X86,UC_MODE_32)
for a,n in [(0x1000000,(len(b)+4095)&~4095),(0x30000000,(len(h)+4095)&~4095),(0x45000000,0x100000),(0x70000000,0x10000),(0x60000000,4096),(0,4096)]:u.mem_map(a,n)
u.mem_write(0x1000000,b);u.mem_write(0x30000000,h);u.mem_write(0x14,struct.pack('<I',0x13579bdf));rows=[];p=0
for i in range(20):
 key,second,n=struct.unpack_from('<3I',expanded,p);data=expanded[p+12:p+12+n];key=(key-0xad7d)&0xffffffff;p+=12+n
 u.mem_write(0x45000000,b'\xa5'*n);u.mem_write(0x70008000,struct.pack('<4I',0x60000000,key,0x45000000,n//2));u.reg_write(UC_X86_REG_ESP,0x70008000);u.emu_start(0x108aa40,0x60000000,count=2000000)
 out=bytes(u.mem_read(0x45000000,n));expected=bytes(v if v in (0,255,35,220) else v^255 for v in data)
 if u.reg_read(UC_X86_REG_EIP)!=0x60000000 or out!=expected:raise RuntimeError((i,out.hex(),expected.hex()))
 rows.append({'key':hex(key),'bytes':n,'source_second_field':second,'original_input':data[:64].hex(),'original_output':out[:64].hex(),'matches_recovered_formula':True})
r={'entry':'0x8aa40','records_checked':len(rows),'samples':rows,'formula':'b unchanged if b in {0x00,0xff,0x23,0xdc}; otherwise b XOR 0xff','scope':'Original lookup and byte-restore function machine code executed over actual initialized offline hash table. No import substitution in these calls. Synthetic prior mixed-run state, stack/TLS; no claim of ART/Dex verifier or business method attribution.'}
Path('output/camscanner-reverse/shell-ajm-original-record-restore.json').write_text(json.dumps(r,indent=2));print(r)
