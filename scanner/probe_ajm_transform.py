"""Execute original ajm outer transform against a retained initialized snapshot.

Uses synthetic stack/TLS and the prior counterfactual N.al state. No ART claim.
"""
from pathlib import Path
import sys,struct,hashlib,json,os
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0,'.work/reverse-python')
from unicorn import *
from unicorn.x86_const import *
p=Path('.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.payload250m2.constructors.bin');b=p.read_bytes();a=Path('.work/camscanner/extracted/assets/ijiami.ajm').read_bytes();u=Uc(UC_ARCH_X86,UC_MODE_32)
for addr,size in [(0x1000000,(len(b)+4095)&~4095),(0x30000000,0x2000000),(0x70000000,0x10000),(0x60000000,4096),(0,4096)]:u.mem_map(addr,size)
heap=Path('.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.payload250m2.constructors.heap.bin').read_bytes();u.mem_map(0x32000000,0x4000000);u.mem_write(0x30000000,heap);u.mem_map(0x40000000,(len(a)+4095)&~4095);u.mem_write(0x1000000,b);u.mem_write(0x40000000,a);u.mem_write(0x14,struct.pack('<I',0x13579bdf));u.mem_write(0x70008000,struct.pack('<4I',0x60000000,0x40000018,len(a)-24,1024));u.reg_write(UC_X86_REG_ESP,0x70008000)
u.emu_start(0x108b1f0,0x60000000,count=10000000)
o=bytes(u.mem_read(0x40000000,len(a)));expected=Path('output/camscanner-reverse/payload-dumps/ajm-transformed-payload250m2.bin').read_bytes();print('pc',hex(u.reg_read(UC_X86_REG_EIP)),'same',o==expected,'head',o[24:40].hex())
Path('output/camscanner-reverse/payload-dumps/ajm-transform-isolated.bin').write_bytes(o)
Path('output/camscanner-reverse/shell-ajm-transform-isolated.json').write_text(json.dumps({'function':'0x8b1f0','returned':u.reg_read(UC_X86_REG_EIP)==0x60000000,'matches_full_original_path_snapshot':o==expected,'input_sha256':hashlib.sha256(a).hexdigest(),'output_sha256':hashlib.sha256(o).hexdigest(),'scope':'Original x86 transform isolated with retained 250M counterfactual N.al image/heap state. Synthetic stack/canary, no import substitution or Android runtime. Initial constructor-only state did not match; initialized state is required.'},indent=2))

