"""Execute original protected-carrier transform with retained shell state.

No instruction hooks/substitution; imports, if encountered, stop with a fault.
Synthetic stack/canary and original mixed offline initialization state.
"""
from pathlib import Path
import sys, struct, hashlib, json, time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_EAX

def main():
    prefix=ROOT/'.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.datread30m.hostzlib.constructors'
    image=Path(str(prefix)+'.bin').read_bytes()
    heap=Path(str(prefix)+'.heap.bin').read_bytes()
    carrier=ROOT/'output/camscanner-reverse/dat-records/classes.dex'
    body=carrier.read_bytes()
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    for addr,size in [(0x1000000,(len(image)+4095)&~4095),(0x30000000,(len(heap)+4095)&~4095),(0x90000000,(len(body)+4095)&~4095),(0x70000000,0x100000),(0x60000000,4096),(0,4096)]:
        uc.mem_map(addr,size)
    uc.mem_write(0x1000000,image);uc.mem_write(0x30000000,heap)
    uc.mem_write(0x90000000,body);uc.mem_write(0x14,struct.pack('<I',0x13579bdf))
    uc.mem_write(0x70001000,struct.pack('<I',0x90000028))
    uc.mem_write(0x700f0000,struct.pack('<4I',0x60000000,0x70001000,len(body)-40,1))
    uc.reg_write(UC_X86_REG_ESP,0x700f0000)
    started=time.monotonic();error=None
    try:uc.emu_start(0x10c1140,0x60000000,count=2000000000)
    except Exception as exc:error=str(exc)
    output=bytes(uc.mem_read(0x90000000,len(body)))
    out=ROOT/'output/camscanner-reverse/payload-dumps/dat-inner-transform-original.bin';out.write_bytes(output)
    evidence={'entry':'0xc1140','arguments':{'payload_offset':40,'bytes':len(body)-40,'mode':1},'source_sha256':hashlib.sha256(body).hexdigest(),'image_sha256':hashlib.sha256(image).hexdigest(),'heap_sha256':hashlib.sha256(heap).hexdigest(),'output_sha256':hashlib.sha256(output).hexdigest(),'returned':uc.reg_read(UC_X86_REG_EIP)==0x60000000,'pc':hex(uc.reg_read(UC_X86_REG_EIP)),'eax':hex(uc.reg_read(UC_X86_REG_EAX)),'error':error,'seconds':time.monotonic()-started,'head_hex':output[:128].hex(),'dex_magic_offsets':[],'scope':'Isolated original x86 c1140 machine code over ZIP member with retained mixed offline initialization state and synthetic stack/TLS. No import substitution inside transform; not full loader path or actual Android execution.'}
    import re
    evidence['dex_magic_offsets']=[m.start() for m in re.finditer(rb'dex\n0[0-9]{2}\x00',output)]
    (ROOT/'output/camscanner-reverse/shell-dat-inner-transform-original.json').write_text(json.dumps(evidence,indent=2))
    print(json.dumps(evidence,indent=2))

if __name__=='__main__':main()
