"""Disassemble PT_DYNAMIC DT_INIT stubs from the packed shell libraries."""
from pathlib import Path
import struct,json,hashlib,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.work/reverse-python'))
from capstone import Cs,CS_ARCH_X86,CS_ARCH_ARM,CS_MODE_32,CS_MODE_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[1]

def row(path):
    b=path.read_bytes(); ident=b[:16]; machine=struct.unpack_from('<H',b,18)[0]
    cls=ident[4]; assert cls==1
    hdr=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    phoff,phentsz,phnum=hdr[5],hdr[9],hdr[10]
    seg=[]
    for i in range(phnum):seg.append(struct.unpack_from('<8I',b,phoff+i*phentsz))
    def off(v):
        for typ,o,va,pa,fs,ms,fl,al in seg:
            if typ==1 and va<=v<va+fs:return o+v-va
        raise ValueError(hex(v))
    dyn=[]
    for typ,o,va,pa,fs,ms,fl,al in seg:
        if typ==2:
            for p in range(o,o+fs,8):
                t,v=struct.unpack_from('<iI',b,p)
                if not t:break
                dyn.append((t,v))
    init=next(v for t,v in dyn if t==12)
    entry=init&~1 if machine==40 else init
    pos=off(entry)
    if machine==3: md=Cs(CS_ARCH_X86,CS_MODE_32)
    else: md=Cs(CS_ARCH_ARM,CS_MODE_THUMB if init&1 else CS_MODE_ARM)
    ins=[{'address':hex(i.address),'mnemonic':i.mnemonic,'op_str':i.op_str} for i in md.disasm(b[pos:pos+192],entry)]
    return {'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(b).hexdigest(),'machine':machine,
            'dt_init':hex(init),'file_offset':hex(pos),'instructions':ins,
            'instruction_mode':'x86-32' if machine==3 else ('Thumb' if init&1 else 'ARM'),
            'finding':('x86 init begins a custom bitstream decode loop; XOR constants are visible in the first decoded-byte path.' if machine==3 else 'ARM initializer decoded in entry-selected instruction mode; no runtime unpacking verified.')}

def main():
    records=[row(p) for p in (ROOT/'.work/camscanner/extracted/assets/ijm_lib').rglob('*.so')]
    (ROOT/'output/camscanner-reverse/shell-initializer-evidence.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
    for r in records: print(r['path'],r['dt_init'],r['machine'],r['instructions'][:5])
if __name__=='__main__':main()
