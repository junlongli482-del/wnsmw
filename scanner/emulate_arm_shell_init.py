"""Isolated ARM/Thumb shell DT_INIT decode with logged syscall stubs."""
from pathlib import Path
import sys,struct,json,hashlib,re
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import *
from unicorn.arm_const import *

def run(name):
    p=ROOT/'.work/camscanner/extracted/assets/ijm_lib/armeabi'/name;b=p.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    assert h[2]==40
    seg=[struct.unpack_from('<8I',b,h[5]+i*h[9]) for i in range(h[10])];tags={}
    for typ,off,va,pa,fs,ms,fl,al in seg:
        if typ==2:
            for pos in range(off,off+fs,8):
                tag,val=struct.unpack_from('<II',b,pos)
                if not tag:break
                tags[tag]=val
    size=(max(s[2]+s[5] for s in seg if s[0]==1)+4095)&~4095;base=0x1000000
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(base,size)
    before=bytearray(size)
    for typ,off,va,pa,fs,ms,fl,al in seg:
        if typ==1:u.mem_write(base+va,b[off:off+fs]);before[va:va+fs]=b[off:off+fs]
    u.mem_map(0x70000000,0x100000);u.reg_write(UC_ARM_REG_SP,0x700f0000)
    u.mem_map(0x60000000,4096);u.mem_write(0x60000000,b'\x00\xbe');u.reg_write(UC_ARM_REG_LR,0x60000001)
    calls=[];faults=[];maps=[];count=0;last=[]
    regs=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5]
    def intr(uc,no,data):
        nr=uc.reg_read(UC_ARM_REG_R7);args=[uc.reg_read(r) for r in regs];rec={'interrupt':no,'syscall':nr,'args':list(map(hex,args)),'pc':hex(uc.reg_read(UC_ARM_REG_PC))};calls.append(rec)
        if nr in (192,90):
            want,length=args[:2];length=(length+4095)&~4095;addr=want or (0x20000000+sum(m['size'] for m in maps))
            if not want:u.mem_map(addr,length);maps.append({'address':addr,'size':length})
            uc.reg_write(UC_ARM_REG_R0,addr);rec['result']=hex(addr)
        elif nr in (91,125,0xf0002):uc.reg_write(UC_ARM_REG_R0,0);rec['result']='0x0'
        else:rec['unsupported']=True;uc.emu_stop()
    def invalid(uc,access,addr,size,value,data):faults.append({'address':hex(addr),'pc':hex(uc.reg_read(UC_ARM_REG_PC))});return False
    def code(uc,addr,size,data):
        nonlocal count
        count+=1
        if len(last)>=20:last.pop(0)
        last.append(hex(addr))
        if addr==0x60000000:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,intr);u.hook_add(UC_HOOK_MEM_INVALID,invalid)
    error=None
    try:u.emu_start(base+tags[12],0,count=60000000)
    except Exception as e:error=str(e)
    image=bytes(u.mem_read(base,size));out=ROOT/'.work/camscanner/shell-unpacked/armeabi'/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(image)
    pc=u.reg_read(UC_ARM_REG_PC)
    return {'library':name,'source_sha256':hashlib.sha256(b).hexdigest(),'dt_init':hex(tags[12]),'base':hex(base),'instructions':count,'returned':pc==0x60000000,'pc':hex(pc),'error':error,'syscalls':calls,'faults':faults,'last_addresses':last,'changed_bytes':sum(a!=c for a,c in zip(before,image)),'output':str(out.relative_to(ROOT)),'sha256':hashlib.sha256(image).hexdigest(),'scope':'Offline ARM/Thumb DT_INIT only. mmap2/mprotect/munmap/cacheflush return stubs logged; no imports/relocations, no Android/JNI or NativeBridge execution.'}

if __name__=='__main__':
    rows=[run(n) for n in ('libexecmain.so','libexec.so')]
    (ROOT/'output/camscanner-reverse/shell-arm-init-emulation-evidence.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    for r in rows:print(r['library'],r['returned'],r['changed_bytes'],r['error'],r['syscalls'],r['faults'])
