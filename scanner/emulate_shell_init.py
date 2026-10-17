"""Offline Unicorn execution of packed x86 DT_INIT; no Android/JNI runtime."""
from pathlib import Path
import sys,struct,json,hashlib,re
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

def run(path):
    source=path.read_bytes(); hdr=struct.unpack_from('<16sHHIIIIIHHHHHH',source)
    assert hdr[2]==3
    seg=[struct.unpack_from('<8I',source,hdr[5]+i*hdr[9]) for i in range(hdr[10])]
    init=None
    for typ,off,va,pa,fs,ms,flags,align in seg:
        if typ==2:
            for p in range(off,off+fs,8):
                tag,val=struct.unpack_from('<II',source,p)
                if tag==12:init=val
    base=0x1000000; size=(max(s[2]+s[5] for s in seg if s[0]==1)+0xfff)&~0xfff
    u=Uc(UC_ARCH_X86,UC_MODE_32); u.mem_map(base,size)
    for typ,off,va,pa,fs,ms,flags,align in seg:
        if typ==1:u.mem_write(base+va,source[off:off+fs])
    stack=0x70000000;u.mem_map(stack,0x100000);sp=stack+0xf0000
    u.mem_write(sp,struct.pack('<I',0x60000000));u.reg_write(UC_X86_REG_ESP,sp)
    u.mem_map(0x60000000,0x1000);u.mem_write(0x60000000,b'\xf4')
    maps=[];calls=[];faults=[];last=[];counter=0
    def intr(uc,no,data):
        nonlocal maps
        eax=uc.reg_read(UC_X86_REG_EAX); ebx=uc.reg_read(UC_X86_REG_EBX)
        rec={'interrupt':no,'syscall':eax,'pc':hex(uc.reg_read(UC_X86_REG_EIP))}
        if no!=128:raise RuntimeError(str(rec))
        if eax==90:
            args=struct.unpack('<6I',uc.mem_read(ebx,24));want,length=args[:2]
            addr=want or (0x20000000+sum(x['size'] for x in maps)); length=(length+4095)&~4095
            rec['args']=list(args);rec['result']=hex(addr)
            if not want:uc.mem_map(addr,length);maps.append({'address':addr,'size':length})
            # MAP_FIXED overlays the original image; mapped pages already exist.
            uc.reg_write(UC_X86_REG_EAX,addr)
        elif eax in (91,125):uc.reg_write(UC_X86_REG_EAX,0)
        else:calls.append(rec);uc.emu_stop();return
        calls.append(rec)
    def invalid(uc,access,address,length,value,data):
        faults.append({'access':access,'address':hex(address),'length':length,'pc':hex(uc.reg_read(UC_X86_REG_EIP))});return False
    def code(uc,address,length,data):
        nonlocal counter
        counter+=1
        if len(last)>=24:last.pop(0)
        last.append(hex(address))
        if address==0x60000000:uc.emu_stop()
    u.hook_add(UC_HOOK_INTR,intr);u.hook_add(UC_HOOK_MEM_INVALID,invalid);u.hook_add(UC_HOOK_CODE,code)
    error=None
    try:u.emu_start(base+init,0,count=60000000)
    except Exception as e:error=str(e)
    out=ROOT/'.work/camscanner/shell-unpacked'/path.parent.name/path.name;out.parent.mkdir(parents=True,exist_ok=True)
    image=bytes(u.mem_read(base,size));out.write_bytes(image)
    # Analysis-only ELF uses memory offsets and discards stale packed sections.
    rebuilt=bytearray(image)
    struct.pack_into('<I',rebuilt,32,0)
    struct.pack_into('<HHH',rebuilt,46,0,0,0)
    loads=sorted(s[2] for s in seg if s[0]==1)
    for i,s in enumerate(seg):
        typ,off,va,pa,fs,ms,flags,align=s
        if fs:struct.pack_into('<I',rebuilt,hdr[5]+i*hdr[9]+4,va)
        if typ==1 and va==loads[0]:
            extent=loads[1] if len(loads)>1 else size
            struct.pack_into('<II',rebuilt,hdr[5]+i*hdr[9]+16,extent,extent)
    analysis=out.with_name(out.name+'.analysis.elf');analysis.write_bytes(rebuilt)
    original=bytearray(size)
    for typ,off,va,pa,fs,ms,flags,align in seg:
        if typ==1:original[va:va+fs]=source[off:off+fs]
    ranges=[];start=None
    for i,(a,b) in enumerate(zip(original,image)):
        if a!=b and start is None:start=i
        if a==b and start is not None:ranges.append([hex(start),hex(i)]);start=None
    if start is not None:ranges.append([hex(start),hex(size)])
    strings=[]
    for m in re.finditer(rb'[ -~]{6,}',image):
        s=m.group().decode('ascii')
        if re.search(r'JNI|Java_|Register|camscanner|classes|dex|attachBase|Application',s,re.I):strings.append({'offset':hex(m.start()),'text':s[:350]})
    dumps=[]
    for i,m in enumerate(maps):
        blob=bytes(u.mem_read(m['address'],m['size']));p=out.with_name(out.name+f'.map{i}.bin');p.write_bytes(blob)
        dumps.append({**m,'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(blob).hexdigest()})
    pc=u.reg_read(UC_X86_REG_EIP)
    try: disasm=[f'{x.address:#x} {x.mnemonic} {x.op_str}' for x in Cs(CS_ARCH_X86,CS_MODE_32).disasm(bytes(u.mem_read(pc,80)),pc)]
    except Exception:disasm=[]
    return {'source':str(path.relative_to(ROOT)),'source_sha256':hashlib.sha256(source).hexdigest(),'dt_init':hex(init),'emulation_base':hex(base),'instructions':counter,'instruction_limit':60000000,'returned_to_caller':pc==0x60000000,'error':error,'pc':hex(pc),'last_addresses':last,'stop_disassembly':disasm,'syscalls':calls,'faults':faults,'image_dump':str(out.relative_to(ROOT)),'image_sha256':hashlib.sha256(image).hexdigest(),'changed_bytes':sum(a!=b for a,b in zip(original,image)),'changed_ranges':ranges[:30],'changed_range_count':len(ranges),'mapped_dumps':dumps,'focused_strings':strings[:100],'scope':'Isolated x86 Unicorn DT_INIT with mmap/mprotect/munmap syscall stubs. No imports relocated, no Android/JNI runtime, no original application UI execution. Memory dumps are virtual-address images, not rebuilt loadable ELF files.'}

if __name__=='__main__':
    results=[run(ROOT/'.work/camscanner/extracted/assets/ijm_lib/x86'/n) for n in ('libexecmain.so','libexec.so')]
    target=ROOT/'output/camscanner-reverse/shell-init-emulation-evidence.json'
    target.write_text(json.dumps(results,indent=2),encoding='utf-8')
    for r in results:print(r['source'],r['changed_bytes'],r['error'],r['pc'],len(r['syscalls']),r['focused_strings'][:5])
