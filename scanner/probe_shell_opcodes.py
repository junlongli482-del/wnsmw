"""Execute original restored x86 getOpCode for all byte inputs, offline."""
from pathlib import Path
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_EAX

def main():
    path=ROOT/'.work/camscanner/shell-unpacked/x86/libexecmain.so.clone.proc.constructors.bin'
    data=path.read_bytes();base=0x1000000;stop=0x60000000;stack=0x70008000
    u=Uc(UC_ARCH_X86,UC_MODE_32)
    u.mem_map(base,(len(data)+4095)&~4095);u.mem_write(base,data)
    u.mem_map(stop,4096);u.mem_write(stop,b'\x90')
    u.mem_map(0x70000000,0x10000)
    rows=[]
    for value in range(256):
        u.mem_write(stack,struct.pack('<II',stop,value));u.reg_write(UC_X86_REG_ESP,stack)
        u.emu_start(base+0x5660,stop,count=100000)
        if u.reg_read(UC_X86_REG_EIP)!=stop:raise RuntimeError(f'input {value}: function did not return')
        rows.append({'input':value,'output_low_byte':u.reg_read(UC_X86_REG_EAX)&255})
    result={'input':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(data).hexdigest(),
        'entry_elf':'0x5660','base':hex(base),'samples':rows,
        'unique_output_bytes':len({r['output_low_byte'] for r in rows}),
        'scope':'Original x86 getOpCode instructions after offline DT_INIT and constructors. No hooks/import stubs in this function. Only low EAX byte is reported; high bytes are not inferred meaningful. This table alone is not a DEX decryptor or VM implementation.'}
    output=ROOT/'output/camscanner-reverse/shell-opcode-byte-map.json'
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='samples'}))

if __name__=='__main__':main()
