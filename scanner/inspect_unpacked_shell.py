"""Focused static validation of DT_INIT memory dumps and analysis-only ELFs."""
from pathlib import Path
import sys,json,struct,hashlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from elftools.elf.elffile import ELFFile
md=Cs(CS_ARCH_X86,CS_MODE_32)
def dis(b,start,length):
    return [{'offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(b[start:start+length],start)]
def main():
    records=[]
    for name in ('libexecmain.so','libexec.so'):
        path=ROOT/'.work/camscanner/shell-unpacked/x86'/name
        image=path.read_bytes();analysis=path.with_name(path.name+'.analysis.elf')
        with analysis.open('rb') as f:
            elf=ELFFile(f)
            loads=[{'offset':hex(s['p_offset']),'vaddr':hex(s['p_vaddr']),'filesz':s['p_filesz'],'memsz':s['p_memsz']} for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
            assert elf.num_sections()==0
            for s in elf.iter_segments():
                if s['p_type']=='PT_LOAD':assert len(s.data())==s['p_filesz']
        r={'path':str(analysis.relative_to(ROOT)),'sha256':hashlib.sha256(analysis.read_bytes()).hexdigest(),'format':'ELF32 little-endian Intel 80386; analysis-only memory image; PT_LOAD p_offset=p_vaddr; first LOAD extended over restored text; stale section table stripped','section_count':0,'loads':loads,'validation':'pyelftools parses headers and all PT_LOAD file ranges without truncation. Ghidra import not executed in this step. Imports/relocations were not applied; not a runnable Android shared-library replacement.'}
        if name=='libexec.so':
            r['jni_onload']={'offset':'0x6e280','disassembly':dis(image,0x6e280,115),'finding':'Recovered JNI_OnLoad wrapper calls 0x101970, 0x101a80, 0x101a40 and 0x104770. Helpers use an explicit value stack; arguments point to binary records at 0x1290c0, 0x1290cc, 0x1290e0 and 0x129260. This suggests an interpreted/virtualized wrapper; no RegisterNatives table or Java method mapping recovered.'}
            r['value_stack_helpers']={'push':dis(image,0x101a80,32),'pop':dis(image,0x104770,32)}
        else:
            entries=struct.unpack_from('<4I',image,0x63e88)
            r['init_array']=[{'offset':hex(x),'disassembly':dis(image,x,48)} for x in entries if x]
            r['finding']='DT_INIT bitstream stage returned; four DT_INIT_ARRAY slots remain [0x43a80,0x43ae0,0x43a10,0]. These constructors were not executed by this experiment.'
        records.append(r)
    (ROOT/'output/camscanner-reverse/shell-unpacked-static-evidence.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
    print(json.dumps([{'path':r['path'],'validated_loads':len(r['loads']),'sections':r['section_count']} for r in records],indent=2))
if __name__=='__main__':main()
