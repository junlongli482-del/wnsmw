"""Read-only ELF symbol/call evidence; never executes target code."""
import sys, json, hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.work/reverse-python'))
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

root=Path('.work/camscanner/extracted/lib/armeabi')
out=Path('output/camscanner-reverse')
out.mkdir(parents=True, exist_ok=True)
for name in ['libscannercs.so','libpagescanner.so','libmagicenhancer.so','libimageprocessor.so']:
    path=root/name
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        symbols=[]
        for section in elf.iter_sections():
            if section['sh_type'] in ('SHT_DYNSYM','SHT_SYMTAB'):
                for s in section.iter_symbols():
                    if s.name:
                        symbols.append({'name':s.name,'address':int(s['st_value']), 'size':int(s['st_size']), 'defined':s['st_shndx']!='SHN_UNDEF','type':s['st_info']['type']})
        dependencies=[]
        dynamic=elf.get_section_by_name('.dynamic')
        if dynamic:
            dependencies=[t.needed for t in dynamic.iter_tags() if t.entry.d_tag=='DT_NEEDED']
        by_address={s['address'] & ~1:s['name'] for s in symbols if s['defined']}
        # ARM ELF PLT uses a 20-byte resolver header followed by 12-byte slots.
        plt=elf.get_section_by_name('.plt')
        relplt=elf.get_section_by_name('.rel.plt')
        if plt is not None and relplt is not None:
            linked=elf.get_section(relplt['sh_link'])
            for ordinal, relocation in enumerate(relplt.iter_relocations()):
                by_address[int(plt['sh_addr'])+20+ordinal*12]='PLT:'+linked.get_symbol(relocation['r_info_sym']).name
        selected=[]
        for s in symbols:
            if not s['defined'] or s['type']!='STT_FUNC':
                continue
            if not any(k.lower() in s['name'].lower() for k in ['detectYuv','detectBorder','detectImage','deshadow','enhance','CropDewarp','initDeshadow','initDeblur','DetectFrame','DetectCurve','documentCrop','VedioCrop','DetectCardInVideo','DetectBoundInVideo','scanet4scan','init_model','cardCut','SinglePageSet','adjustCorners','InferNet9initilize','InferNet9to_tensor','findLines_EDLine']):
                continue
            address=s['address'] & ~1
            data=None
            for segment in elf.iter_segments():
                start=int(segment['p_vaddr'])
                if start<=address<start+int(segment['p_filesz']):
                    stream.seek(int(segment['p_offset'])+address-start)
                    data=stream.read(min(s['size'],4000))
                    break
            if data is None:
                continue
            dis=Cs(CS_ARCH_ARM, CS_MODE_THUMB if s['address']&1 else CS_MODE_ARM)
            lines=[]
            for ins in dis.disasm(data,address):
                target=''
                if ins.mnemonic in ('bl','blx','b','b.w') and ins.op_str.startswith('#0x'):
                    target=by_address.get(int(ins.op_str[1:],16),'')
                lines.append(f'{ins.address:08x}: {ins.mnemonic} {ins.op_str}'+ (' ; '+target if target else ''))
            selected.append({'symbol':s,'assembly':lines,'truncated':s['size']>4000})
        result={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'machine':elf['e_machine'],'dependencies':dependencies,'symbols':symbols,'selected_jni':selected,'limitations':['Static symbol and disassembly evidence only; no runtime invocation or inferred call ordering.']}
        (out/(name+'.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(name, 'symbols',len(symbols),'functions disassembled',len(selected),'dependencies',dependencies)
