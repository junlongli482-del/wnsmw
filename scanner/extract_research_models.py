"""Recover only statically referenced MNN buffers from the supplied APK libraries.

Private research artifacts go to .work, not a deployable application bundle.
"""
from probe_recovered_models import ROOT
from elftools.elf.elffile import ELFFile
import struct,hashlib,json

SPECS={
    'libmagicenhancer.so':[
        ('model-1',0x277ac,0x274bc,0xe2320),
        ('model-2',0x277c4,0x2755e,0xd39ac),
        ('model-3',0x277dc,0x275fe,0xef28),
        ('document-radar',0x2d82c,0x2d758,0x9848c),
        ('scan-old',0x2e830,0x2e2a0,0xcab4)],
    'libpagescanner.so':[
        ('pagescan',0x81aa8,0x81a06,0x182eb0),
        ('dewarp-default',0x922e4,0x921e8,0x182e68),
        ('dewarp-alternate',0x922ec,0x921c8,0xcee20)]}

def main():
    out=ROOT/'.work/camscanner/models';out.mkdir(parents=True,exist_ok=True)
    records=[]
    for library,specs in SPECS.items():
        path=ROOT/'.work/camscanner/extracted/lib/armeabi'/library
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            def read(addr,size):
                for seg in elf.iter_segments():
                    if seg['p_type']=='PT_LOAD' and seg['p_vaddr']<=addr and addr+size<=seg['p_vaddr']+seg['p_filesz']:
                        stream.seek(seg['p_offset']+addr-seg['p_vaddr']);return stream.read(size)
                raise ValueError(f'No file-backed range: {addr:x}+{size:x}')
            for name,literal,pc,size in specs:
                address=pc-0x10000+struct.unpack('<i',read(literal-0x10000,4))[0]
                data=read(address,size)
                root=struct.unpack_from('<I',data)[0]
                assert 0<root<len(data)-4
                (out/f'{name}.mnn').write_bytes(data)
                records.append({'name':name,'library':library,'library_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'ghidra_literal':hex(literal),'ghidra_pc':hex(pc),'elf_address':hex(address),
                    'length':size,'sha256':hashlib.sha256(data).hexdigest()})
    (ROOT/'output/camscanner-reverse/model-extraction-evidence.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
    print(json.dumps(records,indent=2))

if __name__=='__main__':main()
