"""Inspect metadata of statically referenced embedded models; do not export weights."""
import sys, struct, re, json, hashlib
from pathlib import Path
from collections import Counter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.work/reverse-python'))
from elftools.elf.elffile import ELFFile

class Flat:
    def __init__(self,data): self.data=data
    def num(self,offset,fmt='I'): return struct.unpack_from('<'+fmt,self.data,offset)[0]
    def field(self,table,index):
        vt=table-self.num(table,'i')
        entry=4+2*index
        if entry>=self.num(vt,'H'): return None
        offset=self.num(vt+entry,'H')
        return table+offset if offset else None
    def indirect(self,offset): return offset+self.num(offset)
    def string(self,offset):
        if offset is None:return None
        base=self.indirect(offset)
        size=self.num(base)
        return self.data[base+4:base+4+size].decode('utf-8',errors='replace')
    def vector(self,field,kind='i'):
        if field is None:return []
        base=self.indirect(field)
        count=self.num(base)
        if count>100000: raise ValueError('Invalid vector length')
        if kind=='table': return [self.indirect(base+4+4*i) for i in range(count)]
        if kind=='string':return [self.string(base+4+4*i) for i in range(count)]
        return [self.num(base+4+4*i,kind) for i in range(count)]

schema=Path('output/camscanner-reverse/MNN.fbs').read_text()
enum=re.search(r'enum OpType : int \{(.*?)\}',schema,re.S).group(1)
enum=re.sub(r'//[^\n]*','',enum)
optypes={}
value=0
for token in enum.split(','):
    token=token.strip()
    if not token:continue
    if '=' in token:
        name,number=token.split('=');value=int(number.strip(),0)
    else:name=token
    optypes[value]=name.strip();value+=1

path=Path('.work/camscanner/extracted/lib/armeabi/libmagicenhancer.so')
source=path.open('rb');elf=ELFFile(source)
def read_virtual(addr,size):
    for seg in elf.iter_segments():
        if seg['p_vaddr']<=addr and addr+size<=seg['p_vaddr']+seg['p_filesz']:
            source.seek(seg['p_offset']+addr-seg['p_vaddr']);return source.read(size)
    raise ValueError('No file-backed mapping')

records=[]
# Ghidra loaded image base 0x10000. Locations are recovered from scanet::init_model.
for literal,pc,size in [(0x277ac,0x274bc,0xe2320),(0x277c4,0x2755e,0xd39ac),(0x277dc,0x275fe,0xef28)]:
    relative=struct.unpack('<i',read_virtual(literal-0x10000,4))[0]
    native_address=relative+pc-0x10000
    data=read_virtual(native_address,size)
    flat=Flat(data)
    net=flat.num(0)
    ops=[]
    for table in flat.vector(flat.field(net,3),'table'):
        kind=flat.field(table,5)
        typ=flat.num(kind,'i') if kind is not None else 0
        op={'name':flat.string(flat.field(table,3)),'type_id':typ,'type':optypes.get(typ,'unknown'),
            'inputs':flat.vector(flat.field(table,0)), 'outputs':flat.vector(flat.field(table,4))}
        ops.append(op)
    records.append({'library':path.name,'native_virtual_address':hex(native_address),'size':size,
                    'sha256':hashlib.sha256(data).hexdigest(),'operator_count':len(ops),
                    'operator_types':dict(Counter(op['type'] for op in ops)),
                    'output_names':flat.vector(flat.field(net,4),'string'),
                    'tensor_names':flat.vector(flat.field(net,7),'string'), 'operators':ops,
                    'limitations':['Metadata only; weights not exported or executed. Schema is current official MNN source; version compatibility not fully verified.']})
source.close()
Path('output/camscanner-reverse/embedded-model-metadata.json').write_text(json.dumps(records,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps([{k:v for k,v in r.items() if k not in ['operators','tensor_names']} for r in records],indent=2))
