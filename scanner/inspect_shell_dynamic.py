"""Read Android shell ELF32 loader metadata without trusting section headers."""
from pathlib import Path
import struct,json,hashlib
ROOT=Path(__file__).resolve().parents[1]

def inspect(path):
    data=path.read_bytes()
    assert data[:6]==b'\x7fELF\x01\x01'
    header=struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    phoff,phsize,phcount=header[5],header[9],header[10]
    segments=[struct.unpack_from('<8I',data,phoff+i*phsize) for i in range(phcount)]
    def offset(address):
        for typ,off,va,pa,filesz,memsz,flags,align in segments:
            if typ==1 and va<=address<va+filesz:return off+address-va
        raise ValueError(f'Unmapped virtual address {address:#x}')
    tags={}
    for typ,off,va,pa,filesz,memsz,flags,align in segments:
        if typ!=2:continue
        for pos in range(off,off+filesz,8):
            tag,value=struct.unpack_from('<iI',data,pos)
            if not tag:break
            tags.setdefault(tag,[]).append(value)
    strings=offset(tags[5][0]);symbols=offset(tags[6][0]);entry=tags.get(11,[16])[0]
    def string(index):
        start=strings+index;end=data.index(0,start)
        return data[start:end].decode('utf-8',errors='replace')
    if 4 in tags:
        count=struct.unpack_from('<II',data,offset(tags[4][0]))[1]
    else:raise ValueError('No SysV hash count; refuse guessed symbol coverage')
    rows=[]
    for index in range(count):
        name,value,size,info,other,section=struct.unpack_from('<IIIBBH',data,symbols+index*entry)
        if name:rows.append({'index':index,'name':string(name),'address':hex(value),'size':size,'defined':section!=0,'binding':info>>4,'type':info&15})
    return {'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(data).hexdigest(),
            'machine':header[2],'entry':hex(header[4]),'symbol_count':count,
            'needed':[string(x) for x in tags.get(1,[])],
            'initializers':{'DT_INIT':list(map(hex,tags.get(12,[]))),'DT_INIT_ARRAY':list(map(hex,tags.get(25,[]))),'DT_INIT_ARRAYSZ':tags.get(27,[])},
            'symbols':rows,'scope':'PT_LOAD and PT_DYNAMIC loader data; section headers ignored. Static only.'}

def main():
    paths=list((ROOT/'.work/camscanner/extracted/assets/ijm_lib').rglob('*.so'))
    records=[]
    for path in paths:
        row=inspect(path);records.append(row)
        print(row['path'],row['machine'],row['needed'])
        print([s for s in row['symbols'] if 'JNI' in s['name'] or 'Java_' in s['name']])
    (ROOT/'output/camscanner-reverse/shell-dynamic-evidence.json').write_text(json.dumps(records,indent=2),encoding='utf-8')

if __name__=='__main__':main()
