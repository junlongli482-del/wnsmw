"""Extract bounded DEX candidates from one retained offline heap snapshot."""
from pathlib import Path
import argparse, json, re, struct
from validate_recovered_dex import inspect

ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser();parser.add_argument('tag');args=parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+',args.tag):raise ValueError('Invalid tag')
    heap_path=ROOT/'.work/camscanner/shell-unpacked/x86'/('libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.'+args.tag+'.hostzlib.constructors.heap.bin')
    heap=heap_path.read_bytes();out=ROOT/'output/camscanner-reverse/recovered-dex'/args.tag;out.mkdir(parents=True,exist_ok=True)
    results=[]
    for match in re.finditer(rb'dex\n0[0-9]{2}\x00',heap):
        offset=match.start()
        if offset+112>len(heap):continue
        size,header,endian=struct.unpack_from('<III',heap,offset+32)
        if header!=112 or endian!=0x12345678 or size<112 or offset+size>len(heap):continue
        path=out/('candidate-'+hex(offset)+'.dex');path.write_bytes(heap[offset:offset+size])
        result=inspect(path);result['heap_offset']=hex(offset)
        (path.with_suffix('.validation.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
        results.append({k:v for k,v in result.items() if k not in ('class_descriptors','scan_related_classes')})
    evidence={'tag':args.tag,'heap_snapshot':str(heap_path),'candidates':results,'scope':'Bounded extraction from retained original-loader mixed offline execution; validation is structural and checksum only, not ART verification or original UI execution.'}
    (out/'inventory.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    print(json.dumps(evidence,indent=2))
if __name__=='__main__':main()
