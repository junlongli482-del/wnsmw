"""Synthetic rectangle sequence passed to original SinglePageSet ARM code."""
from emulate_pagescan import Arm,ROOT
import struct,json

def main():
    arm=Arm()
    arm.call(arm.BASE+0x4e6fc+1,[])
    state=arm.BASE+0xade2d4;capacity=arm.u32(state)
    rect=arm.alloc(32);rows=[]
    base=[100,100,900,100,900,700,100,700]
    sequence=[base]*8+[[v+300 for v in base]]*8+[base]*8
    for index,values in enumerate(sequence):
        arm.uc.mem_write(rect,struct.pack('<8i',*values))
        result=arm.call(arm.symbols['_ZN8pagescan13SinglePageSet15addCurrentFrameERNS_5mRectE'],[state,rect])
        rows.append({'frame':index,'coordinate_shift':values[0]-100,'return_code':result})
    report={'capacity':capacity,'capacity_provenance':'Original ARM _INIT_2 static initializer executed; Ghidra frame-state-global-refs.txt',
        'sequence':'Synthetic repeated quads, +300 coordinate jump, return; not camera frames.',
        'observations':rows,'static_interpretation':'Warm-up returns 3. Once full, compares all eight coordinates with strict abs difference <151 and returns 1 when at least 2/3 of buffer match, otherwise 2. App interpretation of codes unverified.'}
    (ROOT/'output/camscanner-reverse/frame-state-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
