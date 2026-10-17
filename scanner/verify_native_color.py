"""Verify the recovered integer saturation against shipped ARM machine code."""
from emulate_pagescan import Arm,ROOT
from probe_scan_chain import enhance_color
import numpy as np,json

def main():
    arm=Arm('libmagicenhancer.so');rng=np.random.default_rng(421);records=[]
    fixtures=[rng.integers(0,256,(32,48,3),np.uint8),
              np.repeat(np.arange(256,dtype=np.uint8)[None,:,None],3,axis=2),
              np.array([[[0,255,255],[255,0,255],[255,255,0],[1,0,0],[0,1,0],[0,0,1]]],np.uint8)]
    for image in fixtures:
        mat=arm.mat(image)
        arm.call(arm.symbols['_ZN6scanet13enhance_colorERN2cv3MatE'],[mat])
        actual=arm.image(mat);expected=enhance_color(image)
        delta=np.abs(actual.astype(np.int16)-expected.astype(np.int16))
        records.append({'shape':list(image.shape),'max_error':int(delta.max()),'mismatched_channels':int(np.count_nonzero(delta))})
    report={'library_sha256':arm.sha,'records':records,'scope':'Original ARM enhance_color executes unmodified; cvtColor temporary is host-bridged, integer output loop is original machine code. Random, gray ramp and clipping/color extremes; not end-to-end parity.'}
    (ROOT/'output/camscanner-reverse/color-native-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));assert all(r['max_error']==0 for r in records)

if __name__=='__main__':main()
