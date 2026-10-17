"""Check translated sharpEnhance against original ARM routine, with host blur."""
from emulate_pagescan import Arm,ROOT,load_image,save_image
from probe_scan_chain import sharp_enhance
import numpy as np,json

def main():
    arm=Arm('libmagicenhancer.so');records=[]
    rng=np.random.default_rng(131)
    for h,w in [(32,48),(401,410),(1601,3)]:
        # Last fixture covers a tall image, not the >1600 minimum-side branch.
        image=rng.integers(0,256,(h,w,3),np.uint8)
        inp=arm.mat(image);out=arm.mat(np.zeros_like(image))
        arm.call(arm.symbols['_ZN6scanet12sharpEnhanceERKN2cv3MatERS1_i'],[inp,out,2])
        actual=arm.image(out);expected=sharp_enhance(image)
        delta=np.abs(actual.astype(np.int16)-expected.astype(np.int16))
        records.append({'shape':list(image.shape),'max_absolute_difference':int(delta.max()),'mismatched_channels':int(np.count_nonzero(delta))})
    report={'library_sha256':arm.sha,'fixtures':records,'scope':'Original ARM sharpEnhance versus translation; cv::blur is bridged to the same host OpenCV for both.'}
    (ROOT/'output/camscanner-reverse/sharp-native-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    assert all(r['mismatched_channels']==0 for r in records)

if __name__=='__main__':main()
