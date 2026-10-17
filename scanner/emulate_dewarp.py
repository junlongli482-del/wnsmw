"""Attempt original ARM dewarp map decoder; preserve failures explicitly."""
from emulate_pagescan import Arm,ROOT,load_image,save_image
import numpy as np,cv2,json,time
from unicorn.arm_const import UC_ARM_REG_PC

def main():
    out=ROOT/'output/camscanner-reverse/model-probe';arm=Arm()
    source=load_image(ROOT/'scanner/samples/photo-1.jpg');source=cv2.resize(source,(416,312))
    raw=np.load(out/'photo-1-dewarp-default-output.npy')[0].transpose(1,2,0).copy()
    # get_warp_mat smooths the original 2-channel field with a 39x39 Gaussian.
    field=cv2.GaussianBlur(raw,(39,39),-1,borderType=cv2.BORDER_DEFAULT)
    inp=arm.mat(source);mask=arm.mat(np.full(source.shape[:2],255,np.uint8));mapping=arm.mat(field)
    result=arm.mat(np.zeros_like(source));result_mask=arm.mat(np.zeros(source.shape[:2],np.uint8))
    start=time.perf_counter();record={}
    try:
        symbol=next(n for n in arm.symbols if 'cv_remap_adjust_with_mask' in n)
        arm.call(arm.symbols[symbol],[inp,mask,mapping,result,result_mask,312,416,0])
        image=arm.image(result);save_image(out/'photo-1-native-dewarp-probe.png',image)
        record.update(status='success',output_shape=list(image.shape))
    except Exception as exc:record.update(status='failed',error=str(exc),pc=hex(arm.uc.reg_read(UC_ARM_REG_PC)))
    record.update(seconds=time.perf_counter()-start,host_import_calls=arm.trace,
        scope='Original remap decoder attempt with recovered field. Input mode/crop order not yet verified against Android.')
    (out/'native-dewarp-evidence.json').write_text(json.dumps(record,indent=2),encoding='utf-8');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
