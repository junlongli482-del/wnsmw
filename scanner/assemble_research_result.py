"""Viewable research result: recovered enhancement + native quad/dimensions.

Perspective resampling uses host OpenCV. Curved-page dewarp is not included.
"""
from emulate_pagescan import Arm,ROOT,load_image,save_image
import numpy as np,cv2,json,struct

def main():
    out=ROOT/'output/camscanner-reverse/model-probe';records=[]
    for stem in ('photo-1','photo-2'):
        evidence=json.loads((out/f'{stem}-arm-geometry-evidence.json').read_text())
        assert evidence['status']=='success'
        quad=np.array(evidence['corners_original_image'],np.float32)
        arm=Arm();data=arm.alloc(32);arm.uc.mem_write(data,quad.tobytes())
        vec=arm.alloc(12);arm.uc.mem_write(vec,struct.pack('<3I',data,data+32,data+32))
        width=arm.alloc(4);height=arm.alloc(4)
        target_vec=arm.alloc(12)
        symbol=next(n for n in arm.symbols if 'getTargetPointsForPerspectiveTransformE' in n)
        arm.call(arm.symbols[symbol],[target_vec,vec,width,height,0,0,0])
        w,h=arm.u32(width),arm.u32(height)
        assert 100<w<10000 and 100<h<10000
        target=np.frombuffer(arm.uc.mem_read(arm.u32(target_vec),32),np.float32).reshape(4,2).copy()
        transform=cv2.getPerspectiveTransform(quad,target)
        source=load_image(ROOT/f'scanner/samples/{stem}.jpg')
        enhanced=load_image(out/f'{stem}-scan-sharpened.png')
        cropped=cv2.warpPerspective(enhanced,transform,(w,h),flags=cv2.INTER_LINEAR)
        save_image(out/f'{stem}-research-scan.png',cropped)
        before=cv2.warpPerspective(source,transform,(w,h),flags=cv2.INTER_LINEAR)
        save_image(out/f'{stem}-native-geometry-crop.png',before)
        preview=np.concatenate([cv2.resize(before,(800,600)),cv2.resize(cropped,(800,600))],axis=1)
        save_image(out/f'{stem}-research-comparison.png',preview)
        records.append({'source':stem,'output_size':[w,h],'target_points':target.tolist(),'native_target_function':symbol,'geometry_evidence':f'{stem}-arm-geometry-evidence.json','output':f'{stem}-research-scan.png'})
    (out/'assembled-evidence.json').write_text(json.dumps({'records':records,'scope':'Original models, translated enhancement/sharpening, original ARM corners and getWidthHeight, host perspective warp. No curved dewarp, no Android end-to-end equivalence.'},indent=2),encoding='utf-8')
    print(json.dumps(records,indent=2))

if __name__=='__main__':main()
