"""Test a crop-first hypothesis with original networks and ARM field decoder.

This is a controlled hypothesis, not evidence of the packed Java caller order.
"""
from emulate_pagescan import Arm, ROOT, load_image, save_image
import MNN, numpy as np, cv2, os, json, time

def infer(net,session,source):
    tensor=net.getSessionInput(session);shape=tensor.getShape();side=min(source.shape[:2])
    # Android get_warp_mat field comparison confirms area for every resize stage.
    value=cv2.resize(source,(1024,1024),interpolation=cv2.INTER_AREA) if side>=1024 else source
    if side>=352:value=cv2.resize(value,(352,352),interpolation=cv2.INTER_AREA)
    value=cv2.resize(value,(shape[3],shape[2]),interpolation=cv2.INTER_AREA)
    data=np.ascontiguousarray(value.transpose(2,0,1)[None],np.float32)/255
    tensor.copyFrom(MNN.Tensor(shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Caffe))
    net.runSession(session);result=net.getSessionOutput(session)
    host=MNN.Tensor(result.getShape(),MNN.Halide_Type_Float,np.zeros(result.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
    result.copyToHostTensor(host)
    return np.array(host.getData(),np.float32).reshape(result.getShape())[0].transpose(1,2,0).copy()

def decode(source,raw):
    arm=Arm();arm.capture_remaps=True
    field=cv2.GaussianBlur(raw,(39,39),-1,borderType=cv2.BORDER_DEFAULT)
    h,w=source.shape[:2]
    args=[arm.mat(source),arm.mat(np.full((h,w),255,np.uint8)),arm.mat(field),
          arm.mat(np.zeros_like(source)),arm.mat(np.zeros((h,w),np.uint8)),h,w,0]
    symbol=next(n for n in arm.symbols if 'cv_remap_adjust_with_mask' in n)
    arm.call(arm.symbols[symbol],args)
    return arm.image(args[3]),arm.image(args[4]),arm

def main():
    os.chdir(ROOT);out=ROOT/'output/camscanner-reverse/model-probe';records=[]
    for model in ('dewarp-default','dewarp-alternate'):
        net=MNN.Interpreter(f'.work/camscanner/models/{model}.mnn')
        session=net.createSession({'backend':'CPU','numThread':2})
        for stem in ('photo-1','photo-2'):
            source=load_image(out/f'{stem}-native-geometry-crop.png')
            start=time.perf_counter();raw=infer(net,session,source)
            np.save(out/f'{stem}-cropped-{model}-raw.npy',raw)
            # Full-resolution decoding keeps model displacements and host resampling auditable.
            image,mask,arm=decode(source,raw)
            assert np.isfinite(image).all() and arm.remap_captures
            prefix=f'{stem}-cropped-{model}'
            save_image(out/f'{prefix}.png',image);save_image(out/f'{prefix}-mask.png',mask)
            enhanced=load_image(out/f'{stem}-research-scan.png')
            capture=arm.remap_captures[0]
            np.savez_compressed(out/f'{prefix}-maps.npz',map1=capture['map1'],map2=capture['map2'] if capture['map2'] is not None else np.empty(0))
            enhanced,_,_=decode(enhanced,raw)
            assert enhanced.shape==image.shape
            save_image(out/f'{prefix}-enhanced.png',enhanced)
            comparison=np.concatenate([cv2.resize(source,(720,520)),cv2.resize(image,(720,520)),cv2.resize(enhanced,(720,520))],axis=1)
            save_image(out/f'{prefix}-comparison.png',comparison)
            record={'sample':stem,'model':model,'hypothesis':'crop then infer BGR then original decoder; enhanced image uses same geometry',
                    'source_shape':list(source.shape),'output_shape':list(image.shape),'seconds':time.perf_counter()-start,
                    'mask_nonzero_fraction':float(np.count_nonzero(mask)/mask.size),'remaps':len(arm.remap_captures),
                    'map_shape':list(capture['map1'].shape),'map_range':[float(capture['map1'].min()),float(capture['map1'].max())],
                    'host_import_calls':arm.trace,'library_sha256':arm.sha}
            records.append(record);print(json.dumps(record),flush=True)
            (out/'cropped-dewarp-evidence.json').write_text(json.dumps({'records':records,'scope':'Original ARM decoding, host OpenCV resampling. Crop-first input and BGR remain hypotheses. No Android equivalence.'},indent=2),encoding='utf-8')

if __name__=='__main__':main()
