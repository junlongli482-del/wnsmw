"""Run APK-recovered dewarp networks; save raw maps without assuming semantics."""
from probe_recovered_models import ROOT,load_image,save_image
import MNN,numpy as np,cv2,os,json,hashlib,time

def main():
    os.chdir(ROOT);out=ROOT/'output/camscanner-reverse/model-probe';records=[]
    for name in ('dewarp-default','dewarp-alternate'):
        path=ROOT/f'.work/camscanner/models/{name}.mnn'
        net=MNN.Interpreter(str(path.relative_to(ROOT)));session=net.createSession({'backend':'CPU','numThread':2})
        inp=net.getSessionInput(session);shape=inp.getShape();print(name,shape,flush=True)
        for stem in ('photo-1','photo-2'):
            source=load_image(ROOT/f'scanner/samples/{stem}.jpg')
            # Recovered to_tensor_dewarp uses staged resize: 1024 then 352, then tensor size.
            side=min(source.shape[:2])
            value=cv2.resize(source,(1024,1024),interpolation=cv2.INTER_AREA) if side>=1024 else source
            if side>=352:value=cv2.resize(value,(352,352),interpolation=cv2.INTER_AREA)
            value=cv2.resize(value,(shape[3],shape[2]),interpolation=cv2.INTER_AREA)
            data=np.ascontiguousarray(value.transpose(2,0,1)[None],np.float32)/255
            inp.copyFrom(MNN.Tensor(shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Caffe))
            start=time.perf_counter();net.runSession(session)
            tensors={}
            for key,tensor in net.getSessionOutputAll(session).items():
                host=MNN.Tensor(tensor.getShape(),MNN.Halide_Type_Float,np.zeros(tensor.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
                tensor.copyToHostTensor(host);array=np.array(host.getData(),np.float32).reshape(tensor.getShape())
                assert np.isfinite(array).all()
                np.save(out/f'{stem}-{name}-{key}.npy',array)
                tensors[key]={'shape':list(array.shape),'range':[float(array.min()),float(array.max())]}
                if array.ndim==4:
                    for i,plane in enumerate(array[0]):
                        preview=np.clip((plane-plane.min())/(np.ptp(plane)+1e-9)*255,0,255).astype(np.uint8)
                        save_image(out/f'{stem}-{name}-{i}.png',preview)
            records.append({'model':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'source':stem,'input_shape':list(shape),'outputs':tensors,'seconds':time.perf_counter()-start})
    (out/'dewarp-probe-evidence.json').write_text(json.dumps({'records':records,'limitations':['BGR probe; camera input layout and complete mapping decode still require validation.','Raw network output only; no claim of completed dewarp.']},indent=2),encoding='utf-8')
    print(json.dumps(records,indent=2))

if __name__=='__main__':main()
