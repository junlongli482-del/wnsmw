"""Probe recovered pagescan network. Outputs maps only, not original quadrilateral logic."""
from probe_recovered_models import ROOT, load_image, save_image
import os, json, time, hashlib
import numpy as np
import cv2
import MNN

os.chdir(ROOT)
model = ROOT / '.work/camscanner/models/pagescan.mnn'
net = MNN.Interpreter(str(model.relative_to(ROOT)))
session = net.createSession({'backend':'CPU','numThread':2})
tensor = net.getSessionInput(session)
assert tensor.getShape() == (1,3,240,240)
out = ROOT / 'output/camscanner-reverse/model-probe'
out.mkdir(parents=True,exist_ok=True)
records=[]
for path in sorted((ROOT / 'scanner/samples').glob('photo-*.jpg')):
    source=load_image(path)
    scale=min(1,416/max(source.shape[:2]))
    working=cv2.resize(source,(round(source.shape[1]*scale),round(source.shape[0]*scale)))
    # pagescan::InferNet::to_tensor contains no channel swap; JNI pixel layout unconfirmed.
    # Evaluate both orders explicitly instead of silently assuming the Java-side layout.
    for order in ['BGR','RGB']:
        image=working if order=='BGR' else cv2.cvtColor(working,cv2.COLOR_BGR2RGB)
        data=np.ascontiguousarray(cv2.resize(image,(240,240)).astype(np.float32)[None]/255)
        host=MNN.Tensor(data.shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Tensorflow)
        tensor.copyFrom(host)
        start=time.perf_counter();net.runSession(session)
        result=net.getSessionOutput(session)
        host=MNN.Tensor(result.getShape(),MNN.Halide_Type_Float,np.zeros(result.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
        result.copyToHostTensor(host)
        values=np.asarray(host.getData(),np.float32).reshape(result.getShape())[0]
        assert np.isfinite(values).all()
        maps=[cv2.resize(np.clip(v*255,0,255).astype(np.uint8),(working.shape[1],working.shape[0])) for v in values]
        for i,m in enumerate(maps):save_image(out/f'{path.stem}-pagescan-{order}-{i}.png',m)
        preview=np.concatenate([working]+[cv2.cvtColor(m,cv2.COLOR_GRAY2BGR) for m in maps],axis=1)
        save_image(out/f'{path.stem}-pagescan-{order}-comparison.png',preview)
        records.append({'source':path.name,'input_order':order,'seconds':time.perf_counter()-start,
                        'shape':list(values.shape),'min':float(values.min()),'max':float(values.max())})
report={'model_sha256':hashlib.sha256(model.read_bytes()).hexdigest(),'samples':records,
        'limitations':['Network maps only; original EDLine, candidate selection and adjustCorners not ported.',
                       'Both input channel orders probed because Java-side callers are packed. cardCut consumes first output plane.']}
(out/'pagescan-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
