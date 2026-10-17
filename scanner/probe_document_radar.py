"""Compare recovered classifier preprocessing with original Android outputs.

This uses host MNN, explicitly separate from the original Android radar report.
"""
from probe_recovered_models import ROOT,load_image
import MNN,cv2,numpy as np,json,hashlib,os

def main():
    out=ROOT/'output/camscanner-reverse'
    native=json.loads((out/'android-radar-report.json').read_text())
    model=ROOT/'.work/camscanner/models/document-radar.mnn'
    os.chdir(ROOT)
    interpreter=MNN.Interpreter(str(model.relative_to(ROOT)));session=interpreter.createSession({'backend':'CPU','numThread':2})
    tensor=interpreter.getSessionInput(session);assert tensor.getShape()==(1,3,448,448)
    records=[]
    for row in native['records']:
        path=ROOT/f"scanner/samples/{row['sample']}.jpg" if row['input']=='source' else out/f"model-probe/{row['sample']}-android-full-native-crop.png"
        image=load_image(path);h,w=image.shape[:2]
        scale=np.float32(min(448/float(h),448/float(w)))
        nw,nh=int(scale*np.float32(w)),int(scale*np.float32(h))
        resized=cv2.resize(image,(nw,nh),interpolation=cv2.INTER_LINEAR)
        dx,dy=448-nw,448-nh
        padded=cv2.copyMakeBorder(resized,dy//2,dy-dy//2,dx//2,dx-dx//2,cv2.BORDER_CONSTANT,value=(128,128,128))
        data=np.ascontiguousarray((padded.astype(np.float32)[None]-128)/128)
        tensor.copyFrom(MNN.Tensor(data.shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Tensorflow))
        interpreter.runSession(session);result=interpreter.getSessionOutput(session)
        host=MNN.Tensor(result.getShape(),MNN.Halide_Type_Float,np.zeros(result.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
        result.copyToHostTensor(host);values=np.asarray(host.getData(),np.float32)
        category=int(np.argmax(values));score=float(values[category])
        records.append({'sample':row['sample'],'input':row['input'],'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'fit_size':[nw,nh],'outputs':values.tolist(),'class_index':category,'score':score,
                        'android_class_index':row['class_index'],'android_score':row['score'],
                        'class_matches':category==row['class_index'],'score_absolute_error':abs(score-row['score'])})
    report={'model_sha256':hashlib.sha256(model.read_bytes()).hexdigest(),'records':records,
            'preprocess':'BGR; aspect-fit float32 scale/truncated integer dimensions; bilinear resize; symmetric padding 128; (pixel-128)/128; NHWC host tensor',
            'constants':{'ghidra_0x34b00':-128,'ghidra_0x34b08':.0078125},
            'scope':'Host MNN 3.6.1 vs original Android radar API. Crop PNGs preserve input pixels; original JPEG uses a different decoder. Matching labels/scores here do not establish general equivalence.'}
    (out/'document-radar-host-comparison.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
