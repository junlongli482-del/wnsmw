"""Validate recovered dewarp against retained original Android float fields."""
from probe_recovered_models import ROOT,load_image
import MNN,numpy as np,cv2,os,json,itertools

def main():
    os.chdir(ROOT);out=ROOT/'output/camscanner-reverse';records=[]
    android=json.loads((out/'android-warp-confidence-report.json').read_text())
    for model in ['default','alternate']:
        net=MNN.Interpreter(f'.work/camscanner/models/dewarp-{model}.mnn');session=net.createSession({'backend':'CPU','numThread':2})
        tensor=net.getSessionInput(session);shape=tensor.getShape()
        for stem in ['photo-1','photo-2']:
            source=load_image(out/f'model-probe/{stem}-native-geometry-crop.png')
            row=next(x for x in android['records'] if x['sample']==stem and x['model']==model)
            expected=np.fromfile(out/'model-probe'/row['field_file'],np.float32).reshape(row['field_height'],row['field_width'],2)
            extrema=float(abs(expected[:,:,0].min())+abs(expected[:,:,0].max()))
            native_formula=0.0 if extrema>500 else float(expected.astype(np.float64).std(axis=(0,1)).sum())
            formula_error=abs(native_formula-row['confidence'])
            assert formula_error<1e-6,(stem,model,formula_error)
            candidates=[]
            for modes in itertools.product([cv2.INTER_LINEAR,cv2.INTER_AREA],repeat=2):
                value=cv2.resize(source,(1024,1024),interpolation=modes[0])
                value=cv2.resize(value,(352,352),interpolation=modes[1])
                value=cv2.resize(value,(shape[3],shape[2]),interpolation=cv2.INTER_AREA)
                data=np.ascontiguousarray(value.astype(np.float32)[None]/255)
                tensor.copyFrom(MNN.Tensor(data.shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Tensorflow))
                net.runSession(session);result=net.getSessionOutput(session)
                host=MNN.Tensor(result.getShape(),MNN.Halide_Type_Float,np.zeros(result.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
                result.copyToHostTensor(host)
                raw=np.asarray(host.getData(),np.float32).reshape(result.getShape())[0].transpose(1,2,0).copy()
                field=cv2.GaussianBlur(raw,(39,39),-1,borderType=cv2.BORDER_DEFAULT)
                confidence=float(field.astype(np.float64).std(axis=(0,1)).sum())
                candidates.append({'resize_modes':list(modes),'max_field_error':float(np.abs(field-expected).max()),
                   'mean_field_error':float(np.abs(field-expected).mean()),'confidence':confidence,'confidence_error':abs(confidence-row['confidence'])})
            records.append({'sample':stem,'model':model,'android_confidence':row['confidence'],
                            'native_field_derived_confidence':native_formula,'native_formula_error':formula_error,'candidates':candidates})
    report={'records':records,'scope':'Original Android fields vs host MNN3.6.1 and OpenCV; same asset PNG input. Candidate resize interpolation comparison, not an original UI or phone performance claim.'}
    (out/'android-warp-host-comparison.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
