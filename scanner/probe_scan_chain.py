"""Experimental translation of the recovered three-network scanet::scan branch.

This is research output, pending original-device numerical comparison.
"""
from probe_recovered_models import ROOT, load_image, save_image
import os, json, time, hashlib
import cv2
import numpy as np
import MNN

def resize_planes(value,size):
    return np.stack([cv2.resize(p,(size,size)) for p in value])

class Network:
    def __init__(self,index):
        path=ROOT/f'.work/camscanner/models/model-{index}.mnn'
        self.sha=hashlib.sha256(path.read_bytes()).hexdigest()
        self.net=MNN.Interpreter(str(path.relative_to(ROOT)))
        self.session=self.net.createSession({'backend':'CPU','numThread':2})
        self.input=self.net.getSessionInput(self.session)
        self.shape=self.input.getShape()
    def run(self,chw):
        data=np.ascontiguousarray(chw[None],dtype=np.float32)
        assert data.shape==self.shape
        host=MNN.Tensor(data.shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Caffe)
        self.input.copyFrom(host)
        self.net.runSession(self.session)
        out=self.net.getSessionOutput(self.session)
        host=MNN.Tensor(out.getShape(),MNN.Halide_Type_Float,np.zeros(out.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
        out.copyToHostTensor(host)
        value=np.array(host.getData(),np.float32).reshape(out.getShape())[0]
        assert np.isfinite(value).all()
        return value

def quantize_resize(value,kind,w,h):
    # Original stores three planes in a single 3H-by-W cv::Mat before resize.
    limits=np.iinfo(kind)
    quantized=np.clip(np.rint(value*256),limits.min,limits.max).astype(kind)
    return cv2.resize(quantized.reshape(-1,value.shape[2]),(w,h*3)).reshape(3,h,w)

def sharp_enhance(source,strength=2):
    # Literal translation of scanet::sharpEnhance at ELF 0x1d4b0.
    side=min(source.shape[:2])
    kernel=(strength << int(side>400) << int(side>1600))-1
    blurred=cv2.blur(source,(kernel,kernel),borderType=cv2.BORDER_DEFAULT)
    diff=source.astype(np.int16)-blurred.astype(np.int16)
    boost=np.where(diff < -20,diff*2,diff)
    boost=np.where(diff > -10,diff>>1,boost)
    return np.clip(source.astype(np.int16)+boost,0,255).astype(np.uint8)

def enhance_color(source):
    # scanet::enhance_color, ELF 0x1a76c: original integer BGR saturation.
    value=source.astype(np.int32)
    gray=(value[:,:,0]*15+value[:,:,1]*75+value[:,:,2]*38)>>7
    return np.clip((3*value-gray[:,:,None])>>1,0,255).astype(np.uint8)

def main():
    os.chdir(ROOT)
    networks=[Network(i) for i in range(1,4)]
    out=ROOT/'output/camscanner-reverse/model-probe'
    records=[]
    for path in sorted((ROOT/'scanner/samples').glob('photo-*.jpg')):
        source=load_image(path);h,w=source.shape[:2]
        start=time.perf_counter()
        rgb=cv2.cvtColor(source,cv2.COLOR_BGR2RGB)
        illumination=networks[0].run(cv2.resize(rgb,(480,480)).transpose(2,0,1).astype(np.float32)/255)
        corrected=np.clip(cv2.resize(rgb,(1024,1024)).transpose(2,0,1).astype(np.float32)/(resize_planes(illumination,1024)*255),0,1)
        residual=networks[1].run(resize_planes(corrected,360))
        bias=networks[2].run(corrected+resize_planes(residual,1024))
        residual_full=quantize_resize(residual,np.int16,w,h).astype(np.int32)
        bias_full=quantize_resize(bias,np.int16,w,h).astype(np.int32)
        gain_full=quantize_resize(1/illumination,np.uint16,w,h).astype(np.int32)
        original=rgb.transpose(2,0,1).astype(np.int32)
        result=np.clip(((original*gain_full)>>8)+bias_full+residual_full,0,255).astype(np.uint8)
        enhanced=cv2.cvtColor(result.transpose(1,2,0),cv2.COLOR_RGB2BGR)
        save_image(out/f'{path.stem}-scan-three-model.png',enhanced)
        sharpened=sharp_enhance(enhanced)
        save_image(out/f'{path.stem}-scan-sharpened.png',sharpened)
        save_image(out/f'{path.stem}-scan-three-model-comparison.png',np.concatenate([cv2.resize(source,(640,480)),cv2.resize(enhanced,(640,480))],axis=1))
        records.append({'source':path.name,'seconds':time.perf_counter()-start,
                        'ranges':{n:[float(v.min()),float(v.max()),float(v.mean())] for n,v in [('illumination',illumination),('residual',residual),('bias',bias)]}})
    report={'model_sha256':[n.sha for n in networks],'samples':records,
            'recovered_formula':'clip((source * round(256 / illumination) >> 8) + round(256 * residual) + round(256 * bias), 0, 255)',
            'limitations':['Experimental static translation of scanet::scan; not original end-to-end app output.',
                           'No original Android runtime numerical comparison; independent MNN/OpenCV versions.',
                           'sharpEnhance translated separately; optional enhance_color, crop and dewarp not included.']}
    (out/'three-model-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
