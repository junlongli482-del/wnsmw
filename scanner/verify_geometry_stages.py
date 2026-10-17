"""Check retained native intermediate/final pixels against the full JNI chain."""
from probe_recovered_models import ROOT,load_image,save_image
import numpy as np,json,hashlib
from PIL import Image,ImageDraw,ImageFont

def main():
    out=ROOT/'output/camscanner-reverse';images=out/'model-probe'
    native=json.loads((out/'android-geometry-file-stages-report.json').read_text());records=[]
    font=ImageFont.truetype('C:/Windows/Fonts/msyh.ttc',24)
    for stem in ['photo-1','photo-2']:
        full=load_image(images/f'{stem}-android-full-native-crop.png')
        for model in ['default','alternate']:
            prefix=f'{stem}-android-geometry-file-{model}'
            perspective=load_image(images/(prefix+'-perspective.png'));dewarp=load_image(images/(prefix+'-dewarp.png'))
            row=next(x for x in native['records'] if x['sample']==stem and x['model']==model)
            same_perspective=bool(np.array_equal(perspective,dewarp));same_full=bool(np.array_equal(full,dewarp))
            if model=='default':assert same_full and not same_perspective and row['status_code']==2
            if model=='alternate' and stem=='photo-2':assert same_perspective and row['status_code']==1
            record={'sample':stem,'model':model,'status_code':row['status_code'],'confidence':row['confidence'],
                    'perspective_shape':list(perspective.shape),'dewarp_shape':list(dewarp.shape),
                    'pixel_identical_to_full_jni_crop':same_full,'pixel_identical_to_perspective':same_perspective,
                    'perspective_sha256':hashlib.sha256((images/(prefix+'-perspective.png')).read_bytes()).hexdigest(),
                    'dewarp_sha256':hashlib.sha256((images/(prefix+'-dewarp.png')).read_bytes()).hexdigest()}
            records.append(record)
            canvas=Image.new('RGB',(1600,660),'#efefef');draw=ImageDraw.Draw(canvas)
            draw.text((14,10),'原库透视裁切（展平前）',font=font,fill='black')
            draw.text((814,10),f'原库展平后 / {model} / 状态 {row["status_code"]}',font=font,fill='black')
            for x,array in [(10,perspective),(810,dewarp)]:
                preview=Image.fromarray(array[:,:,::-1]);preview.thumbnail((780,590));canvas.paste(preview,(x+(780-preview.width)//2,60+(590-preview.height)//2))
            canvas.save(images/(prefix+'-comparison.png'))
    report={'records':records,'scope':'Original cv::imread -> transformCut -> get_warp_mat -> dewarp_process(bool1,mode2), no forced branch or tensor. Both default outputs match complete CropDewarpImagePosFile output pixels. Status2 matches changed geometry; status1 matches fallback on retained alternate/photo2. Not a remap-call count, protected UI, physical phone or universal status semantics claim.'}
    (out/'android-geometry-stage-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
