"""Verify saved Android JNI output changes; make a matched-input comparison."""
from probe_recovered_models import ROOT,load_image,save_image
import cv2,numpy as np,json
from PIL import Image,ImageDraw,ImageFont

def main():
    out=ROOT/'output/camscanner-reverse/model-probe';records=[]
    font=ImageFont.truetype('C:/Windows/Fonts/msyh.ttc',25)
    for stem in ['photo-1','photo-2']:
        source=load_image(out/f'{stem}-native-geometry-crop.png');entries=[]
        for suffix in ['enhance-mode0','enhance-mode1','enhance-mode3','dewarp','dewarp-old','pipeline']:
            path=out/f'{stem}-android-{suffix}.png'
            if not path.exists():continue
            target=load_image(path);assert target.shape==source.shape
            diff=np.abs(target.astype(np.int16)-source.astype(np.int16))
            entries.append({'operation':suffix,'identical_to_input':bool(np.array_equal(source,target)),
                'mean_absolute_channel_change':float(diff.mean()),'changed_pixel_fraction':float(np.any(diff!=0,axis=2).mean()),
                'shape':list(target.shape),'output':path.name})
        tiles=[]
        for title,img in [('原始裁切输入',source),('原库增强（mode=3）',load_image(out/f'{stem}-android-enhance-mode3.png')),
                          ('原库展平 → 原库增强',load_image(out/f'{stem}-android-pipeline.png'))]:
            tile=Image.new('RGB',(800,640),'#efefef');view=Image.fromarray(cv2.cvtColor(img,cv2.COLOR_BGR2RGB))
            view.thumbnail((780,580));tile.paste(view,((800-view.width)//2,50+(580-view.height)//2))
            ImageDraw.Draw(tile).text((20,10),title,font=font,fill='#111111');tiles.append(tile)
        canvas=Image.new('RGB',(2400,640),'white')
        for i,tile in enumerate(tiles):canvas.paste(tile,(800*i,0))
        canvas.save(out/f'{stem}-android-native-comparison.png')
        records.append({'sample':stem,'input':f'{stem}-native-geometry-crop.png','operations':entries})
    report={'records':records,'scope':'Output pixel changes do not establish visual quality or original-app equivalence. Input crops were produced using original recovered geometry and host OpenCV perspective resampling. Android bitmap stages use unmodified original native libraries and bundled inference. Mode 3 and stage ordering are researcher-selected; original UI defaults remain unverified.'}
    (ROOT/'output/camscanner-reverse/android-output-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
