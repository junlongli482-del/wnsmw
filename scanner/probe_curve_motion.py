"""Controlled translation/removal through the original contour JNI gateway."""
from pathlib import Path
from PIL import Image,ImageDraw
import urllib.request,json,hashlib,argparse
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--base',default='http://127.0.0.1:18767');args=parser.parse_args()
    out=ROOT/'output/camscanner-reverse/restored-curve-motion';out.mkdir(exist_ok=True)
    records=[]
    for stem in ['photo-1','photo-2']:
        page=Image.open(ROOT/f'scanner/samples/{stem}.jpg').convert('RGBA').resize((300,225))
        frames=[];images=[]
        for index,kind in enumerate(['stable']*6+['shift']*6+['blank']*3+['stable']*6):
            source=Image.new('RGBA',(480,360),(70,70,70,255))
            if kind!='blank':source.paste(page,(165 if kind=='shift' else 90,65))
            raw=source.tobytes();req=urllib.request.Request(args.base+'/detect-curve-rgba',data=raw,headers={'X-Frame-Width':'480','X-Frame-Height':'360'})
            with urllib.request.urlopen(req,timeout=30) as response:result=json.load(response)
            frames.append({'frame':index,'fixture':kind,'input_sha256':hashlib.sha256(raw).hexdigest(),'result':result})
            draw=ImageDraw.Draw(source);curve=result['curve']
            if curve:
                pts=[(curve[i],curve[i+1]) for i in range(0,len(curve),2)]
                draw.line(pts+[pts[0]],fill='#37fca4',width=3)
            draw.text((8,8),f'Original contour JNI | {index}: {kind}, status {result["native_status"]}',fill='white')
            images.append(source.convert('RGB'))
        def average(indices):
            values=[frames[i]['result']['quad'] for i in indices if len(frames[i]['result']['quad'])==8]
            return [sum(v[j] for v in values)/len(values) for j in range(8)] if values else None
        stable=average(range(3,6));shift=average(range(9,12));restored=average(range(18,21))
        observations={'blank_statuses':[frames[i]['result']['native_status'] for i in range(12,15)],
            'blank_frames_with_curve':[i for i in range(12,15) if frames[i]['result']['curve']]}
        if stable and shift:observations['observed_shift_per_corner']=[[shift[i]-stable[i],shift[i+1]-stable[i+1]] for i in range(0,8,2)]
        if stable and restored:observations['restored_minus_initial']=[restored[i]-stable[i] for i in range(8)]
        images[0].save(out/f'{stem}-curve-motion.gif',save_all=True,append_images=images[1:],duration=250,loop=0)
        records.append({'sample':stem,'observations':observations,'frames':frames})
        (out/'evidence.json').write_text(json.dumps({'records':records,'scope':'Actual original curve JNI over live Android gateway. Controlled source translation +75px then removal/recovery; overlay only. No camera, sensor gating or physical-phone timing claim.'},indent=2),encoding='utf-8')
        print(json.dumps({'sample':stem,**observations}),flush=True)
if __name__=='__main__':main()
