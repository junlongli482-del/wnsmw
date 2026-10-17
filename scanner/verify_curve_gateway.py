"""Verify original contour JNI through actual research HTTP transport."""
from pathlib import Path
import json,urllib.request,urllib.error,argparse,hashlib
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--base',default='http://127.0.0.1:18767');args=p.parse_args()
    records=[];blank=bytes([80])*(480*360)+bytes([128])*(480*360//2)
    def request(data,width=480,route='/detect-curve'):
        req=urllib.request.Request(args.base+route,data=data,headers={'X-Frame-Width':str(width),'X-Frame-Height':'360'})
        try:
            with urllib.request.urlopen(req,timeout=30) as r:return r.status,json.load(r)
        except urllib.error.HTTPError as e:return e.code,json.load(e)
    for stem in ['photo-1','photo-2']:
        source=(ROOT/f'.work/android-research-build/assets/{stem}.nv21')
        if not source.exists():
            # Build script stages assets in its own source directory.
            matches=list((ROOT/'.work/android-research-build').rglob(stem+'.nv21'))
            if len(matches)!=1:raise ValueError(matches)
            source=matches[0]
        for kind,body in [('page',source.read_bytes()),('blank',blank),('restored',source.read_bytes())]:
            code,result=request(body);assert code==200,(code,result)
            if kind=='blank':assert result['native_status']<0 and not result['quad'] and not result['curve'],result
            else:
                assert result['native_status']>=0 and len(result['quad'])==8 and len(result['curve'])==160,result
                assert all(0<=v<=(480 if i%2==0 else 360) for i,v in enumerate(result['curve'])),result
            records.append({'sample':stem,'fixture':kind,'input_sha256':hashlib.sha256(body).hexdigest(),'http_status':code,'result':result})
        rgba=Image.open(ROOT/f'scanner/samples/{stem}.jpg').convert('RGBA').resize((480,360)).tobytes()
        code,result=request(rgba,route='/detect-curve-rgba')
        assert code==200 and len(result['curve'])==160 and len(result['quad'])==8,(code,result)
        records.append({'sample':stem,'fixture':'RGBA conversion path','http_status':code,'result':result})
    for body,width in [(b'bad',480),(b'bad',481)]:
        code,result=request(body,width);assert code==400,(code,result)
        records.append({'fixture':'invalid length/dimensions','http_status':code,'result':result})
    with urllib.request.urlopen(args.base+'/health',timeout=10) as r:assert r.status==200
    report={'records':records,'scope':'Actual HTTP gateway -> Android original initContourMask/DetectCurveBorderYUV. Controlled fixtures only, no WeChat runtime or physical camera test.'}
    out=ROOT/'output/camscanner-reverse/curve-gateway-evidence.json';out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'report':str(out),'checks':len(records),'status':'passed'}))
if __name__=='__main__':main()
