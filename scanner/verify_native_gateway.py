"""Integration checks for the real gateway -> Android -> original JNI boundary."""
from probe_recovered_models import ROOT,load_image
import argparse,urllib.request,urllib.error,json,time,hashlib,concurrent.futures
import cv2,subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--base',default='http://127.0.0.1:18766');args=parser.parse_args()
    records=[];out=ROOT/'output/camscanner-reverse'
    def request(route,data=None,headers=None):
        start=time.perf_counter();req=urllib.request.Request(args.base+route,data=data,headers=headers or {})
        try:
            with urllib.request.urlopen(req,timeout=120) as response:return response.status,response.read(),time.perf_counter()-start
        except urllib.error.HTTPError as error:return error.code,error.read(),time.perf_counter()-start
    code,data,seconds=request('/health');assert code==200,(code,data)
    records.append({'endpoint':'/health','status':code,'seconds':seconds})
    for stem in ['photo-1','photo-2']:
        image=cv2.resize(load_image(ROOT/f'scanner/samples/{stem}.jpg'),(480,360))
        rgba=cv2.cvtColor(image,cv2.COLOR_BGR2RGBA).tobytes()
        code,data,seconds=request('/detect-rgba',rgba,{'X-Frame-Width':'480','X-Frame-Height':'360'})
        result=json.loads(data);assert code==200 and len(result['quad'])==8,(code,result)
        records.append({'endpoint':'/detect-rgba','sample':stem,'status':code,'seconds':seconds,'result':result})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(request,'/scan',(ROOT/'scanner/samples/photo-1.jpg').read_bytes(),{'Content-Type':'image/jpeg'})
        time.sleep(.1)
        code,data,seconds=request('/health');assert code==429,(code,data)
        records.append({'fixture':'request while full scan active','status':code})
        code,data,seconds=future.result();assert code==200 and data==(out/'model-probe/photo-1-android-adapter-scan.png').read_bytes()
        records.append({'endpoint':'/scan','seconds':seconds,'byte_identical_to_direct_android_adapter':True,'sha256':hashlib.sha256(data).hexdigest()})
    for route,body,headers in [('/detect-rgba',b'bad',{'X-Frame-Width':'480','X-Frame-Height':'360'}),('/detect-rgba',b'bad',{'X-Frame-Width':'481','X-Frame-Height':'360'})]:
        code,data,seconds=request(route,body,headers);assert code==400,(code,data)
        records.append({'fixture':'invalid dimensions/length','status':code,'error':json.loads(data)})
    code,data,seconds=request('/health');assert code==200
    records.append({'fixture':'valid request after failures','status':code})
    adb=ROOT/'.work/android-sdk/platform-tools/adb.exe'
    def device(*parts):return subprocess.check_output([str(adb),'-s','emulator-5580',*parts]).decode().strip()
    installed=device('shell','pm','path','org.localresearch.scanner').removeprefix('package:')
    report={'harness_apk_sha256':device('shell','sha256sum',installed).split()[0],
            'records':records,'scope':'Live original JNI integration with RGBA conversion, byte equality, concurrency rejection and error recovery. No WeChat camera UI or real phone validation.'}
    (out/'native-gateway-rgba-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
