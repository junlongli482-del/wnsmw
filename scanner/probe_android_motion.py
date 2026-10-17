"""Controlled motion replay through original Android JNI, without host inference."""
from probe_recovered_models import ROOT,load_image
import cv2,numpy as np,json,time,urllib.request,urllib.error,subprocess,hashlib
import argparse
from PIL import Image

BASE='http://127.0.0.1:18766'
ADB=ROOT/'.work/android-sdk/platform-tools/adb.exe'

def request(route,data=None,headers=None):
    start=time.perf_counter()
    with urllib.request.urlopen(urllib.request.Request(BASE+route,data=data,headers=headers or {}),timeout=120) as response:
        return response.read(),(time.perf_counter()-start)*1000

def restart_android():
    def adb(*args):return subprocess.run([str(ADB),'-s','emulator-5580',*args],check=True,capture_output=True).stdout
    adb('shell','am','force-stop','org.localresearch.scanner')
    adb('shell','am','start','-n','org.localresearch.scanner/.MainActivity','--es','stage','http-server')
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        try:
            data,_=request('/health')
            if json.loads(data)['status']=='ready':return int(adb('shell','pidof','org.localresearch.scanner').strip())
        except (OSError,ValueError):pass
        time.sleep(.25)
    raise RuntimeError('Android original JNI service did not initialize')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--suffix',default='status');args=parser.parse_args()
    out=ROOT/'output/camscanner-reverse';records=[]
    for stem in ['photo-1','photo-2']:
        pid=restart_android();source=load_image(ROOT/f'scanner/samples/{stem}.jpg')
        page=cv2.resize(source,(300,225));frames=[];images=[]
        sequence=['stable']*9+['shift']*4+['blank']*3+['stable']*9
        for index,kind in enumerate(sequence):
            image=np.full((360,480,3),70,np.uint8)
            if kind!='blank':
                left=90 if kind=='stable' else 165;image[65:290,left:left+300]=page
            rgba=cv2.cvtColor(image,cv2.COLOR_BGR2RGBA).tobytes()
            data,ms=request('/detect-rgba',rgba,{'X-Frame-Width':'480','X-Frame-Height':'360'})
            result=json.loads(data);quad=result['quad']
            assert len(quad) in (0,8),result
            frames.append({'frame':index,'fixture':kind,'quad':quad,'raw_quad':result.get('raw_quad'),
                           'native_status':result.get('native_status'),'stable':result.get('stable'),'milliseconds':ms,'native_ms':result['native_ms']})
            if quad:cv2.polylines(image,[np.array(quad,np.int32).reshape(4,2)],True,(100,240,100),2)
            cv2.putText(image,f'Original Android - {index}: {kind}, status {result.get("native_status")}',(8,22),cv2.FONT_HERSHEY_SIMPLEX,.44,(255,255,255),1,cv2.LINE_AA)
            images.append(Image.fromarray(cv2.cvtColor(image,cv2.COLOR_BGR2RGB)))
        def mean_quad(indices):
            values=[np.array(frames[i]['quad'],float).reshape(4,2) for i in indices if frames[i]['quad']]
            return np.mean(values,axis=0) if values else None
        stable=mean_quad(range(6,9));shift=mean_quad(range(10,13));restored=mean_quad(range(22,25))
        observations={'blank_frames_with_quad':[i for i in range(13,16) if frames[i]['quad']],
                      'post_blank_first_quad_frame':next((i for i in range(16,25) if frames[i]['quad']),None)}
        if stable is not None and shift is not None:observations['observed_shift_per_corner']=(shift-stable).tolist()
        if stable is not None and restored is not None:observations['restored_quad_minus_initial']=(restored-stable).tolist()
        raw,ms=request('/scan',(ROOT/f'scanner/samples/{stem}.jpg').read_bytes(),{'Content-Type':'image/jpeg'})
        expected=(out/f'model-probe/{stem}-android-adapter-scan.png').read_bytes()
        identical=raw==expected
        (out/f'model-probe/{stem}-android-after-motion-scan.png').write_bytes(raw)
        images[0].save(out/f'model-probe/{stem}-android-motion-{args.suffix}-replay.gif',save_all=True,append_images=images[1:],duration=[max(100,min(1000,int(f['milliseconds']))) for f in frames],loop=0)
        records.append({'sample':stem,'pid':pid,'frames':frames,'observations':observations,
                        'following_jpeg_scan':{'milliseconds':ms,'sha256':hashlib.sha256(raw).hexdigest(),'byte_identical_to_initial_scan':identical}})
        # Retain unexpected differences as findings, rather than silently resetting them.
        report={'records':records,'scope':'Fresh Android original native sessions, controlled 480x360 RGBA fixtures, expected page translation +75 px then removal/recovery. No PC model inference or synthetic tensor injection. New thin JNI calls original exported documentCrop and exposes its actual integer status; quad filters native status 2, raw_quad retained. GIF overlay is research UI, not original app UI. No real-phone/camera claim.'}
        (out/f'android-motion-{args.suffix}-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'sample':stem,'observations':observations,'following_jpeg_scan':records[-1]['following_jpeg_scan']},indent=2),flush=True)

if __name__=='__main__':main()
