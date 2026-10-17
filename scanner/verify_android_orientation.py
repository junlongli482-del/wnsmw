"""Same compressed JPEG, eight EXIF orientations, through the real Android adapter."""
from probe_recovered_models import ROOT,load_image
from PIL import Image
import struct,json,hashlib,time,urllib.request,urllib.error,io,subprocess
import numpy as np

def orient_jpeg(jpeg,orientation):
    assert jpeg[:2]==b'\xff\xd8'
    # Replace only EXIF APP1 segments; compressed scan bytes remain unchanged.
    parts=[jpeg[:2]];offset=2
    while offset<len(jpeg):
        assert jpeg[offset]==255
        marker=jpeg[offset+1]
        if marker in (0xda,0xd9):parts.append(jpeg[offset:]);break
        length=int.from_bytes(jpeg[offset+2:offset+4],'big');end=offset+2+length
        segment=jpeg[offset:end]
        if not (marker==0xe1 and segment[4:10]==b'Exif\x00\x00'):parts.append(segment)
        offset=end
    tiff=b'II'+struct.pack('<HIH',42,8,1)+struct.pack('<HHI',0x112,3,1)+struct.pack('<H',orientation)+b'\x00\x00'+struct.pack('<I',0)
    payload=b'Exif\x00\x00'+tiff
    return parts[0]+b'\xff\xe1'+struct.pack('>H',len(payload)+2)+payload+b''.join(parts[1:])

def main():
    out=ROOT/'output/camscanner-reverse';records=[]
    deadline=time.monotonic()+20
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:18766/health',timeout=3) as response:
                if json.load(response).get('status')=='ready':break
        except (OSError,ValueError):pass
        if time.monotonic()>deadline:raise RuntimeError('Original Android service did not become ready')
        time.sleep(.25)
    transforms={1:None,2:Image.Transpose.FLIP_LEFT_RIGHT,3:Image.Transpose.ROTATE_180,4:Image.Transpose.FLIP_TOP_BOTTOM,
                5:Image.Transpose.TRANSPOSE,6:Image.Transpose.ROTATE_270,7:Image.Transpose.TRANSVERSE,8:Image.Transpose.ROTATE_90}
    for stem in ['photo-1','photo-2']:
        jpeg=(ROOT/f'scanner/samples/{stem}.jpg').read_bytes()
        original=np.array(Image.open(io.BytesIO(jpeg)))
        baseline=Image.open(out/f'model-probe/{stem}-android-adapter-scan.png').convert('RGB')
        for orientation,transform in transforms.items():
            data=orient_jpeg(jpeg,orientation);parsed=Image.open(io.BytesIO(data))
            assert parsed.getexif()[0x112]==orientation and np.array_equal(original,np.array(parsed))
            start=time.perf_counter();request=urllib.request.Request('http://127.0.0.1:18766/scan',data=data,headers={'Content-Type':'image/jpeg'})
            try:
                with urllib.request.urlopen(request,timeout=120) as response:code=response.status;body=response.read()
            except urllib.error.HTTPError as error:code=error.code;body=error.read()
            row={'sample':stem,'exif_orientation':orientation,'status':code,'seconds':time.perf_counter()-start,
                 'input_sha256':hashlib.sha256(data).hexdigest(),'decoded_input_pixels_unchanged':True}
            if code==200:
                path=out/f'model-probe/{stem}-android-exif-{orientation}.png';path.write_bytes(body)
                actual=np.array(Image.open(io.BytesIO(body)).convert('RGB'))
                expected=np.array(baseline.transpose(transform) if transform is not None else baseline)
                row.update({'output':path.name,'shape':list(actual.shape),'expected_shape':list(expected.shape),
                            'pixel_identical_to_oriented_baseline':bool(np.array_equal(actual,expected)),
                            'sha256':hashlib.sha256(body).hexdigest()})
                if actual.shape==expected.shape:row['max_error']=int(np.abs(actual.astype(np.int16)-expected.astype(np.int16)).max())
            else:row['error']=body.decode(errors='replace')
            records.append(row);print(json.dumps(row),flush=True)
    adb=ROOT/'.work/android-sdk/platform-tools/adb.exe'
    def device(*parts):return subprocess.check_output([str(adb),'-s','emulator-5580',*parts]).decode().strip()
    installed=device('shell','pm','path','org.localresearch.scanner').removeprefix('package:')
    report={'harness_apk_sha256':device('shell','sha256sum',installed).split()[0],'records':records,
            'scope':'Real gateway -> Android Bitmap detection -> original crop/dewarp/enhance -> EXIF output transform. JPEG compressed pixels unchanged, all eight EXIF tags; compares with transformed baseline. Synthetic metadata fixtures, not a real phone/WeChat capture.'}
    (out/'android-orientation-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    assert all(r.get('pixel_identical_to_oriented_baseline') for r in records),'Orientation mismatch; inspect report before claiming mobile orientation support'

if __name__=='__main__':main()
