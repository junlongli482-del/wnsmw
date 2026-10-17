"""Measure original detector behavior for landscape/portrait RGBA fixtures.

Rotating/resizing the input is fixture construction, not a detector replacement.
"""
from probe_android_motion import ROOT, restart_android, request
from probe_recovered_models import load_image, save_image
import cv2
import numpy as np
import hashlib
import json
import subprocess


def main():
    out = ROOT / 'output/camscanner-reverse'
    source = load_image(ROOT / 'scanner/samples/photo-1.jpg')
    records = []
    for width, height, rotation in [(480,360,0),(360,480,90),(640,480,0),(480,640,90),
                                    (1280,720,0),(720,1280,90)]:
        pid = restart_android()
        photo = cv2.rotate(source, cv2.ROTATE_90_CLOCKWISE) if rotation else source
        image = cv2.resize(photo, (width, height))
        raw = cv2.cvtColor(image, cv2.COLOR_BGR2RGBA).tobytes()
        frames = []
        for i in range(9):
            data, elapsed = request('/detect-rgba', raw, {'X-Frame-Width':str(width),'X-Frame-Height':str(height)})
            result = json.loads(data)
            assert result['width']==width and result['height']==height
            assert len(result['quad']) in (0,8), result
            frames.append({'frame':i, **result, 'roundtrip_ms':elapsed})
        visual = image.copy()
        quad = frames[-1]['quad']
        if quad:
            cv2.polylines(visual, [np.array(quad,np.int32).reshape(4,2)], True, (0,200,0), max(2,width//240))
        name = f'photo-1-frame-{width}x{height}-r{rotation}.png'
        save_image(out / 'model-probe' / name, visual)
        record = {'width':width,'height':height,'rotation':rotation,'pid':pid,
                  'rgba_sha256':hashlib.sha256(raw).hexdigest(),'frames':frames,
                  'overlay':f'model-probe/{name}',
                  'last_quad_normalized':(np.array(quad,dtype=float).reshape(-1,2)/[width,height]).tolist() if quad else []}
        records.append(record)
        print(json.dumps({'width':width,'height':height,'statuses':[f['native_status'] for f in frames],
                          'last_quad':quad}), flush=True)
    adb = ROOT / '.work/android-sdk/platform-tools/adb.exe'
    def device(*args):
        return subprocess.check_output([str(adb),'-s','emulator-5580',*args]).decode().strip()
    installed = device('shell','pm','path','org.localresearch.scanner').removeprefix('package:')
    report = {'harness_apk_sha256':device('shell','sha256sum',installed).split()[0],
              'records':records, 'scope':'Six fresh original Android JNI sessions, 54 RGBA frames. Synthetic resize/rotation of user photo. Verifies transport and observes native boxes; does not prove physical sensor orientation, WeChat frame-size selection, camera-preview cover mapping or real-phone speed.'}
    (out / 'android-frame-size-evidence.json').write_text(json.dumps(report,indent=2), encoding='utf-8')


if __name__=='__main__':
    main()
