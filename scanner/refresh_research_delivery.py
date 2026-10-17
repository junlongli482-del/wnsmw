"""Refresh local review artifacts only after the original-native probes pass."""
from pathlib import Path
import hashlib,json,shutil,zipfile,subprocess
from build_native_review import main as build_native_review

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/camscanner-reverse'

def main():
    build=json.loads((OUT/'android-research-build-evidence.json').read_text())
    apk=Path(build['apk']);assert hashlib.sha256(apk.read_bytes()).hexdigest()==build['apk_sha256']
    page_report=json.loads((OUT/'wechat-page-integration-evidence.json').read_text())
    page=ROOT/'scanner/wechat-miniprogram/pages/scan/index.js'
    assert page_report['page_js_sha256']==hashlib.sha256(page.read_bytes()).hexdigest()
    assert len(page_report['records'])>=5 and all(row['passed'] for row in page_report['records'])
    assert page_report['records'][0]['harness_apk_sha256']==build['apk_sha256']
    for name in ['android-enhance-stages-report.json','native-gateway-rgba-evidence.json','android-orientation-verification.json']:
        checked=json.loads((OUT/name).read_text())
        assert checked['harness_apk_sha256']==build['apk_sha256'],f'{name}: rerun checks on current APK'
        if name=='android-enhance-stages-report.json':assert checked['status']=='executed'
        if name=='android-orientation-verification.json':
            assert len(checked['records'])==16
            assert all(r['status']==200 and r['pixel_identical_to_oriented_baseline'] for r in checked['records'])
    enhance=json.loads((OUT/'android-enhance-host-comparison.json').read_text())
    warp_gate=json.loads((OUT/'warp-extrema-gate-evidence.json').read_text())
    assert warp_gate['passed'] and len(warp_gate['records'])==12
    assert all(row['passed'] for row in warp_gate['records'])
    frame_sizes=json.loads((OUT/'android-frame-size-evidence.json').read_text())
    assert frame_sizes['harness_apk_sha256']==build['apk_sha256']
    assert len(frame_sizes['records'])==6
    for row in frame_sizes['records']:
        assert [f['native_status'] for f in row['frames']]==[3]*7+[1]*2
        assert len(row['frames'][-1]['quad'])==8
    assert len(enhance['records'])==2
    for row in enhance['records']:
        assert row['direct_native_stages_vs_bitmap_mode3']['max_error']==0
        assert row['host_sharp_on_native_scan']['max_error']==0
    for report in ['android-radar-report.json','native-gateway-rgba-evidence.json','android-motion-status-evidence.json']:
        assert (OUT/report).exists(),report
    motion=json.loads((OUT/'android-motion-status-evidence.json').read_text())
    assert len(motion['records'])==2
    for row in motion['records']:
        assert row['following_jpeg_scan']['byte_identical_to_initial_scan']
        assert [f['native_status'] for f in row['frames'][:9]]==[3]*7+[1]*2
        assert [f['native_status'] for f in row['frames'][13:16]]==[1,2,2]
    shutil.copy2(apk,OUT/'scanner-native-research.apk')
    mini=ROOT/'scanner/wechat-miniprogram'
    with zipfile.ZipFile(OUT/'wechat-scanner-prototype.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(mini.rglob('*')):
            if path.is_file():archive.write(path,path.relative_to(mini).as_posix())
    tool=ROOT/'.work/rea-tools/android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe'
    disassembly=subprocess.run([str(tool),'-d','--triple=thumbv7-linux-android','--start-address=0x772bc','--stop-address=0x772d4',str(ROOT/'.work/camscanner/extracted/lib/armeabi/libpagescanner.so')],capture_output=True,check=True).stdout.decode()
    (OUT/'native-status-abi-evidence.json').write_text(json.dumps({'library_sha256':build['original_libraries'][0]['sha256'],
       'original_return':'ELF 0x772ca: moveq r0,r10, then stack restore and return; integer status',
       'disassembly':disassembly,'bridge_sha256':build['research_status_bridge']['sha256'],
       'runtime_evidence':'android-motion-status-evidence.json','scope':'Original native return, no replacement; observed meanings apply to retained fixtures, not recovered protected Java UI.'},indent=2),encoding='utf-8')
    path=OUT/'integration-boundary-evidence.json';boundary=json.loads(path.read_text())
    boundary['android_original_jni_research']['frame_native_status']='Original exported documentCrop status exposed through NDK thin JNI. Android motion replay 50 frames: 3 warmup,1 stable,2 hidden fallback. First blank still false positive. See android-motion-status-evidence.json and native-status-abi-evidence.json.'
    boundary['android_original_jni_research']['automatic_enhance_classifier']='Original document_radar in Android: original and cropped photos both class0. Static Bitmap mode3 routing chooses scan for0/5, scan_old otherwise. Semantic labels and original UI defaults unknown. android-radar-report.json.'
    boundary['classifier_host_comparison']='Recovered 448 aspect-fit, pad128, BGR and (pixel-128)/128. Crop PNG score error <=2.3842e-7; JPEG error up to .0075, general parity not claimed.'
    boundary['model_inventory']='Eight extracted model buffers, including radar 448x448->9 and scan-old 1024x1024->3 channels; provenance in model-extraction-evidence.json.'
    boundary['enhancement_stage_verification']='Original scan(0,1) then sharpEnhance(2) equals Bitmap mode3 pixel-for-pixel on both saved crops. Host saturation restored and ARM-verified; final mean error .002290/.004593, rare maximum25/26. android-enhance-host-comparison.json and color-native-verification.json; not universal parity.'
    boundary['jpeg_orientation']='Fixed mismatch between BitmapFactory raw detection coordinates and original file decoder EXIF rotation. Reset native source orientation metadata, transform enhanced output once. All16 same-compressed-JPEG EXIF1..8 fixtures match corresponding baseline transform pixel-for-pixel; android-orientation-verification.json. Not physical-camera/WeChat preview validation.'
    boundary['wechat_page_js_integration']='Actual page code executed in Node with wx transport/camera/canvas adapters. Real original JNI backend:37 RGBA frames plus queued shutter/scan, PNG byte equality. Five checks cover live chain, stale scan/health callbacks, throttling/cancelled frame callbacks and delayed camera callback. Does not prove WeChat runtime/rendering; wechat-page-integration-evidence.json.'
    boundary['native_removal_limitation']='Controlled photo1 sequence:9 stable frames then12 blank frames all blank returns1 (stable stale outline); restoration,4 shifted frames then3 blanks returns1,2,2. Raw original state retained; not universal removal behavior or protected UI evidence.'
    if (OUT/'android-geometry-stage-verification.json').exists():
        boundary['android_original_jni_research']['dewarp_stage_verification']='Original imread/transformCut/dewarp_process(bool1,mode2) outputs for both default photos pixel-identical to complete CropDewarpImagePosFile crops, differ from perspective intermediates, status2. Alternate photo2 status1 pixel-identical fallback. android-geometry-stage-verification.json. No remap count or protected UI claim.'
    if (OUT/'android-warp-confidence-report.json').exists():
        boundary['android_original_jni_research']['warp_confidence']='Original Android get_warp_mat, original initialization/inference/smoothing: photo1/default=.578250408, alternate=.365211427; photo2/default=.703660309, alternate=.734003007. Same earlier host-geometry PNG assets, no injected tensors/confidence. android-warp-confidence-report.json.'
        boundary['recovered_native_pipeline']['dewarp_confidence']='Earlier host fixture scores used incorrect intermediate linear resize. Android field comparison confirms INTER_AREA at all stages; host scripts corrected, historical fixture results retained. android-warp-host-comparison.json.'
        boundary['dewarp_host_parity']='Four Android fields vs corrected host: default max error <4.55e-5, alternate <6.2e-4; largest confidence error <.000143. Not universal equivalence or remap-call observation in complete crop entry.'
    boundary['warp_extrema_gate_correction']='Original ARM controlled tensors and s16/s18 capture confirm extrema gate uses channel0 only: abs(min0)+abs(max0)>500 returns0; otherwise std0+std1. Twelve signed499/500/501 cases pass, including channel1=10000. Synthetic post-inference, host GaussianBlur, not Android full-entry evidence. warp-extrema-gate-evidence.json; prior global-extrema hypothesis failed and retained separately.'
    boundary['android_frame_sizes']='Six fresh sessions,54 actual original JNI RGBA frames:480x360,360x480,640x480,480x640,1280x720,720x1280. Each observed3x7,1x2. Synthetic resize/rotation of user photo, no physical-camera/WeChat orientation,preview mapping or mid-session size-change acceptance. android-frame-size-evidence.json.'
    path.write_text(json.dumps(boundary,indent=2),encoding='utf-8')
    build_native_review()
    files=['scanner-native-research.apk','wechat-scanner-prototype.zip','原库效果核对.html','native-review-evidence.json','warp-extrema-gate-evidence.json','android-frame-size-evidence.json',
           'model-probe/photo-1-android-full-native.png','model-probe/photo-2-android-full-native.png']
    records=[{'file':name,'sha256':hashlib.sha256((OUT/name).read_bytes()).hexdigest(),'bytes':(OUT/name).stat().st_size} for name in files]
    manifest={'status':'research artifacts built and verified; real-device/WeChat acceptance pending',
              'latest_findings':['original frame status','Android original document classifier','eight model buffers','Android original warp confidence and field; area-resize correction','original perspective/dewarp stages verified','enhancement stages verified; integer saturation recovered; host residual retained','EXIF coordinate mismatch fixed; all16 orientation fixtures match transformed baselines'],
              'files':records}
    (OUT/'delivery-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
