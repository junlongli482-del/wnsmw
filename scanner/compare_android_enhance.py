"""Same-input comparison of recovered enhancement against original Android JNI."""
from probe_scan_chain import Network,resize_planes,quantize_resize,sharp_enhance,enhance_color
from probe_recovered_models import ROOT,load_image,save_image
import os,json,time,cv2,numpy as np,hashlib

def translate(source,networks):
    h,w=source.shape[:2];rgb=cv2.cvtColor(source,cv2.COLOR_BGR2RGB)
    illumination=networks[0].run(cv2.resize(rgb,(480,480)).transpose(2,0,1).astype(np.float32)/255)
    corrected=np.clip(cv2.resize(rgb,(1024,1024)).transpose(2,0,1).astype(np.float32)/(resize_planes(illumination,1024)*255),0,1)
    residual=networks[1].run(resize_planes(corrected,360))
    bias=networks[2].run(corrected+resize_planes(residual,1024))
    residual_full=quantize_resize(residual,np.int16,w,h).astype(np.int32)
    bias_full=quantize_resize(bias,np.int16,w,h).astype(np.int32)
    gain_full=quantize_resize(1/illumination,np.uint16,w,h).astype(np.int32)
    result=np.clip(((rgb.transpose(2,0,1).astype(np.int32)*gain_full)>>8)+bias_full+residual_full,0,255).astype(np.uint8)
    enhanced=cv2.cvtColor(result.transpose(1,2,0),cv2.COLOR_RGB2BGR)
    return enhanced,sharp_enhance(enhanced)

def metrics(a,b):
    assert a.shape==b.shape,(a.shape,b.shape)
    delta=np.abs(a.astype(np.int16)-b.astype(np.int16))
    return {'max_error':int(delta.max()),'mean_error':float(delta.mean()),'p99_error':float(np.percentile(delta,99)),
            'mismatched_channels':int(np.count_nonzero(delta)),'equal_channel_fraction':float(np.mean(delta==0)),
            'channel_fraction_over_8':float(np.mean(delta>8))}

def main():
    os.chdir(ROOT);out=ROOT/'output/camscanner-reverse';records=[];networks=[Network(i) for i in range(1,4)]
    for stem in ['photo-1','photo-2']:
        path=out/f'model-probe/{stem}-native-geometry-crop.png';source=load_image(path)
        baseline=load_image(out/f'model-probe/{stem}-android-enhance-mode3.png')
        start=time.perf_counter();enhanced,sharp=translate(source,networks)
        save_image(out/f'model-probe/{stem}-host-same-crop-enhance.png',sharp)
        native_scan=load_image(out/f'model-probe/{stem}-android-enhance-stage-scan.png')
        native_sharp=load_image(out/f'model-probe/{stem}-android-enhance-stage-sharp.png')
        colored=enhance_color(enhanced)
        save_image(out/f'model-probe/{stem}-host-same-crop-color-sharp.png',sharp_enhance(colored))
        records.append({'sample':stem,'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'seconds':time.perf_counter()-start,'before_sharp':metrics(enhanced,baseline),'after_sharp':metrics(sharp,baseline),
                        'host_scan_vs_native_scan':metrics(enhanced,native_scan),
                        'host_scan_with_color_vs_native_scan':metrics(colored,native_scan),
                        'host_color_sharp_vs_bitmap_mode3':metrics(sharp_enhance(colored),baseline),
                        'host_sharp_on_native_scan':metrics(sharp_enhance(native_scan),native_sharp),
                        'direct_native_stages_vs_bitmap_mode3':metrics(native_sharp,baseline)})
    report={'records':records,'model_sha256':[n.sha for n in networks],'host_opencv':cv2.__version__,
            'native_stage_report_sha256':hashlib.sha256((out/'android-enhance-stages-report.json').read_bytes()).hexdigest(),
            'scope':'Same PNG as Android Bitmap enhancement fixture. Host MNN3.6.1/OpenCV translated three-model chain; recovered optional enhance_color enabled before sharp. Before/after_sharp retain omitted-color comparison. Rare differences remain; not universal parity or original protected UI defaults.'}
    (out/'android-enhance-host-comparison.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
    assert all(r['host_sharp_on_native_scan']['max_error']==0 and r['direct_native_stages_vs_bitmap_mode3']['max_error']==0 for r in records)
if __name__=='__main__':main()
