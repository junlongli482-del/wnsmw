"""Build a local-only Android harness around original APK JNI libraries."""
from pathlib import Path
import subprocess,sys,zipfile,hashlib,json,shutil
sys.path.insert(0,str(Path(__file__).resolve().parent))
from probe_recovered_models import ROOT,load_image
import cv2,numpy as np
from elftools.elf.elffile import ELFFile

def main():
    source=ROOT/'scanner/android-research';build=ROOT/'.work/android-research-build';build.mkdir(parents=True,exist_ok=True)
    ascii_sdk=Path('C:/Users/LJL/.cache/camscanner-re-sdk')
    sdk=ascii_sdk if ascii_sdk.exists() else ROOT/'.work/android-sdk'
    bt=sdk/'build-tools/android-15';android=sdk/'platforms/android-11/android.jar'
    jdk=Path('C:/Program Files/Amazon Corretto/jdk21.0.12_12/bin')
    classes=build/'classes';classes.mkdir(exist_ok=True)
    dex=build/'dex';dex.mkdir(exist_ok=True)
    def run(args):subprocess.run([str(a) for a in args],check=True,cwd=ROOT)
    ndk=ROOT/'.work/rea-tools/android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64'
    bridge=build/'libresearch_status.so'
    run([ndk/'bin/clang.exe','--target=armv7a-linux-androideabi21','-march=armv7-a','-mfloat-abi=softfp','-fPIC','-shared','-O2',
         '-Wl,-soname,libresearch_status.so','-Wl,--no-undefined','-Wl,-z,max-page-size=16384',
         source/'native/status_bridge.c','-L',ROOT/'.work/camscanner/extracted/lib/armeabi','-lpagescanner','-lmagicenhancer','-lopencv','-lm','-o',bridge])
    run([jdk/'javac.exe','--release','8','-classpath',android,'-d',classes,*source.rglob('*.java')])
    run([jdk/'java.exe','-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','21','--lib',android,'--output',dex,*classes.rglob('*.class')])
    unsigned=build/'research-unsigned.apk'
    run([bt/'aapt2.exe','link','-I',android,'--manifest',source/'AndroidManifest.xml','-o',unsigned])
    provenance=[]
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:
        z.write(dex/'classes.dex','classes.dex')
        z.write(bridge,'lib/armeabi/libresearch_status.so')
        libroot=ROOT/'.work/camscanner/extracted/lib/armeabi'
        pending=['libpagescanner.so','libMNN.so','libopencv.so','libmagicenhancer.so'];libraries=[]
        while pending:
            name=pending.pop(0)
            if name in libraries:continue
            libraries.append(name)
            with (libroot/name).open('rb') as stream:
                dynamic=ELFFile(stream).get_section_by_name('.dynamic')
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag=='DT_NEEDED' and (libroot/tag.needed).exists():pending.append(tag.needed)
        for name in libraries:
            p=ROOT/'.work/camscanner/extracted/lib/armeabi'/name
            z.write(p,'lib/armeabi/'+name);provenance.append({'name':name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
        for stem in ['photo-1','photo-2']:
            z.write(ROOT/f'scanner/samples/{stem}.jpg','assets/'+stem+'.jpg')
            crop=ROOT/f'output/camscanner-reverse/model-probe/{stem}-native-geometry-crop.png'
            z.write(crop,'assets/'+stem+'-crop.png')
            bgr=cv2.resize(load_image(ROOT/f'scanner/samples/{stem}.jpg'),(480,360))
            raw=cv2.cvtColor(bgr,cv2.COLOR_BGR2YUV_I420).ravel();size=480*360
            nv21=np.concatenate([raw[:size],np.stack([raw[size+size//4:],raw[size:size+size//4]],axis=1).ravel()])
            z.writestr('assets/'+stem+'.nv21',nv21.tobytes())
            (build/(stem+'.nv21')).write_bytes(nv21.tobytes())
    key=build/'research-debug.keystore'
    if not key.exists():
        run([jdk/'keytool.exe','-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','research','-dname','CN=Local Research','-keyalg','RSA','-keysize','2048','-validity','3650'])
    aligned=build/'research-aligned.apk';run([bt/'zipalign.exe','-f','4',unsigned,aligned])
    apk=build/'scanner-native-research.apk'
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','verify',apk])
    evidence={'apk':str(apk),'apk_sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'original_libraries':provenance,
              'research_status_bridge':{'sha256':hashlib.sha256(bridge.read_bytes()).hexdigest(),'source':str(source/'native/status_bridge.c'),'role':'Calls original documentCrop, document_radar, get_warp_mat, transformCut, dewarp_process, scan and sharpEnhance with original contexts. Exposes original intermediate images, states and scores. BGR transport only; no hooks, injected tensors, confidence or return replacement.'},
              'jni_descriptors_evidence':'output/camscanner-reverse/restored-PageScanner.java.txt; restored-MagicEnhancer.java.txt; restored-business-dex/restoration-evidence.json',
              'scope':'Local research harness; original libraries unmodified. Used JNI descriptors verified against SHA-1-matched restored DEX. Original Java UI is not included; parameter choices still require per-mode attribution. Not an application equivalence claim.'}
    (ROOT/'output/camscanner-reverse/android-research-build-evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    print(json.dumps(evidence,indent=2))
if __name__=='__main__':main()
