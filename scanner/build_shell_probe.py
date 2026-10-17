"""Separate x86 APK to observe original shell JNI loading in real Android ART."""
from pathlib import Path
import subprocess,zipfile,hashlib,json,argparse
ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--target-sdk',type=int,choices=(25,30),default=30)
    options=parser.parse_args();suffix='' if options.target_sdk==30 else '-target25'
    src=ROOT/'scanner/shell-probe';build=ROOT/'.work/shell-probe-build';build.mkdir(exist_ok=True)
    sdk=Path('C:/Users/LJL/.cache/camscanner-re-sdk')
    if not sdk.exists():sdk=ROOT/'.work/android-sdk'
    bt=sdk/'build-tools/android-15';android=sdk/'platforms/android-11/android.jar'
    jdk=Path('C:/Program Files/Amazon Corretto/jdk21.0.12_12/bin')
    classes=build/'classes';classes.mkdir(exist_ok=True);dex=build/'dex';dex.mkdir(exist_ok=True)
    def run(args):subprocess.run(list(map(str,args)),cwd=ROOT,check=True)
    run([jdk/'javac.exe','--release','8','-classpath',android,'-d',classes,*src.rglob('*.java')])
    run([jdk/'java.exe','-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','21','--lib',android,'--output',dex,*classes.rglob('*.class')])
    manifest=build/('AndroidManifest'+suffix+'.xml')
    manifest.write_text((src/'AndroidManifest.xml').read_text().replace('android:targetSdkVersion="30"',f'android:targetSdkVersion="{options.target_sdk}"'),encoding='utf-8')
    unsigned=build/('unsigned'+suffix+'.apk');run([bt/'aapt2.exe','link','-I',android,'--manifest',manifest,'-o',unsigned])
    provenance=[]
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED,strict_timestamps=False) as archive:
        archive.write(dex/'classes.dex','classes.dex')
        for name in ('libexec.so','libexecmain.so'):
            path=ROOT/'.work/camscanner/extracted/assets/ijm_lib/x86'/name
            archive.write(path,'lib/x86/'+name)
            provenance.append({'name':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    key=ROOT/'.work/android-research-build/research-debug.keystore'
    assert key.exists()
    aligned=build/('aligned'+suffix+'.apk');run([bt/'zipalign.exe','-f','4',unsigned,aligned])
    apk=build/('shell-probe'+suffix+'.apk')
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','verify',apk])
    report={'apk':str(apk.relative_to(ROOT)),'sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'original_libraries':provenance,'target_sdk':options.target_sdk,
      'scope':'Separate x86-only research package. Original shell libraries unchanged. Java N declarations are a fixture. Different package/ART context and no protected app initialization or original scanner UI.'}
    (ROOT/('output/camscanner-reverse/shell-probe'+suffix+'-build-evidence.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
