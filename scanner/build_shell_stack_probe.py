"""Build a minimal own-JNI AppComponentFactory stack collector, no original code."""
from pathlib import Path
import subprocess,zipfile,json,hashlib
ROOT=Path(__file__).resolve().parents[1]
def main():
    src=ROOT/'scanner/stack-probe';build=ROOT/'.work/stack-probe-build';build.mkdir(exist_ok=True)
    sdk=Path('C:/Users/LJL/.cache/camscanner-re-sdk');bt=sdk/'build-tools/android-15'
    android=sdk/'platforms/android-11/android.jar';jdk=Path('C:/Program Files/Amazon Corretto/jdk21.0.12_12/bin')
    ndk=ROOT/'.work/rea-tools/android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64'
    def run(args):subprocess.run([str(x) for x in args],check=True,cwd=ROOT)
    classes=build/'classes';classes.mkdir(exist_ok=True);dex=build/'dex';dex.mkdir(exist_ok=True)
    lib=build/'libstackprobe.so'
    run([ndk/'bin/clang.exe','--target=i686-linux-android29','-shared','-fPIC','-O2','-Wl,--no-undefined',src/'stack_probe.c','-ldl','-o',lib])
    run([jdk/'javac.exe','--release','8','-cp',android,'-d',classes,*src.glob('*.java')])
    run([jdk/'java.exe','-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','29','--lib',android,'--output',dex,*classes.rglob('*.class')])
    unsigned=build/'unsigned.apk';run([bt/'aapt2.exe','link','-I',android,'--manifest',src/'AndroidManifest.xml','-o',unsigned])
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex/'classes.dex','classes.dex');archive.write(lib,'lib/x86/libstackprobe.so')
    aligned=build/'aligned.apk';run([bt/'zipalign.exe','-f','4',unsigned,aligned])
    apk=build/'stack-probe.apk';key=ROOT/'.work/android-research-build/research-debug.keystore'
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([jdk/'java.exe','-jar',bt/'lib/apksigner.jar','verify',apk])
    evidence={'apk':str(apk.relative_to(ROOT)),'sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),
      'scope':'Separate research package, own JNI collector only. Observes actual AppComponentFactory/ART native-to-Java stack; contains no original scanner/shell code or return hooks.'}
    (ROOT/'output/camscanner-reverse/shell-stack-probe-build-evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    print(json.dumps(evidence))
if __name__=='__main__':main()
