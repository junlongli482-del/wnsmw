"""Run a research stage sequentially and retain a fresh, stage-checked report."""
from pathlib import Path
import subprocess,json,time,sys,hashlib
ROOT=Path(__file__).resolve().parents[1]
ADB=ROOT/'.work/android-sdk/platform-tools/adb.exe'
def adb(*args):
    return subprocess.run([str(ADB),'-s','emulator-5580',*args],capture_output=True,check=True).stdout
def main():
    stage,label=sys.argv[1:3]
    out=ROOT/'output/camscanner-reverse'/label;out.mkdir(parents=True,exist_ok=True)
    adb('shell','am','force-stop','org.localresearch.scanner')
    adb('shell','rm','-f','/data/user/0/org.localresearch.scanner/files/bitmap-report.json')
    adb('shell','am','start','-n','org.localresearch.scanner/.MainActivity','--es','stage',stage)
    deadline=time.monotonic()+180;report=None
    while time.monotonic()<deadline:
        try:
            report=json.loads(adb('shell','cat','/data/user/0/org.localresearch.scanner/files/bitmap-report.json'))
            if report.get('status')=='failed':raise RuntimeError(report)
            if report.get('status')=='executed':break
        except (subprocess.CalledProcessError,json.JSONDecodeError):pass
        time.sleep(.5)
    else:raise TimeoutError(report)
    if report.get('stage')!=stage:raise ValueError('Stage mismatch')
    (out/(stage+'-report.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
    checks=[]
    for row in report.get('outputs',[]):
        name=row['file']
        if Path(name).name!=name:raise ValueError(name)
        data=adb('exec-out','cat','/data/user/0/org.localresearch.scanner/files/'+name)
        (out/name).write_bytes(data)
        previous=ROOT/'output/camscanner-reverse/model-probe'/name
        checks.append({'file':name,'sha256':hashlib.sha256(data).hexdigest(),'byte_identical_to_previous':data==previous.read_bytes() if previous.exists() else None})
    if checks:(out/'output-check.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
    print(json.dumps({'stage':stage,'status':report['status'],'output_checks':checks,'report':str(out/(stage+'-report.json'))},indent=2))
if __name__=='__main__':main()
