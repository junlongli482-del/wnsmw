"""Collect research JNI results without shell redirection of binary PNGs."""
from pathlib import Path
import argparse,json,subprocess,time,hashlib

ROOT=Path(__file__).resolve().parents[1]
ADB=ROOT/'.work/android-sdk/platform-tools/adb.exe'
OUT=ROOT/'output/camscanner-reverse'

def adb(*args,check=True):
    return subprocess.run([str(ADB),'-s','emulator-5580',*args],check=check,capture_output=True).stdout

def main():
    parser=argparse.ArgumentParser();parser.add_argument('stage');parser.add_argument('--mode',type=int,default=0)
    parser.add_argument('--launch',action='store_true');args=parser.parse_args()
    suffix=args.stage+(f'-mode{args.mode}' if args.stage=='enhance' else '')
    if args.launch:
        adb('shell','am','force-stop','org.localresearch.scanner')
        adb('shell','run-as','org.localresearch.scanner','rm','-f','files/bitmap-report.json')
        adb('shell','am','start','-n','org.localresearch.scanner/.MainActivity','--es','stage',args.stage,'--ei','mode',str(args.mode))
    started=time.monotonic();deadline=started+90;report={}
    while time.monotonic()<deadline:
        raw=adb('exec-out','run-as','org.localresearch.scanner','cat','files/bitmap-report.json',check=False)
        try:report=json.loads(raw)
        except ValueError:
            if time.monotonic()-started>5 and not adb('shell','pidof','org.localresearch.scanner',check=False).strip():
                report={'stage':args.stage,'status':'failed','reason':'app exited before writing report'}
                break
            time.sleep(1);continue
        if report.get('stage')==args.stage and report.get('status') in ('executed','failed'):break
        if not adb('shell','pidof','org.localresearch.scanner',check=False).strip():break
        time.sleep(1)
    installed=adb('shell','pm','path','org.localresearch.scanner').decode().strip().removeprefix('package:')
    report['harness_apk_sha256']=adb('shell','sha256sum',installed).decode().split()[0]
    (OUT/f'android-{suffix}-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (OUT/f'android-{suffix}-logcat.txt').write_bytes(adb('logcat','-d','-t','500'))
    for row in report.get('outputs',[]):
        data=adb('exec-out','run-as','org.localresearch.scanner','cat','files/'+row['file'])
        assert data.startswith(b'\x89PNG\r\n\x1a\n'),row
        (OUT/'model-probe'/row['file']).write_bytes(data)
        row['sha256']=hashlib.sha256(data).hexdigest()
    for row in report.get('records',[]):
        if 'field_file' not in row:continue
        data=adb('exec-out','run-as','org.localresearch.scanner','cat','files/'+row['field_file'])
        assert len(data)==row['field_width']*row['field_height']*2*4,row
        (OUT/'model-probe'/row['field_file']).write_bytes(data)
        row['field_sha256']=hashlib.sha256(data).hexdigest()
    (OUT/f'android-{suffix}-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    if report.get('status')!='executed':raise SystemExit('JNI stage did not complete; inspect retained report and logcat')

if __name__=='__main__':main()
