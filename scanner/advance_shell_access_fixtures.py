"""Capture exact unknown access paths with the standalone Android read-only probe.

Only supports raw faccessat(F_OK) stopping points. Does not invent results,
change target instructions, or alter the counterfactual profile's scope.
"""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DIR=ROOT/'.work/camscanner/shell-unpacked/x86'
args=['--clone-model','--proc-snapshot','--jni-model','--al-model','--art-file-model','--factory-stack-model','--pthread-model','--nonemulator-profile','--al-instructions=60000000']
records=[]
for iteration in range(8):
    evidence=json.loads((ROOT/'output/camscanner-reverse/shell-n-al-nonemulator-emulation-evidence.json').read_text())[1]
    stop=evidence['al_model']['calls'][-1]
    if stop.get('eax')!='0x133' or stop.get('registers',{}).get('edx')!='0x0' or not stop.get('unsupported'):break
    path=stop['path']
    result=subprocess.run([str(ROOT/'.work/android-sdk/platform-tools/adb.exe'),'-s','emulator-5580','exec-out','/data/local/tmp/probe-shell-access',path],capture_output=True,check=True)
    text=result.stdout.decode().strip();actual,ret,err=text.split('\t')
    if actual!=path:raise RuntimeError('Probe output path mismatch')
    fixture=json.loads((DIR/'android-access.json').read_text());fixture['results'][path]={'mode':0,'result':int(ret),'errno':int(err)};(DIR/'android-access.json').write_text(json.dumps(fixture,indent=2))
    records.append({'path':path,'actual_probe_stdout':text,'result':int(ret),'errno':int(err),'source':'Standalone Android i686 probe on shell UID; no original application UID claim'})
    print('Captured',text,flush=True)
    subprocess.run([sys.executable,str(ROOT/'scanner/emulate_shell_constructors.py'),*args],check=True,capture_output=True)
(ROOT/'output/camscanner-reverse/shell-access-fixture-acquisition.json').write_text(json.dumps(records,indent=2))
print('Captured paths',len(records),flush=True)
