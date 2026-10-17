param([string]$BindHost = '127.0.0.1', [int]$Port = 18766)
$ErrorActionPreference='Stop'
$scannerRoot=Split-Path $PSScriptRoot -Parent
$scannerAdb=Join-Path $scannerRoot '.work/android-sdk/platform-tools/adb.exe'
$scannerNode='C:/Users/LJL/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
$scannerApk=Join-Path $scannerRoot '.work/android-research-build/scanner-native-research.apk'
if(!(Test-Path -LiteralPath $scannerApk)){throw 'Research APK is missing. Run scanner/build_android_research.py first.'}
& $scannerAdb -s emulator-5580 get-state
if($LASTEXITCODE -ne 0){throw 'Start the existing camscanner-re emulator first.'}
& $scannerAdb -s emulator-5580 install -r $scannerApk
if($LASTEXITCODE -ne 0){throw 'Cannot install research APK.'}
& $scannerAdb -s emulator-5580 shell am force-stop org.localresearch.scanner
& $scannerAdb -s emulator-5580 shell am start -n org.localresearch.scanner/.MainActivity --es stage http-server
if($LASTEXITCODE -ne 0){throw 'Cannot start original JNI service.'}
& $scannerAdb -s emulator-5580 forward tcp:18765 tcp:18765
$scannerReady=$false
for($attempt=0;$attempt -lt 30;$attempt++) {
    try {$result=Invoke-RestMethod -Uri 'http://127.0.0.1:18765/health' -TimeoutSec 2;if($result.status -eq 'ready'){$scannerReady=$true;break}}catch{}
    Start-Sleep -Milliseconds 500
}
if(!$scannerReady){throw 'Original JNI service did not become ready.'}
$env:SCANNER_BIND_HOST=$BindHost
$env:SCANNER_GATEWAY_PORT=[string]$Port
& $scannerNode (Join-Path $PSScriptRoot 'native_gateway.mjs')
