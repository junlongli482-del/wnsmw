$ErrorActionPreference = 'Stop'
$reaNode = 'C:\Users\LJL\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
$reaEntry = Join-Path $PSScriptRoot '.work\rea-runtime\node_modules\rea-agents\scripts\rea.mjs'
$env:REA_JADX_MCP_JAR = Join-Path $PSScriptRoot '.work\rea-tools\jadx-verified.jar'
$env:JAVA_HOME = 'C:\Program Files\Amazon Corretto\jdk21.0.12_12'
$env:REA_JADX_HEAP_MIB = '3072'
$env:REA_JADX_ACTIVE_PROCESSOR_COUNT = '4'
$env:GHIDRA_INSTALL_DIR = Join-Path $PSScriptRoot '.work\rea-tools\ghidra_12.1.4_PUBLIC'
$env:REA_ADB_PATH = Join-Path $PSScriptRoot '.work\android-sdk\platform-tools\adb.exe'
& $reaNode $reaEntry @args
exit $LASTEXITCODE
