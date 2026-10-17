$ErrorActionPreference = 'Stop'
& 'C:\Users\LJL\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' (Join-Path $PSScriptRoot 'scanner\scan.py') @args
exit $LASTEXITCODE
