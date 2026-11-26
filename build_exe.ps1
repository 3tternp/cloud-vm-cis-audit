# Build dist\CloudVMAuditor.exe in an isolated virtual environment (keeps your global Python untouched).
#   powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path .venv-build)) { python -m venv .venv-build }
$py = ".\.venv-build\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements.txt pyinstaller
& $py -m PyInstaller cloud_audit.spec --noconfirm --clean
if (Test-Path dist\CloudVMAuditor.exe) {
    $mb = [math]::Round((Get-Item dist\CloudVMAuditor.exe).Length / 1MB, 1)
    Write-Host "Built dist\CloudVMAuditor.exe ($mb MB)"
} else { throw "Build failed: dist\CloudVMAuditor.exe not found" }
