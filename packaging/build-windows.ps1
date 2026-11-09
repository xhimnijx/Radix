# Build the Windows executable.
#
# PyInstaller cannot cross-compile: run this on Windows for the .exe, on macOS for
# the macOS binary, on Linux for the ELF binary. The CI workflow does all three on
# their native runners.
#
# Usage (from the repository root):
#   & .\packaging\build-windows.ps1
#   & .\packaging\build-windows.ps1 -Clean

[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($Clean) {
        Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
    }
    # Native tools write progress to stderr; under ErrorActionPreference=Stop that
    # becomes a terminating error, so check the exit code instead.
    $ErrorActionPreference = "Continue"
    & $Python -m pip install --quiet pyinstaller segno
    if ($LASTEXITCODE -ne 0) { throw "pip failed with exit code $LASTEXITCODE" }
    & $Python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging/radix-testnet.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }
    $ErrorActionPreference = "Stop"

    $artifact = Get-ChildItem dist | Where-Object { $_.Name -like "RadixTestnet*" } | Select-Object -First 1
    if (-not $artifact) { throw "no artefact produced in dist/" }
    $size = [math]::Round($artifact.Length / 1MB, 1)
    Write-Host ""
    Write-Host "built: $($artifact.FullName)  ($size MB)"
    Write-Host "run it with: $($artifact.FullName)"
} finally {
    Pop-Location
}
