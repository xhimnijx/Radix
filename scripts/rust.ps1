# Build and test the Rust proof harness on Windows without MSVC Build Tools
#
# The MSVC toolchain cannot link (no `link.exe`), and the GNU toolchain needs
# `dlltool.exe`, which is not on PATH by default. `rust-mingw` ships a complete
# MinGW set under `...\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained`
# (gcc, ld, dlltool). Putting that directory on PATH makes the GNU toolchain
# self-sufficient - no download and no admin rights required.
#
# Usage (from the repository root):
#   & .\scripts\rust.ps1 test --locked
#   & .\scripts\rust.ps1 test -Directory proof_rust
#   & .\scripts\rust.ps1 test --locked
#   & .\scripts\rust.ps1 test -Directory proof_rust -- --exact depth64_path_opening::tests::proves_and_verifies_private_depth64_path --ignored
#   & .\scripts\rust.ps1 check --locked --all-targets
#
# Verified 2026-11-08: `rust.ps1 test --locked` -> 46 passed, 7 ignored.

[CmdletBinding()]
param(
    # Crate directory relative to the repository root. Defaults to the archived
    # Candidate-A harness; pass `-Directory proof_rust` for the lattice crate.
    [string]$Directory = 'archive\candidate-a\proof_harness',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs
)

$ErrorActionPreference = 'Stop'
if (-not $CargoArgs -or $CargoArgs.Count -eq 0) { $CargoArgs = @('test', '--locked') }

$toolchain = 'stable-x86_64-pc-windows-gnu'
$selfContained = Join-Path $env:USERPROFILE (
    ".rustup\toolchains\$toolchain\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
)

if (-not (Test-Path -LiteralPath (Join-Path $selfContained 'dlltool.exe'))) {
    throw @"
The self-contained MinGW directory was not found:
  $selfContained
Install it with:
  rustup component add rust-mingw --toolchain $toolchain
"@
}

$env:PATH = "$selfContained;$env:PATH"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location (Join-Path $repoRoot $Directory)
try {
    # Cargo writes progress to stderr; under $ErrorActionPreference='Stop' Windows
    # PowerShell promotes that to a terminating NativeCommandError. Use the exit
    # code instead.
    $ErrorActionPreference = 'Continue'
    & cargo "+$toolchain" @CargoArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
