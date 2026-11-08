# Launch one Rust test binary and report elapsed time and peak working set.
#
# Usage (from the repository root):
#   pwsh -File experiments/measure_rust_test.ps1 `
#     -Binary proof_harness/target/release/deps/radix_proof_harness-<hash>.exe `
#     -TestName depth64_path_opening::tests::proves_and_verifies_private_depth64_path
#
# Why: the local toolchain has no linker, so we cannot build a fresh test binary.
# A prebuilt one is still a valid measurement of the prover on this machine, as
# long as the report records which build and which source layout it came from.
#
# The script polls PeakWorkingSet64 (an OS high-water mark) while the process
# runs, which is more reliable than sampling instantaneous working set between
# allocations.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$TestName,
    [int]$IntervalMilliseconds = 100,
    [int]$TimeoutSeconds = 900,
    [switch]$IncludeIgnored
)

$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
    throw "test binary not found: $binaryPath"
}

$testArgs = @('--exact', $TestName, '--nocapture')
if ($IncludeIgnored) { $testArgs = @('--ignored') + $testArgs }

$stamp = [guid]::NewGuid().ToString('N')
$stdout = Join-Path $env:TEMP "radix-measure-$stamp.out.log"
$stderr = Join-Path $env:TEMP "radix-measure-$stamp.err.log"

$timer = [System.Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $binaryPath `
    -ArgumentList $testArgs `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr

$peak = [int64]0
$timedOut = $false
while (-not $process.HasExited) {
    if ($timer.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
        $timedOut = $true
        try { $process.Kill() } catch { }
        break
    }
    try {
        $process.Refresh()
        $sample = $process.PeakWorkingSet64
        if ($sample -gt $peak) { $peak = $sample }
    } catch { }
    Start-Sleep -Milliseconds $IntervalMilliseconds
}
$timer.Stop()
$process.WaitForExit()
$exitCode = $process.ExitCode

Write-Output "binary      : $binaryPath"
Write-Output "test        : $TestName"
Write-Output "exit code   : $exitCode$(if ($timedOut) { ' (TIMED OUT)' } else { '' })"
Write-Output ("elapsed     : {0:N2} s" -f $timer.Elapsed.TotalSeconds)
Write-Output ("peak WS     : {0:N0} bytes ({1:N2} GiB)" -f $peak, ($peak / 1GB))
Write-Output "stdout log  : $stdout"
Write-Output "stderr log  : $stderr"
if (Test-Path -LiteralPath $stdout) {
    $tail = Get-Content -LiteralPath $stdout -Tail 6
    if ($tail) { Write-Output '--- stdout tail ---'; $tail | ForEach-Object { Write-Output $_ } }
}
if ($exitCode -ne 0) { exit $exitCode }
