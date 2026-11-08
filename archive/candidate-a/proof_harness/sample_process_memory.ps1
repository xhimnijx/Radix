[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$ProcessId,

    [ValidateRange(25, 10000)]
    [int]$IntervalMilliseconds = 250,

    [ValidateRange(1, 86400)]
    [int]$MaxDurationSeconds = 1800,

    [Parameter(Mandatory = $true)]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$invariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
$outputPath = [System.IO.Path]::GetFullPath($CsvPath)
if (Test-Path -LiteralPath $outputPath) {
    throw "Refusing to overwrite existing sample file: $outputPath"
}
$outputDirectory = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw "Output directory does not exist: $outputDirectory"
}

$initialProcess = Get-Process -Id $ProcessId -ErrorAction Stop
$targetStartTicks = $initialProcess.StartTime.ToUniversalTime().Ticks
$initialProcess.Dispose()

$writer = [System.IO.StreamWriter]::new(
    $outputPath,
    $false,
    [System.Text.UTF8Encoding]::new($false)
)
$writer.AutoFlush = $true
$writer.WriteLine('timestamp_utc,elapsed_seconds,process_id,working_set_bytes,private_bytes')

$started = [DateTimeOffset]::UtcNow
$sampleCount = 0
$peakWorkingSetBytes = [long]0
$peakPrivateBytes = [long]0
$stopReason = 'duration-limit'

try {
    while ($true) {
        $now = [DateTimeOffset]::UtcNow
        $elapsedSeconds = ($now - $started).TotalSeconds
        if ($elapsedSeconds -ge $MaxDurationSeconds) {
            $stopReason = 'duration-limit'
            break
        }

        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $process) {
            $stopReason = 'process-exited'
            break
        }

        try {
            if ($process.StartTime.ToUniversalTime().Ticks -ne $targetStartTicks) {
                $stopReason = 'pid-reused-or-process-replaced'
                break
            }
            $workingSetBytes = [long]$process.WorkingSet64
            $privateBytes = [long]$process.PrivateMemorySize64
        }
        finally {
            $process.Dispose()
        }

        $elapsedText = $elapsedSeconds.ToString('F3', $invariantCulture)
        $timestamp = $now.ToString('o', $invariantCulture)
        $row = '"{0}",{1},{2},{3},{4}' -f $timestamp, $elapsedText, $ProcessId, $workingSetBytes, $privateBytes
        $writer.WriteLine($row)
        $sampleCount++
        if ($workingSetBytes -gt $peakWorkingSetBytes) {
            $peakWorkingSetBytes = $workingSetBytes
        }
        if ($privateBytes -gt $peakPrivateBytes) {
            $peakPrivateBytes = $privateBytes
        }

        Start-Sleep -Milliseconds $IntervalMilliseconds
    }
}
finally {
    $writer.Dispose()
}

[pscustomobject]@{
    ProcessId = $ProcessId
    Samples = $sampleCount
    StopReason = $stopReason
    PeakWorkingSetMiB = [math]::Round($peakWorkingSetBytes / 1MB, 1)
    PeakPrivateMiB = [math]::Round($peakPrivateBytes / 1MB, 1)
    CsvPath = $outputPath
}
