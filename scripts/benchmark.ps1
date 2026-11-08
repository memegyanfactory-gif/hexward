# Head-to-head benchmark: Hexward vs ClamAV vs KicomAV on the same samples.
#
# RUN ONLY INSIDE AN ISOLATED VIRTUAL MACHINE with networking off: -Samples holds live malware.
# See docs/BENCHMARK.md for the full method.
#
#   pwsh scripts/benchmark.ps1 -Samples D:\bench\malware -Clean D:\bench\clean `
#        [-Hexward .\hexward.exe] [-ClamScan "C:\Program Files\ClamAV\clamscan.exe"] `
#        [-KicomAV "C:\kicomav\k2.py"] [-Out results.md]
#
# Detection rate = share of -Samples files reported. False alarms = -Clean files reported.
# Each scanner runs once on each folder; wall-clock time is measured.

param(
    [Parameter(Mandatory = $true)][string]$Samples,
    [Parameter(Mandatory = $true)][string]$Clean,
    [string]$Hexward = "hexward.exe",
    [string]$ClamScan = "",
    [string]$KicomAV = "",
    [string]$Out = "benchmark-results.md"
)

$ErrorActionPreference = "Stop"
$nSamples = (Get-ChildItem $Samples -File -Recurse).Count
$nClean = (Get-ChildItem $Clean -File -Recurse).Count
if ($nSamples -eq 0) { throw "No files in $Samples" }

function Measure-Scanner($name, [scriptblock]$run) {
    $rows = @()
    foreach ($set in @(@{ Label = "malware"; Path = $Samples; Total = $nSamples }, @{ Label = "clean"; Path = $Clean; Total = $nClean })) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $flagged = & $run $set.Path
        $sw.Stop()
        $rows += [pscustomobject]@{ Scanner = $name; Set = $set.Label; Flagged = @($flagged | Sort-Object -Unique).Count; Total = $set.Total; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
    }
    $rows
}

$results = @()

$results += Measure-Scanner "Hexward" {
    param($p)
    & $Hexward scan $p --json --no-cache --max-size-mb 256 2>$null | ConvertFrom-Json |
        ForEach-Object { $_.summary.threats } | ForEach-Object { $_.path }
}

if ($ClamScan -and (Test-Path $ClamScan)) {
    $results += Measure-Scanner "ClamAV" {
        param($p)
        & $ClamScan -r --infected --no-summary $p 2>$null | ForEach-Object { if ($_ -match '^(.*): .* FOUND$') { $Matches[1] } }
    }
}

if ($KicomAV -and (Test-Path $KicomAV)) {
    $results += Measure-Scanner "KicomAV" {
        param($p)
        & python $KicomAV $p -r -I 2>$null | ForEach-Object { if ($_ -match '^(.*?)\s+infected') { $Matches[1] } }
    }
}

$md = @(
    "# Benchmark results",
    "",
    "$(Get-Date -Format 'yyyy-MM-dd') · $nSamples malware samples · $nClean clean files · $([Environment]::OSVersion.VersionString)",
    "",
    "| Scanner | Detected malware | Detection rate | False alarms on clean files | Time (malware) | Time (clean) |",
    "|---|---|---|---|---|---|"
)
foreach ($s in ($results | Group-Object Scanner)) {
    $m = $s.Group | Where-Object Set -eq "malware"
    $c = $s.Group | Where-Object Set -eq "clean"
    $md += "| $($s.Name) | $($m.Flagged) / $($m.Total) | $([math]::Round(100 * $m.Flagged / [math]::Max(1, $m.Total), 1))% | $($c.Flagged) / $($c.Total) | $($m.Seconds) s | $($c.Seconds) s |"
}
$md -join "`n" | Out-File -Encoding utf8 $Out
$md -join "`n" | Write-Host
Write-Host "`nWritten to $Out"
