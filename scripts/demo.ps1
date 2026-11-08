# Hexward demo: shows every command on harmless test files, then a real quick scan.
# Run from the repo root after `cargo build --release`:   & .\scripts\demo.ps1

$ErrorActionPreference = 'Continue'
$hw = Join-Path $PSScriptRoot '..\target\release\hexward.exe'
if (-not (Test-Path $hw)) { Write-Host 'Build first: cargo build --release' -ForegroundColor Red; return }

function Step($title) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGreen
    Write-Host "  $title" -ForegroundColor Green
    Write-Host ('=' * 70) -ForegroundColor DarkGreen
    Start-Sleep -Milliseconds 800
}

Step '1. Version and loaded rules'
& $hw --version
& $hw rules

Step '2. Make a demo folder with harmless test files'
$demo = Join-Path $env:TEMP 'hexward-demo'
Remove-Item $demo -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $demo | Out-Null
Set-Content -Path (Join-Path $demo 'notes.txt') -Value 'A normal text file.' -NoNewline
Set-Content -Path (Join-Path $demo 'marker.bin') -Value 'HEXWARD-HARMLESS-TEST-MARKER-7f3a9c' -NoNewline
Set-Content -Path (Join-Path $demo 'hash-test.bin') -Value 'HEXWARD-HARMLESS-HASH-TEST' -NoNewline
Set-Content -Path (Join-Path $demo 'invoice_2026.pdf.exe') -Value 'not really a program' -NoNewline
Copy-Item "$env:SystemRoot\System32\notepad.exe" (Join-Path $demo 'holiday-photo.jpg')
Get-ChildItem $demo | Format-Table Name, Length -AutoSize

Step '3. Scan the demo folder (report only, nothing changes)'
& $hw scan $demo
Write-Host "exit code: $LASTEXITCODE  (0 = clean, 1 = threats found, 2 = error)" -ForegroundColor DarkGray

Step '4. Scan again with --quarantine (moves confirmed threats only)'
& $hw scan $demo --quarantine
Write-Host ''
Write-Host 'Files left in the demo folder:' -ForegroundColor DarkGray
Get-ChildItem $demo | Format-Table Name, Length -AutoSize

Step '5. What is in quarantine'
& $hw quarantine list

Step '6. Restore everything the demo quarantined'
$items = & $hw quarantine list --json | ConvertFrom-Json
foreach ($i in $items) {
    if ($i.original_path -like "$demo*") { & $hw quarantine restore $i.id }
}
Get-ChildItem $demo | Format-Table Name, Length -AutoSize

Step '7. Programs that start with Windows'
& $hw startup

Step '8. Real quick scan of this PC (report only)'
& $hw scan

Write-Host ''
Write-Host "Demo files are in $demo. Delete them with: Remove-Item $demo -Recurse" -ForegroundColor DarkGray
