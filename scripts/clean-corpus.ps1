# Downloads a set of popular, signed installers and game launchers from their official sources
# and scans them. Used by the release pipeline's false-alarm gate: one confirmed detection fails it.
#
#   pwsh scripts/clean-corpus.ps1 -Hexward target/release/hexward.exe [-Dir corpus]
#
# Sources are official "latest" links or GitHub release APIs, so the set stays current.
# A download that fails is skipped (and listed), never a reason to fail the gate.

param(
    [Parameter(Mandatory = $true)][string]$Hexward,
    [string]$Dir = "corpus"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Dir | Out-Null

# Direct "always latest" links.
$direct = [ordered]@{
    "chrome-enterprise.msi" = "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi"
    "firefox-setup.exe"     = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US"
    "vscode-user-setup.exe" = "https://update.code.visualstudio.com/latest/win32-x64-user/stable"
    "putty-installer.msi"   = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-installer.msi"
    "steam-setup.exe"       = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    "epic-launcher.msi"     = "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi"
    "discord-setup.exe"     = "https://discord.com/api/download?platform=win"
    "zoom-installer.exe"    = "https://zoom.us/client/latest/ZoomInstallerFull.exe?archType=x64"
}

# GitHub releases: (repo, asset name pattern).
$github = @(
    @("notepad-plus-plus/notepad-plus-plus", "Installer.x64.exe$"),
    @("ip7z/7zip", "-x64.exe$"),
    @("git-for-windows/git", "-64-bit.exe$"),
    @("audacity/audacity", "64bit.exe$"),
    @("pbatard/rufus", "^rufus-[0-9.]+\.exe$"),
    @("obsproject/obs-studio", "Windows-x64-Installer.exe$"),
    @("keepassxreboot/keepassxc", "Win64.msi$"),
    @("PowerShell/PowerShell", "win-x64.msi$")
)

$failed = @()
foreach ($name in $direct.Keys) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $direct[$name] -OutFile (Join-Path $Dir $name) -MaximumRedirection 10
    } catch {
        $failed += $name
    }
}
$headers = @{ "User-Agent" = "hexward-ci" }
if ($env:GH_TOKEN) { $headers["Authorization"] = "Bearer $env:GH_TOKEN" }
foreach ($g in $github) {
    try {
        $rel = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$($g[0])/releases/latest"
        $asset = $rel.assets | Where-Object { $_.name -match $g[1] } | Select-Object -First 1
        if ($asset) {
            Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile (Join-Path $Dir $asset.name)
        } else {
            $failed += $g[0]
        }
    } catch {
        $failed += $g[0]
    }
}

$files = Get-ChildItem $Dir -File
Write-Host "Clean corpus: $($files.Count) installers ($([math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB)) MB). Not downloaded: $($failed -join ', ')"

# Installers are big: raise the size limit so they're actually unpacked and scanned.
& $Hexward scan $Dir --json --no-cache --max-size-mb 1024 > corpus.json
$s = (Get-Content corpus.json -Raw | ConvertFrom-Json).summary
$confirmed = @($s.threats | Where-Object { @($_.detections | Where-Object { $_.source -in @('hash', 'rule', 'eicar') }).Count -gt 0 })
$lines = @("## Clean installers", "", "$($files.Count) installers · $($s.files_scanned) files including unpacked contents · $($confirmed.Count) confirmed hits · $(@($s.threats).Count - $confirmed.Count) suspicious", "")
foreach ($t in @($s.threats)) { $lines += "- ``$($t.detections[0].name)`` · $(Split-Path $t.path -Leaf) $(if ($t.detections[0].inner) { '› ' + $t.detections[0].inner })" }
if ($failed.Count) { $lines += ""; $lines += "Couldn't download: $($failed -join ', ')" }
if ($env:GITHUB_STEP_SUMMARY) { $lines -join "`n" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY } else { $lines -join "`n" | Write-Host }
if ($confirmed.Count -gt 0) {
    Write-Host "::error::$($confirmed.Count) confirmed detections in clean installers."
    exit 1
}
exit 0
