# Benchmarking Hexward

Hexward's own numbers (false alarms on clean software) are measured on every release by the
pipeline's gates. Detection of real malware has to be measured somewhere live malware can't
hurt anyone. This page is the method; results are published here when a run is done.

## Status

- **False alarms (every release):** System32, Program Files and about 16 popular installers and game
  launchers fetched fresh from their official sources must produce zero confirmed detections. See the
  "False-alarm gate" and "Clean installers" sections of each release run's summary.
- **Detection vs ClamAV and KicomAV:** harness ready (`scripts/benchmark.ps1`); first published run pending.

## Method

1. **Isolated VM.** A Windows 11 virtual machine with networking switched off after setup, a snapshot
   taken before the samples go in, and the snapshot restored afterwards. Never on a real PC.
2. **Samples.** One day of MalwareBazaar uploads (the daily zip, password `infected`), unpacked inside
   the VM. Duplicates and non-Windows files removed, so every sample is something a Windows user could
   actually receive.
3. **Clean set.** The same installers as the release gate (`scripts/clean-corpus.ps1` downloads them),
   plus `C:\Windows\System32`.
4. **Scanners, same day, same rules age:**
   - Hexward with `hexward update` run just before (core pack from the rule channel).
   - ClamAV with `freshclam` run just before.
   - KicomAV from its GitHub repository, latest commit.
5. **Run:**

   ```powershell
   pwsh scripts/benchmark.ps1 -Samples D:\bench\malware -Clean D:\bench\clean `
        -Hexward .\hexward.exe -ClamScan "C:\Program Files\ClamAV\clamscan.exe" -KicomAV C:\kicomav\k2.py
   ```

6. **Report** detection rate, false alarms and time for each scanner, the sample date and the rule
   versions. Suspicious-only Hexward findings are counted as detections in the table and listed
   separately, so nobody has to take a blended number on trust.

## Why this way

- A single day of fresh samples is closer to what people meet than an old curated set every scanner
  has already seen.
- Running everything on the same day removes rule-freshness differences.
- Publishing the script means anyone can repeat the run and check the numbers.
