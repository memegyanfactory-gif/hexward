# Hexward self-test

Harmless samples of each kind of threat Hexward should catch, in the spirit of AMTSO's
[Security Features Check](https://www.amtso.org/security-features-check/). Built and run by
[scripts/selftest.ps1](../scripts/selftest.ps1); the release pipeline runs it on every release.

Hexward 0.3.0 · 2026-11-08 · **10 passed, 0 failed, 2 blocked by another antivirus first**

| Test | File | Expected | Result |
|---|---|---|---|
| Signature rule on a plain file | `marker.bin` | Test/Any.HexwardMarker | PASS |
| Inside a ZIP | `archive.zip` | Test/Any.HexwardMarker | PASS |
| Inside a ZIP inside a ZIP | `nested.zip` | Test/Any.HexwardMarker | PASS |
| Inside GZIP | `marker.bin.gz` | Test/Any.HexwardMarker | PASS |
| Double extension | `invoice.pdf.exe` | DoubleExt | PASS |
| Program disguised as a photo | `holiday-photo.jpg` | Masquerade | PASS |
| EICAR test file | `eicar.com` | EICAR | blocked by another antivirus first |
| Script that downloads and runs code | `update.ps1` | Script.DownloadExec | PASS |
| Obfuscated download-and-run (character codes) | `hidden.ps1` | Script.DownloadExec | PASS |
| ClickFix page | `verify.html` | Html.ClickFix | blocked by another antivirus first |
| Shortcut dropper | `document.pdf.lnk` | Lnk | PASS |
| Clean Windows program (must not be flagged) | `notepad.exe` | nothing | PASS (clean) |
