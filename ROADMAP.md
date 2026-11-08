# Hexward roadmap

Goal: the best antivirus and anti-malware product available. It should match the leaders on protection,
beat them on false alarms, honesty and privacy, and protect developers and AI agents, which nobody else does.
The reasoning and sources behind this order are in [docs/STRATEGY.md](docs/STRATEGY.md).
Zero-cost rule: the founder pays no one (see STRATEGY §0).

Every item is a checkbox: `[x]` done, `[~]` in progress, `[ ]` not started. `scripts/progress.js` turns this file into the progress page, so ticking a box
here is what updates the page.

---

## Phase 1 · Scanner you can trust

- [x] Rust engine: SHA-256 hash lists, YARA-X rules, EICAR, file-name tricks, disguised programs
- [x] YARA Forge rule packs (core 5,100+ / extended 10,800+), MalwareBazaar hashes with an abuse.ch key
- [x] False-alarm guards: signed software never auto-quarantined, disabled-rule list, hunting rules = suspicious
- [x] Encrypted, reversible quarantine; Delete only on request; Allow list by SHA-256
- [x] Desktop app (Slint): one-piece window, pixel animation, tray, notifications, light and dark themes
- [x] Quick, System, Full and Custom scans (pick any drives and folders)
- [x] `hexward` command line with JSON output
- [x] Signed self-update from GitHub Releases (Ed25519, version-bound signatures)
- [x] Release pipeline: tests, lints, signing, publishing; actions pinned to commit SHAs
- [x] README, credits, GPL-3.0 licence, brand assets, research strategy

## Phase 1.5 · Look inside everything

- [x] ZIP and ZIP-based formats (Office, JAR, APK, MSIX), 7z, GZIP, TAR, nested up to 3 levels
- [x] ISO 9660 disk images (own reader)
- [x] Hard limits: depth, entries, bytes, compression ratio; zip-bomb detection
- [x] Password-protected archive hiding a program; small disk image hiding a program
- [x] Shortcut (.lnk) analysis per MS-SHLLINK: LOLBin droppers, hidden arguments, oversized payloads
- [x] Office macros (own MS-OVBA decompressor) and files embedded in documents
- [x] Scripts: PowerShell, batch, JS, VBS, HTA download-and-run, with base64 -enc decoding
- [x] Web: HTML/SVG smuggling, SVG phishing redirects, ClickFix pages, .url WebDAV tricks
- [x] Scan cache tied to the rule-set fingerprint
- [x] False-alarm gate in the release pipeline (System32 + Program Files with the real rules)
- [ ] RTF, PDF JavaScript, OneNote attachments
- [ ] RAR, CAB, VHD/VHDX, IMG/UDF
- [ ] MSI, MSIX manifests, NSIS and Inno Setup installers, UPX, PyInstaller
- [ ] Deeper script de-obfuscation (string building, char-code arrays, nested encodings)
- [ ] Signed, staged rule packs: canary → 10% → 100%, rollback, kill switch
- [ ] Bigger clean corpus for the gate: NSRL Modern sets, top winget installers, popular games
- [ ] Head-to-head benchmark against KicomAV and ClamAV in a VM, results published

## Phase 2 · Real-time protection (user mode)

- [x] File shield: Downloads, Desktop and Startup folders, scanned as files finish writing
- [x] Process shield: every program scanned as it starts
- [x] Auto-quarantine of confirmed threats (process stopped first); suspicious finds wait for the user
- [x] ClickFix shield: scores copied commands, replaces clear-cut lures on the clipboard
- [x] Run-dialog (Win+R) history check for past ClickFix commands
- [x] Stealer shield: flags non-owners opening browser, Discord, Telegram and wallet secrets (Restart Manager)
- [ ] Background service so shields run without the app open
- [ ] AMSI provider: PowerShell, VBScript, JScript and macros checked as they run
- [ ] Download watcher with Mark-of-the-Web; copy it onto files extracted from archives
- [ ] Suspicious process chains (browser/Office starting mshta, wscript, powershell -enc, regsvr32 /i:http)
- [ ] Vulnerable-driver blocklist (Microsoft list + LOLDrivers); alert on new kernel drivers
- [ ] Quiet mode for games; low-priority scanning; performance budget (AV-Comparatives impact ≤ 10)

## Phase 2.5 · PC care (startup, tasks, cleanup)

Startup manager
- [x] List and scan everything that starts with Windows (Run keys, Startup folders, tasks, services, Winlogon)
- [x] Switch entries off and back on with undo (Run keys, Startup folders)
- [x] Every entry with publisher, signature status, size and icon, sorted and searchable
- [x] Scheduled tasks and services on/off (asks for admin only when needed; Windows' own tasks and services are never offered)

Task manager
- [x] Processes grouped: Windows (system), Apps (with a window), Background; SYSTEM services resolved through the Service Control Manager
- [x] Windows and security processes are protected: they can't be ended from Hexward
- [x] End task (with a confirm step), scan with Hexward, open file location, live CPU and memory, program icons and publishers
- [x] Unsigned programs running from Temp or Downloads highlighted

Cleaner
- [x] Detect installed browsers (Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi, Yandex) and show their own icons
- [x] Tick boxes per browser: cache, history and download list, cookies (cache ticked by default; history and cookies opt-in; remembered)
- [x] Windows: temp files (older than a day), recycle bin, thumbnail cache, crash dumps and error reports, shader caches
- [x] Shows how much space each item frees before anything is deleted; skips files in use
- [x] Skips an open browser, or closes it politely on request (no force); every clean logged in History

## Phase 3 · Developer, supply-chain and AI-agent protection (our edge)

- [x] `hexward audit <folder or git URL>` and an "Audit a project" screen (repositories cloned with hooks, submodules, LFS and fsmonitor off)
- [x] Install-time code: npm pre/postinstall (project and installed packages), setup.py/pyproject, Cargo build.rs, binding.gyp, git hooks, git config, submodules
- [x] Known-malicious versions (OSV `MAL-*`), names missing from npm/PyPI (slopsquatting), packages from git or URLs, dependency confusion
- [ ] Release anomalies: sudden version jumps, 10× size growth, releases without a git tag
- [x] Agent and IDE configs: `.claude/settings.json` hooks, `.vscode/tasks.json` folder-open tasks, MCP configs
- [x] Hidden text for AI agents: Unicode tags, zero-width and bidi characters, prompt injection in docs
- [x] GitHub Actions: tags instead of SHAs, `pull_request_target` misuse, broad permissions
- [x] Leaked secrets in files and git history
- [x] Hexward Guard: checks agent commands before they run; MCP servers pinned by hash; user approves
- [x] Extension inventory: VS Code, Cursor, Open VSX and browser extensions, with version diffs

## Phase 4 · Smarter detection

- [ ] Static machine learning on Windows programs (EMBER2024 models) as one signal, never alone
- [ ] Memory scanning of running processes with YARA
- [ ] Ransomware shield: canary files, rename/entropy bursts, shadow-copy deletion; file rollback
- [ ] Unpacking and emulation for common packers

## Phase 5 · Certification (free route)

- [~] Our own update signing (Ed25519) and signed GitHub releases (first release building on GitHub)
- [ ] Free Authenticode signing through the SignPath Foundation (open-source program)
- [ ] EULA, privacy policy, published criteria for unwanted software
- [ ] Internal AMTSO-style tests published
- [ ] Free lab test series: AVLab, AV-Comparatives main series, SE Labs

## Phase 6 · Cloud intelligence (opt-in) and the website

- [x] hexward.onurilabs.com product page on the Onuri Labs site
- [ ] Hash-prefix reputation lookups; certificate and signer reputation; community allow list
- [ ] Separate opt-in for detection reports and sample upload; published retention policy
- [ ] Dashboard: detections over time, false-alarm reports, supply-chain findings; database feeding rule packs
- [ ] Yearly transparency report

---

## False-alarm policy (the GTA Vice City rule)

Old games and tools (no-CD fixes, packers, trainers) are where other antivirus products have deleted working files.
Hexward never deletes on its own:
- Only exact known-bad hashes and high-confidence rules can be quarantined automatically
- Unsigned old programs with a pattern match are shown as "suspicious", with the reason
- Every result offers Quarantine, Delete forever or Allow; quarantine is always reversible
- Allowed files are remembered by hash and never flagged again
- Microsoft-signed system files are never acted on
- Real false alarms found on real PCs become regression tests (Autodesk Maya data, Anaconda's shortcut, cached app bundles)
