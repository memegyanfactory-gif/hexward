# Hexward roadmap

Goal: the best antivirus and anti-malware product available. It should match the leaders on protection,
beat them on false alarms, honesty and privacy, and protect developers and AI agents, which nobody else does.
The reasoning and sources behind this order are in [docs/STRATEGY.md](docs/STRATEGY.md).

"Best" is proven by independent labs (AV-TEST, AV-Comparatives, SE Labs, AVLab), never claimed.
Each phase ships as a signed release through the GitHub pipeline and reaches users by the in-app updater.

---

## Phase 1 · Scanner you can trust (done)

- Rust engine: hash lists, YARA-X rules (5,100+ from YARA Forge), EICAR, file-name tricks, disguised programs
- False-alarm guards: a pattern rule alone never quarantines signed software; disabled-rule list; Allow list
- Encrypted, reversible quarantine; Delete only on request; startup checker and fixer with undo
- Desktop app (Slint) with pixel animation, tray, notifications; `hexward` command line
- Signed self-update from GitHub Releases; release pipeline with tests, lints and signing

## Phase 1.5 · Look inside everything (in progress)

Built from scratch in Rust; every parser has hard limits (depth, entries, bytes, compression ratio).
- [x] ZIP (and Office/JAR/APK/MSIX built on it), 7z, GZIP, TAR, ISO 9660; nested up to 3 levels
- [x] Zip-bomb detection, password-protected archive hiding a program, small disk image hiding a program
- [x] LNK shortcut analysis per MS-SHLLINK: LOLBin targets, hidden or encoded arguments, oversized payloads
- [x] Office macros (OLE/VBA, OOXML vbaProject.bin) and embedded Ole10Native files
- [ ] RTF, PDF JavaScript, OneNote attachments
- [x] Scripts: HTA, JS, VBS, PowerShell, batch, with base64 -enc decoding; SVG and HTML smuggling; ClickFix pages
- [ ] Deeper script de-obfuscation (string concatenation, char-code arrays, nested encodings)
- [ ] Installers and packers: MSI, MSIX manifests, NSIS, Inno Setup, UPX, PyInstaller
- [x] `.url` files with WebDAV or `file://` targets
- [ ] RAR, CAB, VHD/VHDX, IMG/UDF
- [x] Scan cache keyed by path + size + write time + rule-set fingerprint, so repeat scans skip unchanged files
- [x] **False-alarm gate in CI** (runner System32 + Program Files with the real rule pack; extend with NSRL sets and winget installers): every rule pack is scanned against a clean corpus first (Windows system
      files, NSRL Modern sets, top winget installers, popular games); any hit on a Microsoft-signed file fails the release
- [ ] **Signed, staged rule packs:** a separate offline key; canary → 10% → 100% picked locally by each client;
      instant rollback; kill switch; boot-loop breaker
- [ ] Head-to-head benchmark against KicomAV and ClamAV in a VM; results published

## Phase 2 · Real-time protection, user mode (the gate to every lab test)

- [x] File shield (Downloads, Desktop, Startup folders) and process shield in the app, with auto-quarantine of confirmed threats
- [ ] Background service so the shields run without the app open; ETW events once running as a service
- [ ] AMSI provider: scans PowerShell, VBScript, JScript and Office macros as they run (no Microsoft approval needed)
- [ ] Download watcher and scan-on-Mark-of-the-Web; copy the archive's Mark-of-the-Web onto everything extracted
- [ ] **Stealer shield:** alert when a non-browser program reads browser passwords and cookies, wallets or Discord/Telegram sessions
- [ ] **ClickFix shield:** catch commands copied from a browser and pasted into Run, Terminal or Explorer's address bar
- [ ] Suspicious process chains: browser, Office or Explorer starting mshta, wscript, `powershell -enc`, `regsvr32 /i:http`, `certutil -urlcache`
- [ ] Vulnerable-driver blocklist (Microsoft list + LOLDrivers); alert on new kernel-driver services
- [ ] Quiet mode for games; idle and low-priority scanning; performance budget (AV-Comparatives impact ≤ 10)

## Phase 3 · Developer, supply-chain and AI-agent protection (our edge)

`hexward audit <folder or git URL>`, an "Audit a project" screen, and Hexward Guard.
- Install-time code: npm `preinstall`/`postinstall`, `setup.py`/`pyproject`, Cargo `build.rs`, `binding.gyp`, git hooks
- Known-malicious versions (OSV `MAL-*`), phantom dependencies, version jumps, 10× size growth, releases with no git tag
- Agent and IDE configs: `.claude/settings.json` hooks, `.vscode/tasks.json` folder-open tasks, MCP configs, workflows
- Hidden text for AI agents: Unicode tags, zero-width and bidi characters, prompt injection in README/AGENTS.md/CLAUDE.md/.cursorrules
- GitHub Actions: tags instead of commit SHAs, `pull_request_target` misuse, broad permissions
- Leaked secrets in files and git history
- Guard: checks commands from agent processes before they run (`curl | sh`, credential reads, force-pushes, edits to agent
  configs, permission-bypass flags); MCP servers pinned by hash; the user approves, never the agent
- Extension inventory: VS Code, Cursor, Open VSX and browser extensions, with version diffs

## Phase 4 · Smarter detection

- Static machine learning on Windows programs (EMBER2024 LightGBM, Apache-2.0) as one signal at a very strict threshold, never alone
- Memory scanning of running processes with YARA
- Ransomware shield: canary files, rename/entropy bursts, shadow-copy deletion attempts; file rollback
- Unpacking and emulation for common packers

## Phase 5 · Certification, free route

Zero-cost rule: the founder pays no one (see docs/STRATEGY.md §0).
- Free Authenticode signing through the SignPath Foundation (open-source program), wired into the release workflow
- EULA and privacy policy (the GPL already disclaims warranty); published criteria for unwanted software
- Internal AMTSO-style tests published; then the free test series: AVLab, AV-Comparatives main series, SE Labs
- Run alongside Microsoft Defender as a second layer; no attempt to replace it in Security Center

Paused while the zero-cost rule stands (they need paid signing or certificates):
- Microsoft Virus Initiative → early-launch driver → protected service → Security Center registration → threat ETW
- Kernel minifilter for pre-execution blocking; Microsoft's user-mode security platform (WESP) through MVI

## Phase 6 · Cloud intelligence (opt-in) and the Hexward website

- Hash-prefix reputation lookups (k-anonymity); certificate and signer reputation; community allow list
- Separate opt-in for detection reports and sample upload; never browsing data; published retention policy
- Website dashboard: detections over time, false-alarm reports, supply-chain findings; internal database feeding rule packs
- Transparency report every year

---

## False-alarm policy (the GTA Vice City rule)

Old games and tools (no-CD fixes, packers, trainers) are where other antivirus products have deleted working files.
Hexward never deletes on its own:
- Only exact known-bad hashes and high-confidence rules can be quarantined automatically, and only on request
- Unsigned old programs with a pattern match are shown as "suspicious", with the reason
- Every result offers Quarantine, Delete forever or Allow; quarantine is always reversible
- Allowed files are remembered by hash and never flagged again
- Microsoft-signed system files are never acted on
- False-alarm reports (Phase 6) feed rule fixes shipped in the next staged update
