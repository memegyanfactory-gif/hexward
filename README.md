<div align="center">

<a href="https://hexward.onurilabs.com"><img src="assets/brand/hexward-lockup.svg" alt="Hexward" width="420"></a>

### Every byte, warded.

**A free, open-source malware scanner and security suite for Windows, written fully in Rust.**
No account. No ads. No paid tier. Nothing leaves your PC unless you choose to send it.

[Website](https://hexward.onurilabs.com) · [Download](https://github.com/memegyanfactory-gif/hexward/releases/latest) · [Roadmap](ROADMAP.md) · [Strategy and research](docs/STRATEGY.md) · [Credits](THIRD_PARTY_NOTICES.md)

![Rust](https://img.shields.io/badge/Rust-2024-0B0F14?logo=rust&logoColor=F0743A)
![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011-0B0F14?logo=windows&logoColor=4BE07A)
![License](https://img.shields.io/badge/license-GPL--3.0-0B0F14?labelColor=1A7F45)
![Rules](https://img.shields.io/badge/YARA%20rules-5%2C100%2B-0B0F14?labelColor=1A7F45)
![Tests](https://img.shields.io/badge/tests-123%20passing-0B0F14?labelColor=1A7F45)

<img src="docs/screenshots/01-home.png" alt="Hexward home screen" width="860">

</div>

---

## What Hexward does

Hexward finds malware, explains what it found in plain words, and lets **you** decide what happens next.
It runs alongside Microsoft Defender as a second layer that looks deeper into files, makes fewer false alarms,
and covers attacks Defender wasn't built for, like weaponized shortcuts, ClickFix pages and booby-trapped Office macros.

| | |
|---|---|
| **Scans** | Quick, System, Full, or Custom (tick any drives, add any folders or projects, scan them together) |
| **Looks inside** | ZIP and everything built on it (Office, JAR, APK, MSIX), 7z, GZIP, TAR, CAB, RAR (file list and stored files), ISO, VHD/VHDX and IMG disk images, MSI installers, NSIS installers, PyInstaller programs, UPX-packed programs, Office macros, RTF objects, PDF scripts and attachments, OneNote attachments, nested 3 levels deep |
| **Detects** | 5,100+ community YARA rules, known-bad hashes, ~3,000 vulnerable and malicious kernel drivers (LOLDrivers and Microsoft's blocklist), the EICAR test file, Windows file-name tricks, disguised programs, shortcut, macro, script and installer droppers (including obfuscated ones: split strings, character codes, reversed and nested base64), Equation Editor exploits, auto-running PDF scripts, HTML and SVG smuggling, ClickFix pages, zip bombs |
| **Guards in real time** | File, process, script, ClickFix and stealer shields: new downloads, every program that starts and who started it, PowerShell/VBScript/JScript/macros as they run (AMSI), commands copied from websites, anything that opens your browser passwords or wallets, and new kernel drivers. Starts with Windows; goes quiet during games and presentations. Confirmed threats are quarantined automatically (their process stopped first); suspicious finds always wait for you |
| **Fixes** | Quarantine (encrypted, always reversible), Delete forever (asks first), or Allow (trust that exact file). Startup items can be switched off and back on |
| **Protects developers and AI agents** | Audits a project or GitHub repository before you install or open it, guards Claude Code's commands as they run, pins MCP servers, and keeps an eye on editor and browser extensions |
| **Looks after the PC** | A startup manager (publisher, signature, size, search), a task manager that sorts programs into Apps, Background and Windows and won't let you end Windows or your security software, and a cleaner for browser caches, history, cookies and Windows junk |
| **Stays honest** | Signed software is never quarantined on a pattern alone. Suspicious isn't the same as confirmed, and the app shows the difference |
| **Stays fast** | A scan cache skips files a previous scan found clean with the same rules, so daily scans only read what changed |
| **Updates itself** | Signed releases from GitHub; every update's signature is checked before it installs. Rule packs come through a signed, staged channel with rollback and a kill switch |

<div align="center">
<img src="docs/screenshots/04-scan-threat-flash.png" alt="A scan in progress finding a threat" width="49%">
<img src="docs/screenshots/05-results.png" alt="Results with Quarantine, Delete and Allow" width="49%">
<img src="docs/screenshots/02-scan-choose.png" alt="Choosing drives and folders to scan" width="49%">
<img src="docs/screenshots/12-home-light.png" alt="Light theme with an update ready" width="49%">
</div>

### Developers and AI agents

Supply-chain attacks (Shai-Hulud, the chalk/debug takeover, s1ngularity, GlassWorm, the tj-actions hijack) now reach
people through `npm install`, a cloned repository, an editor extension, or an AI agent that reads the wrong file.
Hexward reads all of it and runs none of it.

<div align="center">
<img src="docs/screenshots/16-dev-audit.png" alt="Project audit finding install scripts, agent hooks and hidden text" width="49%">
<img src="docs/screenshots/17-dev-agents.png" alt="Hexward Guard and MCP server pinning" width="49%">
</div>

- **Project audit** (a folder or a GitHub address; repositories are cloned with hooks, submodules, LFS and fsmonitor switched off):
  - install-time code: npm lifecycle scripts in the project and in every installed package, `setup.py`, custom Python build backends, `build.rs`, `binding.gyp`, git hooks, git settings that run programs, submodule commands
  - AI-agent and editor traps: Claude Code hooks, "bypass permissions", broad allow rules and API redirects in `.claude/settings.json`; VS Code tasks that run when a folder opens; workspace settings that point at programs in the repository; unpinned MCP servers; prompt injection in README, AGENTS.md, CLAUDE.md and rule files, including hidden HTML comments
  - hidden text: Unicode tag characters (decoded and shown), Trojan Source bidi controls, zero-width and variation-selector payloads
  - GitHub Actions: actions on movable tags, known-hijacked actions, `pull_request_target` running PR code, issue and PR text pasted into shell commands, write-all tokens
  - leaked secrets: 20 key formats (GitHub, AWS, npm, PyPI, OpenAI, Anthropic, Stripe, Slack, private keys, …) in files and in git history, always masked
  - dependencies: packages from git or plain URLs, missing integrity hashes, any-version ranges, extra pip indexes (dependency confusion); with **Check online**, every locked version against OSV.dev's malware list and every named package against npm and PyPI, to catch names an AI invented (slopsquatting)
- **Hexward Guard** checks each command and file edit Claude Code is about to make. It blocks download-and-run, Defender tampering, backup deletion, credential theft and agents started with safety off, and asks you first about force-pushes, publishing and edits to agent configs, git hooks or startup entries. Switch it on in the app, or run `hexward guard install`.
- **MCP pinning** fingerprints every MCP server in Claude Code, Claude Desktop, Cursor, VS Code and Windsurf, including the script a local server runs. A new or changed server waits for your approval.
- **Extensions**: every VS Code, Cursor, Windsurf and VSCodium extension and every Chrome, Edge, Brave, Opera, Vivaldi, Yandex and Firefox extension, rated by what it can do, scanned for GlassWorm-style hidden code, with what was added, removed or updated since last time.

### PC care

<div align="center">
<img src="docs/screenshots/15-cleaner.png" alt="Cleaner with browser icons and tick boxes" width="49%">
<img src="docs/screenshots/14-tasks.png" alt="Task manager with locked Windows processes" width="49%">
</div>

- **Cleaner.** Finds Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi and Yandex, shows each with its own icon, and measures every item before anything is deleted. Cache is ticked by default; history, cookies and the Recycle Bin wait for you. Bookmarks and saved passwords are never touched, and Firefox history is left alone because it shares a file with bookmarks. An open browser is skipped (or closed politely, like clicking its X, if you ask). Temp files from the last 24 hours are kept, and files in use are skipped.
- **Task manager.** Every running program with its icon, publisher, CPU and memory, grouped into Apps, Background and Windows. Windows processes and security software are locked: Hexward refuses to end them, checked again at the moment you click. Scan any running program, open its folder, or end it after a confirm step. Unsigned programs running from Temp or Downloads are highlighted. SYSTEM services are matched to their programs through the Service Control Manager, so they land in the right group without admin rights.
- **Startup manager.** Everything that starts with Windows, scanned, with publisher, signature status, size and icon. Search and sort it, and switch entries off and back on: Run keys, Startup-folder shortcuts, and third-party scheduled tasks and services. Windows asks for administrator approval only when a change needs it, and Windows' own tasks, services and drivers are never offered.

---

## How it works

```mermaid
flowchart LR
    F[File on disk] --> N[Name checks<br/>double extension, RTLO, padding]
    F --> H[SHA-256<br/>allow list, known-bad hashes]
    F --> E[EICAR test file]
    F --> Y[YARA-X<br/>5,100+ rules]
    F --> C[Content checks<br/>disguised programs, shortcuts, scripts, web pages]
    F --> X{Container?}
    X -- ZIP · 7z · GZIP · TAR · ISO --> U[Unpack inside limits<br/>depth 3 · 5,000 entries · 1 GB · ratio 250:1]
    X -- Office document --> M[Macros and embedded files<br/>MS-OVBA, Ole10Native]
    U --> F
    M --> F
    N & H & E & Y & C --> V[Verdict]
    V --> S{Signed by a<br/>trusted publisher?}
    S -- yes --> SU[Suspicious: report only]
    S -- no --> CF[Confirmed or suspicious]
```

Every file goes through five layers, cheapest first. Anything that is a container is opened and each file inside it
goes through the same layers, recursively, so a payload in `mail.zip › invoice.iso › Invoice.lnk` is found and
reported with its full path.

### Detection layers

| Layer | Finds | Verdict |
|---|---|---|
| File name | `invoice.pdf.exe`, right-to-left override characters, names padded with spaces | suspicious |
| SHA-256 | Exact known-bad files (MalwareBazaar, Hexward's list); trusted files you allowed are skipped | confirmed |
| EICAR | The standard antivirus test file (built in memory, never stored in this repo) | confirmed |
| YARA-X rules | Patterns from 5,100+ curated rules. Filename, path and extension are passed to rules that use them | confirmed or suspicious by rule score |
| Disguised programs | A `.jpg` or `.pdf` that is really a Windows program | suspicious |
| Shortcuts (.lnk) | Shortcuts that launch PowerShell, mshta, rundll32 or similar tools with download, encoded or whitespace-hidden arguments; oversized shortcuts carrying a payload | suspicious |
| Office macros | Macros that run on open and download, launch programs or inject code; each macro is also run through every YARA rule | suspicious |
| Scripts | PowerShell, batch, JS, VBS, HTA download-and-run, including **base64 `-enc` payloads, which are decoded and checked** | suspicious |
| Web pages and images | HTML and SVG smuggling, SVGs that redirect to phishing, **ClickFix** pages that copy a command and tell you to paste it | suspicious |
| Internet shortcuts (.url) | Shortcuts that open WebDAV or file shares to dodge download warnings (CVE-2024-21412 style) | suspicious |
| Containers | Zip bombs, password-protected archives hiding programs, small disk images hiding a program or shortcut | suspicious |

### Real-time shields

The shields run in user mode (no kernel driver, no admin rights, no paid certificates):

- **File shield:** watches Downloads, Desktop and both Startup folders. A new or changed file is scanned once it stops changing, so half-finished downloads are left alone.
- **Process shield:** every program that starts is scanned; each program file is checked once until it changes. It also looks at who started it: Word, Excel, Outlook or a PDF reader starting PowerShell or a script host, a browser starting mshta or regsvr32, `regsvr32 /i:http`, `certutil -urlcache`, hidden encoded PowerShell. Clear-cut chains are stopped.
- **Script shield (AMSI):** PowerShell, VBScript, JScript and Office macros are checked as they run, after Windows has decoded them. A small provider DLL hands each script to Hexward; if Hexward doesn't answer in 3 seconds the script runs as normal, so it can never make PowerShell hang. Turning it on needs administrator approval once (the DLL goes into Program Files so it can't be swapped).
- **Download marks:** files unpacked from a downloaded archive get Windows' "from the internet" mark back (many archive tools drop it), so SmartScreen and Office's Protected View still warn.
- **Driver watch:** a new kernel driver is reported with its publisher and signature, and checked against ~3,000 known vulnerable and malicious drivers (the "bring your own vulnerable driver" trick ransomware uses to switch off security software).
- **Background and quiet:** Hexward starts with Windows in the notification area (no admin rights). During full-screen games, videos and presentations notifications wait and scans pause; shields and quiet-time scans run at background CPU and disk priority.
- **ClickFix shield:** watches what gets copied. A command that downloads and runs code is flagged; a clear-cut "verify you're human" lure (download + run + a hidden window, encoded command or fake verification comment) is replaced on the clipboard, so pasting it into Win+R does nothing. It also checks your Win+R history for lures pasted in the past. Real install commands (like Scoop's) only get a warning.
- **Stealer shield:** asks Windows which programs have browser passwords and cookies (Chrome, Edge, Brave, Vivaldi, Opera, Yandex, Firefox), Discord and Telegram sessions, or crypto wallets (Exodus, Electrum, Atomic) open, and flags anything that isn't the app that owns them. Unsigned programs running from Temp or Downloads are stopped and quarantined automatically; signed ones only raise a warning.
- **What happens on a hit:** a confirmed threat is quarantined automatically, and its process is stopped first. Suspicious finds are reported and left in place. Automatic quarantine can be switched off in Settings.

User mode means Hexward acts right after a file lands or a program starts, not before. Microsoft Defender keeps blocking up front, and Hexward is designed to run alongside it.

### Built not to break your PC

Antivirus products have deleted Windows system files (McAfee 2010, Webroot 2017), app shortcuts (Defender 2023)
and old games. Hexward is designed around those failures:

- **Nothing is deleted unless you click Delete.** Quarantine is encrypted (ChaCha20-Poly1305) and restores a file exactly where it was.
- **Signed software is never quarantined on a pattern alone.** If a rule hits a file with a valid Authenticode signature, it's reported as suspicious, with the reason.
- **Confirmed and suspicious are kept apart.** Only exact hash matches and high-confidence malware rules are pre-selected for quarantine. Hunting rules, hack-tool rules and machine-generated rules are always just "suspicious".
- **Allow** remembers a file by its SHA-256, so it's never flagged again, and changes to the file get it re-checked.
- **Rules with known false alarms are disabled** in [`rules/disabled.txt`](rules/disabled.txt), each with the clean file it hit.
- **Measured:** 434,191 files in `Program Files` and 22,548 in `System32` on a real PC produced zero false alarms after these fixes.

### Built for hostile files

An antivirus reads the most dangerous files on the machine, so its parsers are a target too.

- **Written in Rust**, so a crafted file can't trigger the memory bugs that C parsers suffer from.
- **Every reader has hard limits**: nesting depth, number of entries, total bytes unpacked, compression ratio. Archives are judged by their headers before anything is decompressed.
- **The ISO 9660 reader, the shortcut parser and the VBA decompressor are written from Microsoft's and ECMA's specifications**, with every offset bounds-checked. The VBA decompressor is tested against the spec's own worked examples.
- **Attack samples in the test suite are assembled from fragments at runtime**, so this repository never contains a complete attack. Other antivirus products delete source files that do.

---

## Install

**Download** the latest signed release from [Releases](https://github.com/memegyanfactory-gif/hexward/releases/latest):
`hexward-app.exe` (the desktop app) and `hexward.exe` (command line). Then:

1. Run `hexward-app.exe`.
2. Click **Download rules** on the home screen (about 1.7 MB from YARA Forge).
3. Click **Quick scan**.

**Build from source** (Rust 1.88 or newer, Windows):

```bash
git clone https://github.com/memegyanfactory-gif/hexward.git
cd hexward
cargo build --release
target\release\hexward-app.exe
```

## Command line

```bash
hexward update                          # download rule packs
hexward update --rollback               # go back to the previous rule pack
hexward scan                            # quick scan
hexward scan D:\Downloads E:\           # any files, folders or drives
hexward scan --full                     # every fixed drive
hexward scan D:\x --quarantine          # move confirmed threats to quarantine
hexward startup --all                   # everything that starts with Windows
hexward quarantine list
hexward quarantine restore <id>
hexward rules --verbose                 # what's loaded, from where, and anything left out
hexward audit                           # audit the project in this folder
hexward audit https://github.com/o/r    # audit a repository without running anything from it
hexward audit D:\code\app --online      # also check dependencies against OSV.dev, npm and PyPI
hexward guard install                   # Hexward Guard for Claude Code
hexward guard check "npm publish"       # ask Guard about one command (exit 0 allow, 1 ask, 2 deny)
hexward guard mcp --approve-all         # record MCP servers as they are now
hexward extensions                      # editor and browser extensions, and what changed
```

Add `--json` to `scan`, `startup`, `update`, `audit`, `extensions`, `guard mcp` and `quarantine list` for machine-readable output.
Exit codes: `0` nothing found, `1` threats found, `2` error.

## Rule packs

`hexward update` (or **Settings › Update rules**) downloads into `%LOCALAPPDATA%\Hexward\rules`:

| Pack | Source | Key | Contents |
|---|---|---|---|
| YARA Forge core (default) | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) | none | ~5,100 tested community rules |
| YARA Forge extended / full | same | none | more rules, more noise |
| MalwareBazaar hashes | [bazaar.abuse.ch](https://bazaar.abuse.ch) | free [Auth-Key](https://auth.abuse.ch) in `HEXWARD_ABUSECH_KEY` | SHA-256 of fresh malware, kept and grown on every update |
| Driver blocklist | [LOLDrivers](https://www.loldrivers.io) and [Microsoft's vulnerable driver blocklist](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | none | file and Authenticode hashes of vulnerable and malicious drivers |

**The rule channel.** The core pack arrives through Hexward's own channel (the `rules-channel` release): a daily workflow takes each new YARA Forge pack, runs it through the false-alarm gate, signs it with the release key and rolls it out in stages (5% of installs, then 25% after a day, everyone after two). A pack can be withdrawn at once with the kill switch, and installs that have it go back to the last good one. `hexward update --rollback` goes back to the previous pack by hand.

A new pack replaces the old one only after it compiles (and, from the channel, only after its signature checks), so a failed update never leaves you with fewer rules.
You can also drop your own `*.yar` rules, `*.txt`/`*.csv` hash lists and a `disabled.txt` into that folder.

## Updates and releases

```mermaid
flowchart LR
    P[Push to main] --> T[Tests + clippy<br/>GitHub Actions]
    T --> G[False-alarm gate<br/>real rules vs System32 + Program Files]
    G -- any confirmed hit --> F[Release blocked]
    G -- clean --> V{New version<br/>in Cargo.toml?}
    V -- no --> D[Done]
    V -- yes --> B[Build release]
    B --> S[Sign with Ed25519<br/>key held only by GitHub]
    S --> R[GitHub Release]
    R --> A[Apps check every 6 h]
    A --> C{Signature valid for<br/>this file + version?}
    C -- yes --> I[Install, restart]
    C -- no --> X[Refuse]
```

- The signature covers the file name, the version and the file's SHA-256, so neither a tampered file nor an old version relabelled as new can install.
- **False-alarm gate:** before any build, the pipeline downloads the real rule pack and scans the runner's `System32` and `Program Files`. One confirmed hit on that clean software blocks the release; suspicious hits are listed in the run summary.
- The workflow pins every GitHub Action to a full commit SHA (the tj-actions lesson) and refuses to publish if the signing key is missing.
- To release: bump `version` in `Cargo.toml`, add a `## version` section to [CHANGELOG.md](CHANGELOG.md), and push.

## Privacy

- No account, no telemetry, no analytics.
- Scans, history, quarantine and settings stay in `%LOCALAPPDATA%\Hexward`.
- Network use: rule and blocklist downloads (GitHub, abuse.ch, loldrivers.io, Microsoft), the update check (GitHub API), and, only when you tick **Check online** in a project audit, package names and versions sent to OSV.dev, npm and PyPI. Nothing else.
- The script shield's pipe only accepts connections from this PC, and scripts never leave it.
- Any future cloud features will be opt-in and send only hash prefixes. See [docs/STRATEGY.md](docs/STRATEGY.md).

## Project layout

```
crates/engine    scanning core: hashes, YARA-X, heuristics, containers, Office, scripts, project audit,
                 Guard, MCP pinning, extensions,
                 shortcuts, signatures, quarantine, startup items, allow list, history,
                 task list, services, cleaner
crates/cli       the hexward command
crates/app       the desktop app (Slint): screens, tray, notifications, self-update
crates/update    rule packs (YARA Forge, MalwareBazaar) and signed app updates
crates/release   signing tool for the release pipeline and the rule channel
crates/amsi      the AMSI provider DLL (hands scripts to the app over a local pipe)
rules/           built-in test rules, test hash, disabled-rule list
assets/brand     logos (generated from the pixel grids by scripts/brand-assets.js)
docs/            strategy and research, screenshots
```

## Testing

```bash
cargo test --workspace      # 123 tests
cargo clippy --workspace --all-targets -- -D warnings
target\debug\hexward-app.exe --shots docs\screenshots   # renders every screen to PNG
```

- **What the tests cover:** detection on harmless markers and fragment-built attack samples; real Windows files
  that must stay clean (notepad.exe, every Start-menu shortcut); and hostile inputs: zip bombs, malformed archives,
  malformed shortcuts and malformed documents.
- **Also tested:** quarantine round trips, signature verification of updates, the command line end to end, the cleaner on
  Chromium-style profiles (bookmarks must survive, files held open must be skipped), and the task manager refusing to end system processes.
- **Never put live malware on your main PC.** Test with the harmless markers, or in an isolated virtual machine.

## Roadmap

Hexward's goal is to be the best antivirus available: matching the leaders on protection, beating them on false
alarms and honesty, and protecting developers and AI coding agents, which nobody else does.
The full plan, with the research behind it, is in [ROADMAP.md](ROADMAP.md) and [docs/STRATEGY.md](docs/STRATEGY.md).

**Next:**
- Inno Setup unpacking, and RAR's compressed entries (the official unRAR code isn't GPL-compatible)
- the first published head-to-head benchmark (method in [docs/BENCHMARK.md](docs/BENCHMARK.md))
- release anomalies in dependencies: sudden version jumps, 10× size growth, releases without a git tag

## Credits

Hexward is built on excellent open work: [YARA-X](https://github.com/VirusTotal/yara-x) by VirusTotal,
[YARA Forge](https://github.com/YARAHQ/yara-forge) and the hundreds of rule authors it collects,
[MalwareBazaar](https://bazaar.abuse.ch) by abuse.ch, [Slint](https://slint.dev), the
[Pixelify Sans](https://github.com/eifetx/Pixelify-Sans) and [Geist](https://github.com/vercel/geist-font) fonts, and
35 Rust crates from the community. [KicomAV](https://github.com/hanul93/kicomav) by Kei Choi shaped the file-format
roadmap (no code used). Full list with licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

[GPL-3.0-or-later](LICENSE). Free forever, for everyone.

---

<div align="center">

<a href="https://onurilabs.com"><img src="assets/brand/onurilabs-mark.svg" alt="" width="22"></a>&nbsp;&nbsp;<a href="https://onurilabs.com"><img src="assets/brand/onurilabs-wordmark.svg" alt="ONURILABS" width="190"></a>

Made by **[Onuri Labs](https://onurilabs.com)** · [hexward.onurilabs.com](https://hexward.onurilabs.com)

</div>
