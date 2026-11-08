# Changelog

Each `## version` section becomes the release notes and the first line shows in the app's update banner.

## 0.5.0

- Ransomware rollback: Hexward keeps a private copy of your documents and photos, and Settings › Document backup › Restore puts back files ransomware damaged, renamed or removed (`hexward restore-files`)
- Opt-in cloud, all off until you turn it on: reputation lookups that send only 6 of 64 hash characters, signer reputation, detection and false-alarm reports, and "Send to lab" on results
- Community database: confirmed submissions now reach every install with the rule update
- Inno Setup installers are unpacked (setup commands, script, and the programs inside)
- Weekly known-good check of every malware hash Hexward ships (CIRCL hashlookup, which includes the NSRL)
- Fixed: the project audit no longer mistakes split-up test samples for private keys in git history
- Also in this release (0.4.0 was never published):
- Ransomware shield: hidden decoy files, bulk rename and encryption detection, backup-deletion blocking
- Memory scan: checks the memory of running programs for unpacked and injected code (Tasks › Scan memory)
- Project audits now spot odd dependency releases: a new install script, a 10× size jump, a huge version jump, or a release with no git commit
- Self-test of every threat type on each release ([docs/SELFTEST.md](docs/SELFTEST.md))
- Privacy policy, plain-words licence terms and published criteria for unwanted software

## 0.3.0

- Looks inside more: RTF objects (Equation Editor exploits), PDF scripts, launch actions and attachments, OneNote attachments, CAB, RAR (names and stored files), MSI, NSIS installers, PyInstaller programs, UPX-packed programs, and VHD/VHDX/IMG disk images
- Sees through script obfuscation: split strings, escape characters, character codes, reversed text, nested and compressed base64
- Script shield (AMSI): PowerShell, VBScript, JScript and Office macros checked as they run
- Process shield now catches suspicious chains: Office or a browser starting script tools, regsvr32/mshta/certutil tricks, hidden encoded PowerShell
- Vulnerable and malicious kernel drivers (LOLDrivers and Microsoft's blocklist), and an alert for every new driver
- Files unpacked from downloaded archives get their "from the internet" mark back
- Starts with Windows in the notification area; quiet mode for games and presentations; background-priority scanning
- Signed, staged rule channel with rollback and a kill switch (`hexward update --rollback`)
- Microsoft's own catalog-signed scripts and programs are recognized as signed
- Release gate now also scans 16 popular installers and game launchers fetched fresh

## 0.2.0

- Dev & AI protection: audit a project or GitHub repository for supply-chain and AI-agent traps before you install or open it
- Finds install-time code, poisoned Claude Code and VS Code configs, prompt injection, hidden Unicode, risky GitHub Actions and leaked keys (also in git history)
- Optional online check: known-malware package versions (OSV.dev) and package names that don't exist (slopsquatting)
- Hexward Guard: checks Claude Code's commands and file edits before they run
- MCP server pinning: new or changed servers wait for your approval
- Extension inventory for editors and browsers, with risky permissions, hidden-code checks and changes since last time
- `hexward audit`, `hexward guard` and `hexward extensions` commands
- Cleaner: finds your browsers and shows their icons; tick cache, history or cookies per browser, plus temp files, crash dumps, thumbnail and shader caches and the Recycle Bin. Sizes are shown before anything is deleted, bookmarks and passwords are never touched, files in use are skipped
- Task manager: programs grouped into Apps, Background and Windows with icons, publishers, CPU and memory; Windows and security processes are locked; scan, open the folder or end a program after a confirm step; unsigned programs in Temp or Downloads are highlighted
- Startup manager: publisher, signature status, size and icon for each entry, with search and sorting; third-party scheduled tasks and services can be switched off and back on (admin asked only when needed)
- PC care: a cleaner, a task manager and a better startup manager

## 0.1.1

- ClickFix shield: fake "verify you're human" commands are replaced on the clipboard; Win+R history checked
- Stealer shield: alerts when a non-browser opens saved passwords, cookies, Discord/Telegram sessions or wallets
- Fewer false alarms: cached app bundles in Temp, Anaconda's PowerShell shortcut, large data files
- Progress page and a PC care phase (startup manager, task manager, cleaner) on the roadmap

## 0.1.0

- First release: desktop app and `hexward` command line
- Quick, System, Full and Custom scans (pick drives and folders)
- 5,100+ YARA Forge rules, MalwareBazaar hashes with an abuse.ch key
- Quarantine, Delete or Allow for every result; signed files never auto-quarantined
- Startup-item checker and fixer with undo
- Tray icon, Windows notifications, light and dark themes
- Signed self-update from GitHub Releases
- Looks inside ZIP, 7z, GZIP, TAR and ISO files, Office macros and embedded files
- Detects shortcut droppers, macro droppers, script droppers, HTML/SVG smuggling and ClickFix pages
- Real-time file shield and process shield; scan cache for fast repeat scans
- False-alarm gate in the release pipeline
