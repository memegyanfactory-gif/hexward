# Changelog

Each `## version` section becomes the release notes and the first line shows in the app's update banner.

## 0.3.0

- Dev & AI protection: audit a project or GitHub repository for supply-chain and AI-agent traps before you install or open it
- Finds install-time code, poisoned Claude Code and VS Code configs, prompt injection, hidden Unicode, risky GitHub Actions and leaked keys (also in git history)
- Optional online check: known-malware package versions (OSV.dev) and package names that don't exist (slopsquatting)
- Hexward Guard: checks Claude Code's commands and file edits before they run
- MCP server pinning: new or changed servers wait for your approval
- Extension inventory for editors and browsers, with risky permissions, hidden-code checks and changes since last time
- `hexward audit`, `hexward guard` and `hexward extensions` commands

## 0.2.0

- PC care: a cleaner, a task manager and a better startup manager
- Cleaner: finds your browsers and shows their icons; tick cache, history or cookies per browser, plus temp files, crash dumps, thumbnail and shader caches and the Recycle Bin. Sizes are shown before anything is deleted, bookmarks and passwords are never touched, files in use are skipped
- Task manager: programs grouped into Apps, Background and Windows with icons, publishers, CPU and memory; Windows and security processes are locked; scan, open the folder or end a program after a confirm step; unsigned programs in Temp or Downloads are highlighted
- Startup manager: publisher, signature status, size and icon for each entry, with search and sorting; third-party scheduled tasks and services can be switched off and back on (admin asked only when needed)

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
