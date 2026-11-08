# Hexward roadmap

Goal: a free, open-source Windows security suite in Rust that stands next to Norton, McAfee, Avast,
Avira and Malwarebytes on protection, beats them on honesty and false alarms, and adds what they
don't have: protection against poisoned code, packages and AI coding agents.

"Best" is proven by independent lab results (AV-TEST, AV-Comparatives, SE Labs), never claimed.

Each phase ships as a signed release through the GitHub pipeline and reaches users by the in-app updater.

---

## Phase 1 · Scanner you can trust (now)

Done
- Rust engine: hash lists, YARA-X rules, EICAR, file-name tricks, disguised programs
- YARA Forge rule packs (5,100+ rules), MalwareBazaar hashes with an abuse.ch key
- False-alarm guards: signed software never auto-quarantined, disabled-rule list, hunting rules = suspicious
- Encrypted quarantine with restore; startup-item checker and fixer with undo
- `hexward` command line; desktop app (Slint) with 8 screens; local history and threat map

In progress
- One-piece window: custom title bar inside the app, cleaner visuals
- Scan picker: Quick, System (Windows + Program Files + startup + running programs), Full, and Custom
  (tick any drives, add any number of folders or projects, scan them together)
- Per-result choice: Quarantine, Delete forever, or Allow (trust this file from now on)
- Tray icon and Windows notifications; closing the window keeps Hexward in the tray
- Signed self-update from GitHub Releases + release pipeline (tests → build → sign → publish)

## Phase 2 · Code and supply-chain security (the thing nobody else does well)

`hexward audit <folder or git URL>` and an "Audit a project" screen.
- Install-time code: npm `preinstall`/`postinstall`, Python `setup.py`, Cargo `build.rs`, Makefiles, git hooks
- Known compromised package versions (lockfiles: package-lock, yarn, pnpm, Cargo.lock, poetry, requirements)
- Typosquats and dependency confusion (names one edit away from popular packages, unpinned internal names)
- Obfuscated or injected code: long base64/hex blobs, `eval`/`Function` on decoded strings, crypto-wallet
  address swaps, beacons to paste sites, credential grabbing (`.npmrc`, `.ssh`, cloud keys, browser data)
- Hidden text for AI agents: invisible Unicode (tags, zero-width, bidi), prompt injection in README,
  `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, issue templates, MCP configs
- Leaked secrets in files and git history (API keys, tokens, private keys)
- CI risks: GitHub Actions pinned to tags instead of commit SHAs, `pull_request_target` misuse, script injection
- Signed, explainable report with a fix for each finding

## Phase 3 · Guardrails for AI agents and command-line tools

"Hexward Guard": a policy layer that sits in front of coding agents (Claude Code, Cursor, Codex,
Copilot CLI and others) and plain shells.
- Hooks that check each command before it runs: blocks `curl | sh`, unknown package installs,
  reading `~/.ssh`/browser data/credential stores, mass deletes, force-pushes, edits outside the project
- Package firewall: new installs are checked against Phase 2 data before they reach disk
- Git protection: blocks pushes of secrets, unsigned commits to protected branches, hook tampering
- Every block explained in plain words, with a one-click allow for the user (never for the agent)

## Phase 4 · Real-time protection

- File shield: Windows minifilter driver (signed), scan on open, write and execute
- Behavior shield: ransomware detection (mass encryption, canary files) with automatic file rollback
- Exploit and script shield: AMSI provider for PowerShell, VBScript, JScript, Office macros
- Web shield: block known phishing and malware domains (local DNS filter, no traffic leaves the PC)
- USB and download scanning; scheduled scans; game/full-screen quiet mode
- Microsoft Virus Initiative membership, then register as the Windows antivirus

## Phase 5 · Cloud intelligence (opt-in)

Requires the Hexward website and API. Off by default; users choose what to share.
- Share detection reports: file hash, detection name, rule, Hexward version. Never file contents, paths or names
- Optional: submit a suspicious file for analysis (user clicks, sees exactly what is sent)
- Website dashboard: detections over time, top families, false-alarm reports, git/package findings
- Internal database grows from shared reports, lab samples and community rules; feeds back into rule packs
- Privacy policy, GDPR basics, data deletion on request; published transparency report

## Phase 6 · Full suite and proof

- Machine-learning model for Windows programs (trained on EMBER/SOREL-20M, runs in Rust via tract)
- Firewall rules UI, Wi-Fi checks, browser extension checks, data-breach checks
- Independent lab tests every quarter, results published in the app whatever they say

---

## False-alarm policy (the GTA Vice City rule)

Old games and tools (no-CD fixes, packers, trainers) are where Avast and Avira used to delete working files.
Hexward never deletes on its own:
- Only exact known-bad hashes and high-confidence rules can be quarantined automatically, and only on request
- Unsigned old programs with a pattern match are shown as "suspicious" with the reason
- Every result offers Quarantine, Delete forever or Allow; quarantine is always reversible
- Allowed files are remembered by hash and never flagged again
- Users can report a false alarm in one click (Phase 5); fixed rules ship in the next rule update
