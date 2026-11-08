# What Hexward calls malware, suspicious, or unwanted

Antivirus products have deleted working games, tools and system files on a hunch. Hexward publishes
its criteria so anyone can predict what it will do, and challenge a decision.

## Three levels

| Level | Meaning | What Hexward does |
|---|---|---|
| **Confirmed threat** | An exact known-bad file (hash list), a high-confidence malware rule on an unsigned file, a known-malicious driver, a script blocked by the script shield | Can be quarantined automatically (if that setting is on). Never deleted without you |
| **Suspicious** | A pattern match on a signed file, a hunting/hack-tool rule, a heuristic (script that downloads and runs code, disguised program, shortcut dropper, vulnerable driver, unusual process chain) | Reported with the reason. Nothing changes until you choose Quarantine, Delete or Allow |
| **Worth a look** | Informational: unsigned programs running from Temp or Downloads, extensions with broad permissions, new drivers, project audit findings | Listed so you can decide |

## Potentially unwanted software

Hexward reports software as potentially unwanted (suspicious, never auto-quarantined) only when it
does at least one of these **without clear consent**:

1. **Hides itself**: no visible window or uninstaller, disguised file names, or it re-installs itself
   after removal.
2. **Takes control**: changes browser home pages, search engines or proxy settings; injects ads;
   intercepts traffic; or blocks security software.
3. **Collects data**: reads saved passwords, cookies, wallets or messages that don't belong to it
   (see the stealer shield), or records keystrokes or the screen.
4. **Misleads**: fake system warnings, "cleaners" or "optimizers" that invent problems to sell a fix,
   or installers that add unrelated software that's pre-ticked.
5. **Abuses resources**: mines cryptocurrency or joins a botnet without asking.

Being a hacking, remote-access, game-trainer, cracking or "no-CD" tool is **not** enough on its own.
Such tools are reported as suspicious only when they're also unsigned and running from an unusual
place, so you can allow them once and never see the warning again.

## What is never flagged

- Microsoft-signed files and catalog-signed Windows files are never acted on.
- Files you Allow are remembered by their SHA-256 and never flagged again, until they change.
- Rules with known false alarms are disabled in [rules/disabled.txt](../rules/disabled.txt), each with
  the clean file it hit.

## Disagree with a result?

Open an issue at https://github.com/memegyanfactory-gif/hexward/issues with the file's SHA-256 and
the detection name. Real false alarms become regression tests, so they stay fixed.
