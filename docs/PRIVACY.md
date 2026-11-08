# Hexward privacy policy

Hexward is a free, open-source program by Onuri Labs. This page says exactly what it does with
information about you and your computer. The code is public, so every line below can be checked.

## What stays on your PC

Everything Hexward learns about your computer stays on it:

- scan results, history, settings and the list of files you chose to trust
- quarantined files (encrypted)
- project audits, Hexward Guard decisions, MCP server fingerprints and extension inventories
- the scripts the script shield (AMSI) checks: they go from the program running them to the Hexward
  app over a pipe that only works on this PC, and are never stored or sent anywhere

All of it lives in `%LOCALAPPDATA%\Hexward`. Uninstalling and deleting that folder removes it.

There is no account, no telemetry, no analytics, no advertising and no tracking.

## What Hexward downloads

| What | From | When | What's sent |
|---|---|---|---|
| App updates | GitHub (api.github.com, github.com) | every 6 hours, or when you click "Check" | an ordinary web request; nothing about you or your PC |
| Rule packs | GitHub (Hexward's rule channel, YARA Forge) | when you update rules | an ordinary web request |
| Known-malware hashes | abuse.ch (MalwareBazaar) | when you update rules, only if you set an Auth-Key | your Auth-Key, which abuse.ch requires |
| Driver blocklists | loldrivers.io, Microsoft | when you update rules | an ordinary web request |
| Community hashes | hexward.onurilabs.com | when you update rules | an ordinary web request |
| Script shield component | GitHub | once, when you turn the script shield on | an ordinary web request |

## What Hexward sends, only when you ask

- **Project audit, "Check online"** (off by default): the names and versions of the project's
  packages go to OSV.dev, npm and PyPI to look up known malware and check the names exist. No file
  contents, no file paths, nothing else.
- **Submitting a sample** on hexward.onurilabs.com: the file you choose and your optional note. See the
  website for how samples are stored (encrypted, reviewed by a person, never shared).

## Cloud features (opt-in, all off by default)

Four switches in Settings › Cloud. Nothing below happens until you turn the switch on.

| Switch | What is sent | Where | What is kept, and for how long |
|---|---|---|---|
| Cloud reputation | the first 6 of the 64 hex characters of a program's or script's SHA-256 | hexward.onurilabs.com | a count of lookups per day; no prefix, no address |
| Send detection reports | the file's name (never its folder), its SHA-256, the detection name, the Hexward version, a random install number | hexward.onurilabs.com | the report, 90 days, then deleted; only a hash of the install number |
| (same switch) Allow on a result | the same, marked as a false alarm | hexward.onurilabs.com | 90 days; a confirmed false alarm joins the community allow list (hash and file name only) |
| (same switch) Project audit, Check online | the name and version of a malicious package the audit found | hexward.onurilabs.com | 90 days |
| Share anonymous counts | about once an hour, numbers only: how many scans, files checked, threats found, files quarantined and threats blocked since the last report, and the Hexward version; the first time you switch it on, the totals already in your History are included, once. No file names, hashes, folders or install number | hexward.onurilabs.com | daily totals, kept for good, for "Threats caught so far"; your address is never stored with them |
| Send samples to the lab | the file, only when you click Send to lab on a result | hexward.onurilabs.com | encrypted until a person has reviewed it |

How the reputation lookup stays private: the server answers with every known-bad and allow-listed
hash that starts with those 6 characters (out of about 16 million possible starts), and Hexward
compares the full hash on your PC. The server never learns which file you have.

Your network address is never stored with a report. The rule update also downloads the confirmed
community hashes (an ordinary download; nothing is sent). The live numbers, and every request for
user data we ever receive, are on https://hexward.onurilabs.com/transparency.

## Contact

Questions: open an issue at https://github.com/memegyanfactory-gif/hexward/issues.

_Last updated: November 2026._
