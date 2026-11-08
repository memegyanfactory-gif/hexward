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
| Script shield component | GitHub | once, when you turn the script shield on | an ordinary web request |

## What Hexward sends, only when you ask

- **Project audit, "Check online"** (off by default): the names and versions of the project's
  packages go to OSV.dev, npm and PyPI to look up known malware and check the names exist. No file
  contents, no file paths, nothing else.
- **Submitting a sample** on hexward.onurilabs.com: the file you choose and your optional note. See the
  website for how samples are stored (encrypted, reviewed by a person, never shared).

## Future cloud features

Planned cloud features (reputation lookups, detection reports) will be separate opt-in switches, send
only hash prefixes where possible, and have a published retention period before they ship.

## Contact

Questions: open an issue at https://github.com/memegyanfactory-gif/hexward/issues.

_Last updated: November 2026._
