# Free signing and lab-test applications

Hexward stays free and its maker pays no one, so every certification goes through a free route.
These are ready-to-send texts. A person has to submit each one (they need a real contact and
sometimes a call); nothing here is sent automatically.

## 1. SignPath Foundation: free Authenticode code signing for open source

Where: https://signpath.org/apply (the SignPath Foundation's open-source program).

What they check: an OSI-approved licence (GPL-3.0-or-later ✓), public source and builds from it
(GitHub Actions ✓), released versions (v0.2.0 and later ✓), no proprietary parts (✓), and that the
project is maintained. A very new repository may be asked to wait for more history: apply once a few
monthly releases have shipped.

How signing would fit: the release workflow already builds on GitHub's runners. SignPath signs the
built `hexward.exe`, `hexward-app.exe` and `hexward_amsi.dll` through its GitHub Action, after the
false-alarm gate and the self-test and before our own Ed25519 signatures are made.

Text to send:

> **Project:** Hexward, https://github.com/memegyanfactory-gif/hexward
> **Licence:** GPL-3.0-or-later
> **What it is:** a free, open-source antivirus and anti-malware suite for Windows, written in Rust:
> scanning with YARA-X rules and hash lists, real-time shields in user mode (files, processes,
> clipboard ClickFix lures, password stealers, ransomware), an AMSI script provider, supply-chain
> audits for code projects and protection for AI coding agents.
> **Why signing matters here:** Windows SmartScreen and other antivirus products treat unsigned security
> tools with suspicion, and the AMSI provider DLL is loaded into other programs. Signing lets people
> trust that the binaries came from this repository's build.
> **Build:** GitHub Actions, `.github/workflows/release.yml`; every release passes a false-alarm gate
> over a clean Windows install and a self-test before it is published. Releases also carry Ed25519
> signatures checked by the built-in updater.
> **Maintainer:** Onuri Labs, https://onurilabs.com

## 2. AV-Comparatives

Where: https://www.av-comparatives.org/contact/ (ask about the free tests open to new vendors, and
the Consumer Main-Test Series criteria).

Honest status to include: Hexward runs in user mode beside Microsoft Defender (no kernel driver), so
it fits the "additional protection" category better than a full replacement. The Real-World and
Malware Protection tests need the product to block on its own; start by asking for a pre-test or
the performance test, where the budget is an impact score of 10 or less ([BENCHMARK.md](BENCHMARK.md)).

Text to send:

> Hello. Onuri Labs makes Hexward, a free, open-source (GPL-3.0) antivirus for Windows written in
> Rust (https://github.com/memegyanfactory-gif/hexward). We can't pay test fees: the project is free
> and stays free. Is there a free way for a new open-source product to be tested, for example a
> pre-test, the performance test, or a place in a public test as a non-paying participant? Hexward
> works in user mode alongside Microsoft Defender. Its own self-test and false-alarm results are
> published with each release (docs/SELFTEST.md). Thank you.

## 3. AVLab Cybersecurity Foundation

Where: https://avlab.pl/en/contact. AVLab runs "Advanced In-The-Wild Malware Test" series and has
tested free products before.

Text to send: the AV-Comparatives text above, addressed to AVLab, adding that Hexward has a
command-line scanner (`hexward scan --json`) for automated test harnesses.

## 4. SE Labs

Where: https://selabs.uk/contact. SE Labs mostly tests paying vendors; ask whether a free product can
be included in the public home anti-malware report.

## What's needed from the maintainer

- A contact name and email for each form (support@ addresses are fine).
- For SignPath: a GitHub account with admin rights on the repository, to install their GitHub App.
- Patience: labs reply in weeks, and may ask for a few more releases first.
