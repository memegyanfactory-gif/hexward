# How Hexward becomes the best antivirus

Research synthesis, 8 November 2026. Three research passes covered independent lab tests, the 2024–2026
threat landscape, and Microsoft's platform rules plus the legal and business side. Key sources are linked
at the end. Claims marked *(unverified)* came from a single secondary source.

## The one-paragraph answer

The top products (Kaspersky, Bitdefender, Norton/Avast, ESET, Microsoft Defender) all block 99–100% of
real-world attacks, so they are told apart by **false alarms and slowdown**, not protection.
Each one gets there in three layers:
1. A local engine catches 86–98% of threats.
2. Cloud reputation adds up to 13 points.
3. Behavior blocking at the moment a program runs closes the last few points.

A signature-only engine tops out around 60%. ClamAV caught 59.9% of 416,561 MalwareBazaar samples in Splunk's test.
Microsoft's antivirus program (MVI) gates the Windows features a top antivirus needs: early-launch driver,
protected service, kernel threat telemetry, and registration as the active antivirus.
MVI only admits products that already have real-time protection **and** an independent lab certificate from
the last 12 months. So the path is fixed:

**real-time protection → near-zero false alarms → lab certificate → MVI → kernel-grade protection → cloud.**

Open source wins where closed vendors can't follow: public, reproducible benchmarks, transparent rules, fixes
that ship in hours, no telemetry by default, memory-safe parsers, and a security layer for developers and AI
agents that nobody else offers.

## 0. The zero-cost rule (decided 8 Nov 2026)

Hexward stays free, and the founder pays no one: not Microsoft, not certificate sellers, not labs, not
hosting. Every part of the plan uses a free route:

| Need | Paid route others use | Hexward's free route |
|---|---|---|
| Windows code signing (SmartScreen, Smart App Control) | Artifact Signing ~$10/month, EV certificate $300–700/year | **SignPath Foundation**: free Authenticode signing for OSI-licensed open-source projects, built and signed from GitHub Actions (SignPath is named as publisher) |
| Update integrity | – | Our own Ed25519 signatures (already shipped) |
| Distribution | Paid CDN | GitHub Releases, winget community manifest |
| Real-time protection | Kernel minifilter (needs an EV certificate) | **User mode**: ETW events, file watchers, AMSI provider. Detects fast after start; can't block before a file opens |
| Lab tests | Paid consultancy | AV-Comparatives' main series (free, limited places), AVLab (free testing), SE Labs (no subject fee) |
| Cloud lookups and website | Paid servers | Free tiers: GitHub Pages for the site, a serverless free tier for opt-in hash lookups |
| Team | Salaries | Volunteers; grants and sponsors may fund work later, paid to the project, never by the founder |

**What the rule rules out:** Microsoft's antivirus program (MVI) requires Microsoft's paid Artifact Signing.
Without MVI there's no early-launch driver, no protected service and no Security Center registration, and
without an EV certificate there's no kernel driver. So Hexward is built to run **alongside Microsoft
Defender** as a second layer: Defender keeps doing pre-execution blocking, and Hexward adds deeper archive
and file analysis, behavior shields in user mode, honest false-alarm handling, and the developer and
AI-agent protection nobody else has. If sponsors ever cover the ~$120/year for Artifact Signing, the MVI
path below reopens.

"Best" under this rule means the best-scoring product in what we can control: false alarms, transparency,
depth of file analysis, speed, privacy, and developer and agent security. It also means lab results for
on-demand and user-mode protection, published whatever they say.

## 1. What "best" is measured by

| Lab | What wins | Recent numbers |
|---|---|---|
| AV-Comparatives Real-World (Feb–May 2026, 400 cases) | Protection rate, downgraded one award level if false alarms are above average | Kaspersky 99.8% / 3 FPs, Microsoft 99.0% / **0 FPs**, Trend Micro 98.3% / 83 FPs (lowest award), Malwarebytes 98.8% / 39 FPs |
| AV-Comparatives Malware Protection (Mar 2026, 10,000 samples) | Offline → online → after-execution detection | Bitdefender 97.6% offline; Microsoft 89.2% offline, 99.93% after execution |
| AV-TEST (every 2 months) | 6 points each for Protection, Performance, Usability | Clean set of **887,078 files; the industry average is 3 false detections** |
| AV-Comparatives Performance (Apr 2026) | Impact score, lower is better | McAfee 3.3, Kaspersky 3.5, ESET 4.2, Defender 12.9, Malwarebytes 17.6 |
| SE Labs, MRG Effitas, AVLab | Full attack chains | Each counts for MVI at its top grade (AAA, Level 2, 99.6%) |

**Lesson:** half a point of protection is worth less than 20 false alarms. Usability decides the awards.

## 2. Where Hexward stands

| Layer | Top products | Hexward today |
|---|---|---|
| Signatures, hashes, YARA | ✓ | ✓ 5,134 YARA Forge rules, hash lists |
| Looking inside archives and disk images | ✓ | ✓ new: ZIP, 7z, GZIP, TAR, ISO; LNK dropper analysis |
| Office macros, PDF, scripts, installers, unpackers | ✓ | ✗ Phase 1.5 |
| Static machine learning | ✓ | ✗ Phase 4 (EMBER2024 models, Apache-2.0) |
| Real-time file and process protection | ✓ | ✗ **the gate; Phase 2** |
| Script and macro scanning (AMSI) | ✓ | ✗ Phase 2 (needs no Microsoft approval) |
| Behavior blocking (stealers, ransomware, ClickFix) | ✓ | ✗ Phase 2–4 |
| Cloud reputation | ✓ adds 0–13 points | ✗ Phase 6, opt-in |
| False-alarm controls | ✓ | ✓ signature-aware, disabled rules, allow list, reversible quarantine |
| Safe updates | ✓ (after CrowdStrike) | Partly: signed app updates; rule packs not yet signed or staged |
| Developer and AI-agent protection | ✗ nobody | Phase 3: **our unique ground** |

## 3. The threats that matter most now (2024–2026)

- **Infostealers** are the top consumer threat. Lumma infected ~394,000 PCs in two months before Microsoft
  took it down in May 2025, and Vidar 2.0 took over. Stealers grab browser passwords and cookies, crypto
  wallets, Discord and Telegram sessions. **Catch them by behavior:** a non-browser program reading browser
  credential files.
- **ClickFix / paste-and-run**: fake CAPTCHAs that tell people to paste a command into Run. ESET measured
  +517% in H1 2025 (~8% of blocked attacks). **Catch it** by watching what gets pasted into Run, Terminal and
  Explorer's address bar.
- **Initial-access files:** LNK shortcuts with hidden arguments (used by 11 state groups, unpatched by
  Microsoft), ISO/IMG/VHD to dodge the downloaded-file warning, password-protected ZIPs, SVG and HTML
  smuggling, signed MSIX installers, LOLBins (mshta, rundll32, regsvr32, msiexec, certutil).
  *Hexward now covers the first three.*
- **Ransomware** hit a record of 7,000–8,000 leak-site victims in 2025. Attackers kill antivirus with
  vulnerable drivers (BYOVD), so a driver blocklist and self-protection are required.
- **Software supply chain**: 454,600 new malicious packages in 2025 (+75%). Examples:
  - **npm:** the chalk/debug compromise; the Shai-Hulud worms (which install the Bun runtime, run TruffleHog
    and republish themselves); Axios; TanStack.
  - **CI and repos:** the tj-actions tag hijack; xz-utils.
  - **Editor extensions:** GlassWorm hid code in invisible Unicode in VS Code extensions.
  - **AI agents:** the Keyv worm writes `.claude/settings.json` hooks and `.vscode/tasks.json`.
- **Attacks through AI coding agents:**
  - prompt injection in README, `AGENTS.md`, `CLAUDE.md` and `.cursorrules`
  - invisible Unicode tag characters
  - poisoned MCP servers (postmark-mcp BCC'd every email to an attacker)
  - agents run with `--dangerously-skip-permissions` by malicious install scripts (s1ngularity)

## 4. Gates we can't skip

1. **A legal entity** (US or EU) is needed for Microsoft programs, EV certificates and Partner Center.
2. **Code signing.** Microsoft Artifact Signing is about $10/month. Sign every binary under one identity so
   SmartScreen and Smart App Control learn to trust it.
3. **Real-time protection**, in order:
   - First in user mode: ETW process and file events, a download watcher, and an AMSI provider. It acts
     right after something runs, so we say "detects fast", never "prevents".
   - Then a file-system minifilter for real blocking. That needs an EV certificate, a Microsoft altitude
     request (free, ~30 business days) and driver testing.
4. **Lab certification:** AVLab first (free testing; 99.6% counts for MVI), then AV-Comparatives, whose main
   series is free but places are limited. Expect a year or more.
5. **MVI membership** unlocks the early-launch driver, the protected service, kernel threat telemetry,
   Security Center registration, and Microsoft's new user-mode security platform (WESP), which is replacing
   kernel drivers after CrowdStrike.

## 5. Rules we adopt now (from other vendors' disasters)

- **Never act on Microsoft-signed or catalog-signed files, Hexward's own files or boot-critical paths.**
  McAfee DAT 5958 deleted svchost.exe in 2010, Webroot quarantined Windows files in 2017, and Defender deleted
  shortcuts in 2023.
- **Quarantine, never delete, unless the user chooses.** Already true.
- **Every rule pack goes through a false-alarm gate before release.** We scan a clean corpus first:
  - Windows system files
  - NSRL Modern hash sets
  - top winget installers
  - popular games and launchers

  The target is AV-TEST's bar of about 1 false alarm per 300,000 clean files. Any hit on a Microsoft-signed
  file blocks the release.
- **Updates roll out like CrowdStrike's do now:**
  - signed packs, validated and fuzzed
  - canary → 10% → 100%, with each client picking its group locally (no telemetry needed)
  - instant rollback, a kill switch, and a "delay updates" option
  - a boot-loop breaker
- **Privacy:**
  - cloud lookups send only a hash prefix
  - telemetry and sample upload are separate opt-ins
  - no browsing data, ever

  Avast was fined about €13.9M in the Czech Republic plus $16.5M by the US FTC for selling "anonymised"
  browsing data.
- **Licences:**
  - VirusTotal can't be used inside the product (its terms forbid it).
  - abuse.ch data is free for non-profit use; get its position in writing.
  - ClamAV code is GPL-2.0-only and can't be linked into Hexward.
  - Rules under the Detection Rule License must keep author credit in match messages.

## 6. Machine learning, honestly

- **Best open option:** EMBER2024 (KDD 2025, 3.2M files, LightGBM models under Apache-2.0) reaches 94.5%
  detection at 1% false positives.
- **The catch:** 1% false positives would be about **8,900 false alarms** on AV-TEST's clean set, where the
  industry average is 3.
- **How we'd use it:** as one signal only, at a very strict threshold, combined with "unsigned + rare +
  suspicious traits", and never acting on its own.
- **Upkeep:** retrain every quarter and evaluate on time-split data. Attack research shows ML can be evaded
  (74% against EMBER's model), which is why layers matter.

## 7. People and money

- **Every past open-source antivirus fell short:** ClamWin (on-demand only, last release 2021), Immunet
  (discontinued 2024) and KicomAV (one maintainer). None had real-time blocking, a cloud, analysts or a lab
  certificate.
- **The leaders are huge:** ESET has 2,400+ staff (800+ researchers) and €733M revenue; Bitdefender about 2,000.
- **A realistic open challenger:**
  - Years 0–2: 3–6 full-time people (2–3 engineers, 1–2 malware analysts), about $0.5–1M a year, from grants
    (Sovereign Tech Fund, NLnet), sponsors and a paid business tier.
  - Top tier means 10–20+ people by years 3–5.
- **Liability:**
  - an EULA with a warranty disclaimer
  - published rules for what counts as unwanted software (see *Enigma v. Malwarebytes*)
  - the EU's new Product Liability Directive covers commercial software from December 2026

## 8. The plan in order

See [ROADMAP.md](../ROADMAP.md). In short:

1. **Now:** archive and document engine (started), false-alarm gate, signed and staged rule packs,
   code signing, legal entity.
2. **Next:** real-time protection in user mode, an AMSI provider, and behavior shields for stealers and
   ClickFix (the two biggest consumer threats).
3. **Our edge:** the code, supply-chain and AI-agent scanner and guard.
4. **Then:** a machine-learning signal, memory scanning, a ransomware shield with rollback.
5. **Then:** lab certificate → MVI → minifilter, protected service, Windows Security Center.
6. **Last:** opt-in cloud reputation and the Hexward website.

## Key sources

- AV-Comparatives Real-World Feb–May 2026: https://www.av-comparatives.org/tests/real-world-protection-test-february-may-2026/
- AV-Comparatives Malware Protection Mar 2026: https://www.av-comparatives.org/tests/malware-protection-test-march-2026/
- AV-Comparatives Performance Apr 2026: https://www.av-comparatives.org/tests/performance-test-april-2026/
- AV-TEST Windows 11, Oct 2025: https://www.av-test.org/en/antivirus/home-windows/windows-11/october-2025/
- Microsoft MVI criteria (Oct 2026): https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria
- ELAM prerequisites: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites
- Protected anti-malware services: https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Minifilter altitude requests: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
- Elastic on Microsoft's WESP platform (Oct 2026): https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp
- SmartScreen reputation: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
- CrowdStrike Channel File 291 RCA: https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf
- Splunk ClamAV efficacy study: https://www.splunk.com/en_us/blog/security/how-good-is-clamav-at-detecting-commodity-malware
- Microsoft on Lumma (May 2025): https://blogs.microsoft.com/on-the-issues/2025/05/21/microsoft-leads-global-action-against-favored-cybercrime-tool/
- Microsoft on ClickFix (Aug 2025): https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique
- ESET Threat Report H1 2025: https://www.welivesecurity.com/en/eset-research/eset-threat-report-h1-2025/
- ZDI-CAN-25373 LNK abuse: https://www.logpoint.com/en/blog/windows-shell-link-vulnerability-zdi-can-25373-detecting-hidden-commands
- Unit 42 npm supply-chain tracker: https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks.md
- Shai-Hulud (Sysdig): https://sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages
- tj-actions (CISA): https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- Pillar "Rules File Backdoor": https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
- Invariant Labs, GitHub MCP: https://invariantlabs.ai/blog/mcp-github-vulnerability
- Embrace The Red, Unicode tags: https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags
- EMBER2024: https://arxiv.org/html/2506.05074v1
- TESSERACT (time-split evaluation): https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury
- Czech DPA fine against Avast: https://uoou.gov.cz/en/news/business-communication/czech-dpa-imposed-fine-of-351-million-czk-for-gdpr-infringement
- VirusTotal API terms: https://docs.virustotal.com/reference/public-vs-premium-api
- abuse.ch terms: https://abuse.ch/terms-of-use/
