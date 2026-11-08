# Hexward

Free, open-source malware scanner for Windows, written in Rust. Every byte, warded.

Status: **phase 1, on-demand scanner.** It scans, reports and quarantines. Real-time protection and the desktop app come later.

## Use it

```
cargo build --release
target\release\hexward.exe update                     # download rule packs (do this first)
target\release\hexward.exe scan                       # quick scan: Downloads, Desktop, Temp, startup, running programs
target\release\hexward.exe scan D:\Downloads          # scan a folder
target\release\hexward.exe scan --full                # every fixed drive
target\release\hexward.exe scan D:\x --quarantine     # move confirmed threats to quarantine
target\release\hexward.exe startup                    # check what starts with Windows
target\release\hexward.exe quarantine list
target\release\hexward.exe quarantine restore <id>
target\release\hexward.exe rules --verbose            # what is loaded, and any rules left out
```

Add `--json` to `scan`, `startup`, `update` and `quarantine list` for machine-readable output.
Exit codes: `0` nothing found, `1` threats found, `2` error.

## How it detects

Cheapest first, per file:

| Layer | Finds | Confidence |
|---|---|---|
| File name | `invoice.pdf.exe`, right-to-left override, space-padded names | suspicious |
| SHA-256 list | exact known-bad files | confirmed |
| EICAR | the standard antivirus test file | confirmed |
| YARA-X rules | patterns inside files | confirmed or suspicious, see below |
| Content | Windows programs disguised as images or documents | suspicious |

`--quarantine` only moves **confirmed** hits. Suspicious files stay put unless you add `--include-suspicious`.

A rule hit is only **confirmed** when all of these hold:

- the rule's score is 75 or more (community convention: 70+ likely bad, 80+ malware);
- it isn't a hunting rule (`SUSP_`, `HKTL_`/hack tools, `PUA_`) or a machine-generated Malpedia `_Auto` rule;
- the file has **no valid digital signature**. Signed software with a rule hit is reported, never moved on a pattern alone.

Rules with known false alarms are listed in `rules/disabled.txt`, each with the clean file it matched.

## Rule packs

`hexward update` downloads into `%LOCALAPPDATA%\Hexward\rules`:

| Pack | Source | Key | What you get |
|---|---|---|---|
| YARA Forge core (default) | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) releases | none | ~5,100 tested community rules |
| YARA Forge extended / full | same, `--yara extended` or `--yara full` | none | more rules, more noise |
| MalwareBazaar hashes | [bazaar.abuse.ch](https://bazaar.abuse.ch) | free Auth-Key | SHA-256 of fresh malware, kept and grown on every update |

- A new YARA pack replaces the old one only after it compiles. A failed update leaves the previous rules in place.
- For MalwareBazaar, create a free key at https://auth.abuse.ch and set it before updating:
  `setx HEXWARD_ABUSECH_KEY your-key` (new terminals pick it up). Its export covers 48 hours, so update at least daily;
  abuse.ch asks for no more than one download every 5 minutes, which `update` enforces.
- `packs.json` in the rules folder records what was downloaded, when, and its SHA-256.

Licenses: each YARA Forge rule keeps its author's license (see the rule's `author` and `license_url` meta); some source repos set none.
MalwareBazaar data is CC0. `update` downloads straight to the user's PC, so Hexward doesn't redistribute the rules itself;
check licenses before bundling any pack into a release.

You can also drop your own files into the rules folder (or pass `--rules DIR`):
`*.yar`/`*.yara` rules (set `meta: name`, `severity`, `description` for best output), `*.txt`/`*.csv` hash lists, and `disabled.txt`.

## Measured on the development PC (YARA Forge core, 5,134 rules)

| Folder | Files | Time | Speed | False alarms |
|---|---|---|---|---|
| `C:\Windows\System32` | 22,548 (6.3 GB) | 24.8 s | 908 files/s | 0 |
| `C:\Program Files` + `(x86)` | 434,191 (77.3 GB) | 476 s | 912 files/s | 11 before fixes, 0 after |

The 11 were signed Adobe and Microsoft DLLs matched by two rules; both rules are now disabled and the signature check would have kept them in place anyway.
Loading 5,134 rules takes about 2 s (YARA-X compiles them to WebAssembly each time). Caching compiled rules didn't help, so the desktop app should load rules in the background.

## Quarantine

Files are encrypted (ChaCha20-Poly1305) into `%LOCALAPPDATA%\Hexward\Quarantine` so they can't run, then the original is removed.
If the original can't be removed (in use), nothing changes. The key sits beside the vault: this is containment, not secrecy.
`HEXWARD_HOME` moves all data elsewhere (the tests use it).

## Safety while developing

- Never put live malware on your main PC. Test detection with the harmless markers here, or in an isolated virtual machine.
- Never write the EICAR string to a file in this repo; other antivirus products will delete it. The engine builds it in memory.

## Build notes

- `rsa` is pinned to `0.10.0-rc.19` in `Cargo.lock`: `yara-x 1.23` doesn't build with later release candidates.
  If `cargo update` moves it, run `cargo update -p rsa --precise 0.10.0-rc.19`.
- `zip` is built with pure-Rust deflate only (`deflate-flate2-zlib-rs`), no C libraries.
- Tests: `cargo test --workspace`. Lints: `cargo clippy --workspace --all-targets`.

## Layout

```
crates/engine   scanning core: hashes, rules, heuristics, signatures, quarantine, startup items
crates/cli      the hexward command, including `update`
rules/          built-in test rules, test hash, disabled-rule list
```

## Next in phase 1

1. A false-alarm corpus in CI: scan large sets of clean software on every rule or engine change.
2. Catalog signatures, so Windows' own catalog-signed files count as signed too.
3. Machine-learning model for Windows programs (tract, trained on EMBER/SOREL-20M features).
4. Cleanup of startup entries and archive (.zip) scanning.
5. The Slint desktop app from the brand book.

License: GPL-3.0-or-later.
