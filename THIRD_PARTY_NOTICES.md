# Third-party notices

Hexward stands on other people's work. This file lists what it uses and under which terms. Hexward itself is
licensed GPL-3.0-or-later; the desktop app binary is distributed under GPL-3.0 because it uses Slint under its GPL option.

## Detection content (downloaded by the user at runtime, not bundled in releases)

| Source | What Hexward uses | Terms |
|---|---|---|
| [YARA Forge](https://github.com/YARAHQ/yara-forge) by Florian Roth and contributors | Curated, tested YARA rule packs (core / extended / full) | Each rule keeps its original author's licence; see the `author` and `license_url` meta in every rule. Some rules use the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License), which requires author attribution, which Hexward shows with every rule hit |
| [MalwareBazaar](https://bazaar.abuse.ch) by abuse.ch | SHA-256 hashes of recent malware samples (with the user's own free Auth-Key) | CC0 per abuse.ch; see the [abuse.ch terms](https://abuse.ch/terms-of-use/) |

## Specifications implemented from scratch

| Specification | Used for |
|---|---|
| [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/) (Microsoft) | Windows shortcut (.lnk) parser |
| [MS-OVBA](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/) (Microsoft) | VBA macro decompression and project directory; tested against the spec's own worked examples |
| [MS-CFB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/) (Microsoft) | Office compound documents (via the `cfb` crate) |
| [ECMA-119 / ISO 9660](https://ecma-international.org/publications-and-standards/standards/ecma-119/) | Disk image (.iso) reader |
| [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) | Standard antivirus test string |

## Fonts (bundled in the app, SIL Open Font License 1.1)

| Font | Designer | Licence file |
|---|---|---|
| [Pixelify Sans](https://github.com/eifetx/Pixelify-Sans) | The Pixelify Sans Project Authors | `crates/app/ui/fonts/OFL-PixelifySans.txt` |
| [Geist](https://github.com/vercel/geist-font) | The Geist Project Authors (Vercel) | `crates/app/ui/fonts/OFL-Geist.txt` |
| [Geist Mono](https://github.com/vercel/geist-font) | The Geist Project Authors (Vercel) | `crates/app/ui/fonts/OFL-GeistMono.txt` |

## Rust crates used directly

| Crate | Licence | Author |
|---|---|---|
| [anyhow](https://crates.io/crates/anyhow) | MIT OR Apache-2.0 | David Tolnay |
| [cfb](https://crates.io/crates/cfb) | MIT | Matthew D. Steele |
| [chacha20poly1305](https://crates.io/crates/chacha20poly1305) | Apache-2.0 OR MIT | RustCrypto Developers |
| [chrono](https://crates.io/crates/chrono) | MIT OR Apache-2.0 | — |
| [clap](https://crates.io/crates/clap) | MIT OR Apache-2.0 | — |
| [crossbeam-channel](https://crates.io/crates/crossbeam-channel) | MIT OR Apache-2.0 | — |
| [dirs](https://crates.io/crates/dirs) | MIT OR Apache-2.0 | Simon Ochsenreither |
| [ed25519-dalek](https://crates.io/crates/ed25519-dalek) | BSD-3-Clause | isis lovecruft |
| [embed-resource](https://crates.io/crates/embed-resource) | MIT | наб |
| [flate2](https://crates.io/crates/flate2) | MIT OR Apache-2.0 | Alex Crichton |
| [getrandom](https://crates.io/crates/getrandom) | MIT OR Apache-2.0 | The Rand Project Developers |
| [goblin](https://crates.io/crates/goblin) | MIT | m4b |
| [hex](https://crates.io/crates/hex) | MIT OR Apache-2.0 | KokaKiwi |
| [ico](https://crates.io/crates/ico) | MIT | Matthew D. Steele |
| [notify-rust](https://crates.io/crates/notify-rust) | MIT OR Apache-2.0 | Hendrik Sollich |
| [png](https://crates.io/crates/png) | MIT OR Apache-2.0 | The image-rs Developers |
| [rayon](https://crates.io/crates/rayon) | MIT OR Apache-2.0 | — |
| [rfd](https://crates.io/crates/rfd) | MIT | Poly |
| [serde](https://crates.io/crates/serde) | MIT OR Apache-2.0 | Erick Tryzelaar |
| [serde_json](https://crates.io/crates/serde_json) | MIT OR Apache-2.0 | — |
| [sevenz-rust2](https://crates.io/crates/sevenz-rust2) | Apache-2.0 | — |
| [sha2](https://crates.io/crates/sha2) | MIT OR Apache-2.0 | RustCrypto Developers |
| [slint](https://crates.io/crates/slint) | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | Slint Developers |
| [slint-build](https://crates.io/crates/slint-build) | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | Slint Developers |
| [sysinfo](https://crates.io/crates/sysinfo) | MIT | Guillaume Gomez |
| [tar](https://crates.io/crates/tar) | MIT OR Apache-2.0 | Alex Crichton |
| [tempfile](https://crates.io/crates/tempfile) | MIT OR Apache-2.0 | Steven Allen |
| [thiserror](https://crates.io/crates/thiserror) | MIT OR Apache-2.0 | David Tolnay |
| [tray-icon](https://crates.io/crates/tray-icon) | MIT OR Apache-2.0 | — |
| [ureq](https://crates.io/crates/ureq) | MIT OR Apache-2.0 | Martin Algesten |
| [walkdir](https://crates.io/crates/walkdir) | Unlicense/MIT | Andrew Gallant |
| [windows-sys](https://crates.io/crates/windows-sys) | MIT OR Apache-2.0 | Microsoft |
| [winreg](https://crates.io/crates/winreg) | MIT | Igor Shaula |
| [yara-x](https://crates.io/crates/yara-x) | BSD-3-Clause | Victor M. Alvarez |
| [zip](https://crates.io/crates/zip) | MIT | Mathijs van de Nes |

## All 848 crates in the build, by licence

Generated from `cargo metadata`. Run `cargo metadata --format-version 1` for the full list.

| Licence | Crates |
|---|---|
| MIT OR Apache-2.0 | 355 |
| MIT | 181 |
| Apache-2.0 OR MIT | 95 |
| MIT/Apache-2.0 | 30 |
| Apache-2.0 WITH LLVM-exception | 28 |
| Unicode-3.0 | 27 |
| Apache-2.0 | 19 |
| Zlib OR Apache-2.0 OR MIT | 15 |
| GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | 14 |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 14 |
| BSD-3-Clause | 12 |
| Unlicense OR MIT | 8 |
| MIT OR Apache-2.0 OR Zlib | 7 |
| Zlib | 4 |
| ISC | 4 |
| Apache-2.0/MIT | 3 |
| BSL-1.0 | 2 |
| MIT OR Apache-2.0 OR BSD-1-Clause | 2 |
| MIT OR Zlib OR Apache-2.0 | 2 |
| BSD-3-Clause OR Apache-2.0 | 2 |
| BSD-3-Clause OR MIT OR Apache-2.0 | 2 |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 2 |
| Unlicense/MIT | 2 |
| BSD-2-Clause OR Apache-2.0 OR MIT | 2 |
| 0BSD OR MIT OR Apache-2.0 | 1 |
| BSD-2-Clause | 1 |
| MIT / Apache-2.0 | 1 |
| CC0-1.0 OR MIT-0 OR Apache-2.0 | 1 |
| Apache-2.0 AND MIT | 1 |
| Apache-2.0 / MIT | 1 |
| CC0-1.0 OR Apache-2.0 | 1 |
| Unlicense | 1 |
| bzip2-1.0.6 | 1 |
| BSD-2-Clause OR MIT OR Apache-2.0 | 1 |
| MPL-2.0 | 1 |
| CC0-1.0 OR MIT-0 | 1 |
| Apache-2.0 AND ISC | 1 |
| Apache-2.0 OR ISC OR MIT | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| CDLA-Permissive-2.0 | 1 |

## Inspiration and benchmarks (no code used)

- [KicomAV](https://github.com/hanul93/kicomav) by Kei Choi (MIT): its list of supported file formats shaped Hexward's format roadmap.
  No KicomAV code is included; Hexward's parsers are written from the specifications above.
- [ClamAV](https://www.clamav.net) (GPL-2.0): detection-rate benchmark reference (Splunk's 2022 study). No ClamAV code is included.
- Research sources for the strategy are listed in [docs/STRATEGY.md](docs/STRATEGY.md).
