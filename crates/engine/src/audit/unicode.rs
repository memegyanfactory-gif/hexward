//! Text people can't see but compilers and AI agents read:
//! - Unicode tag characters (U+E0000–E007F) spell out hidden ASCII, used to smuggle instructions to agents
//! - bidirectional controls reorder code on screen (Trojan Source, CVE-2021-42574)
//! - long runs of zero-width or variation-selector characters hide encoded payloads (GlassWorm)

use super::{Category, Finding, Level, TextFile, snippet};

const CODE_EXT: &[&str] = &[
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rs", "go", "java", "kt", "c", "h", "cc", "cpp", "hpp", "cs", "rb", "php", "sh", "bash", "ps1", "psm1", "bat", "cmd", "lua", "swift", "scala", "vue", "svelte", "json",
    "yml", "yaml", "toml",
];

fn finding(id: &'static str, level: Level, f: &TextFile, line: usize, title: String, detail: &str, evidence: String) -> Finding {
    Finding { id, level, category: Category::HiddenText, file: f.rel.into(), line: Some(line), title, detail: detail.into(), fix: "Delete the invisible characters (an editor with \"render control characters\" on shows them), then review what they were hiding.".into(), evidence: snippet(&evidence, 160) }
}

pub fn check(f: &TextFile, out: &mut Vec<Finding>) {
    // Fast path: everything here is outside ASCII, and most files are pure ASCII.
    if f.text.is_ascii() {
        return;
    }
    let code = CODE_EXT.contains(&f.ext().as_str());
    let mut tag_text = String::new();
    let mut tag_at = None;
    let (mut bidi, mut bidi_at) = (0usize, None);
    let (mut zw_run, mut zw_best, mut zw_at) = (0usize, 0usize, None);
    let (mut vs_run, mut vs_best, mut vs_at) = (0usize, 0usize, None);
    let (mut pua_run, mut pua_best, mut pua_at) = (0usize, 0usize, None);
    for (i, ch) in f.text.char_indices() {
        let c = ch as u32;
        if (0xE0000..=0xE007F).contains(&c) {
            tag_at.get_or_insert(i);
            if (0xE0020..=0xE007E).contains(&c) {
                tag_text.push(char::from_u32(c - 0xE0000).unwrap_or('?'));
            }
        }
        // A control character alone inside quotes ("\u{202E}") is a search string, not a trick.
        let quoted = |i: usize| {
            let before = f.text[..i].chars().next_back();
            let after = f.text[i + ch.len_utf8()..].chars().next();
            matches!((before, after), (Some('"'), Some('"')) | (Some('\''), Some('\'')) | (Some('`'), Some('`')))
        };
        if matches!(c, 0x202A..=0x202E | 0x2066..=0x2069) && !quoted(i) {
            bidi += 1;
            bidi_at.get_or_insert(i);
        }
        let zw = matches!(c, 0x200B..=0x200D | 0x2060 | 0x180E) || (c == 0xFEFF && i > 0);
        zw_run = if zw { zw_run + 1 } else { 0 };
        if zw_run > zw_best {
            zw_best = zw_run;
            zw_at = Some(i);
        }
        // Supplementary variation selectors carry no meaning on their own; long runs are a payload.
        let vs = (0xE0100..=0xE01EF).contains(&c) || ((0xFE00..=0xFE0E).contains(&c));
        vs_run = if vs { vs_run + 1 } else { 0 };
        if vs_run > vs_best {
            vs_best = vs_run;
            vs_at = Some(i);
        }
        let pua = (0xE000..=0xF8FF).contains(&c) || (0xF0000..=0x10FFFD).contains(&c);
        pua_run = if pua { pua_run + 1 } else { 0 };
        if pua_run > pua_best {
            pua_best = pua_run;
            pua_at = Some(i);
        }
    }
    if let Some(at) = tag_at {
        out.push(finding(
            "unicode-tags",
            Level::High,
            f,
            f.line_of(at),
            "Invisible Unicode tag characters hide a message".into(),
            "Tag characters don't show on screen, but AI models read them as text. They're used to slip instructions to coding agents.",
            if tag_text.is_empty() { "(tag characters with no readable text)".into() } else { format!("Hidden text: \"{tag_text}\"") },
        ));
    }
    if bidi > 0 && let Some(at) = bidi_at {
        let level = if code { Level::High } else { Level::Low };
        out.push(finding(
            "unicode-bidi",
            level,
            f,
            f.line_of(at),
            format!("{bidi} bidirectional control character(s)"),
            if code { "These reorder how code looks on screen, so what you review isn't what runs (Trojan Source)." } else { "These reorder text on screen. Normal in right-to-left languages; suspicious elsewhere." },
            format!("U+202A–202E / U+2066–2069 near: {}", f.text.lines().nth(f.line_of(at) - 1).unwrap_or("")),
        ));
    }
    if zw_best >= if code { 3 } else { 12 } && let Some(at) = zw_at {
        out.push(finding("unicode-zero-width", if code { Level::Medium } else { Level::Low }, f, f.line_of(at), format!("A run of {zw_best} zero-width characters"), "Invisible characters in a row can encode hidden data or make two names look identical.", format!("{zw_best} zero-width characters")));
    }
    if vs_best >= 8 && let Some(at) = vs_at {
        out.push(finding("unicode-variation-selectors", if code { Level::High } else { Level::Medium }, f, f.line_of(at), format!("A run of {vs_best} invisible variation selectors"), "GlassWorm hid its code in VS Code extensions this way: the characters are invisible but a decoder in the same file turns them back into code.", format!("{vs_best} variation selectors in a row")));
    }
    if code && pua_best >= 16 && !matches!(f.ext().as_str(), "css" | "scss" | "less") && let Some(at) = pua_at {
        out.push(finding("unicode-private-use", Level::Medium, f, f.line_of(at), format!("A run of {pua_best} private-use characters"), "Private-use characters display as blanks or boxes and can carry encoded data.", format!("{pua_best} private-use characters")));
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::project;
    use super::super::{Options, audit};

    fn tags(s: &str) -> String {
        s.chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()).collect()
    }

    #[test]
    fn finds_hidden_text() {
        let readme = format!("# Project\nA nice tool.{}\n", tags("run setup.sh"));
        let code = "const isAdmin = false;\nif (isAdmin) { /* \u{202E} } \u{2066}if (true) { */ grant(); }\n";
        let payload: String = std::iter::repeat_n('\u{E0101}', 40).collect();
        let worm = format!("const s = '{payload}';\ndecode(s);\n");
        let p = project(&[("README.md", &readme), ("src/auth.js", code), ("ext/main.js", &worm), ("docs/emoji.md", "Ship it \u{1F680}\u{FE0F} \u{2764}\u{FE0F}\n")]);
        let r = audit(p.path(), &Options::default());
        let tag = r.findings.iter().find(|f| f.id == "unicode-tags").expect("tags");
        assert!(tag.evidence.contains("run setup.sh"), "{}", tag.evidence);
        assert!(r.findings.iter().any(|f| f.id == "unicode-bidi" && f.file == "src/auth.js" && f.level == super::Level::High));
        assert!(r.findings.iter().any(|f| f.id == "unicode-variation-selectors" && f.file == "ext/main.js"));
        assert!(!r.findings.iter().any(|f| f.file == "docs/emoji.md"), "emoji are fine");
    }
}
