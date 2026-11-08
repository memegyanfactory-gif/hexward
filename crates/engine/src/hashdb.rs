use std::collections::HashMap;
use std::sync::Arc;

/// SHA-256 → detection name.
#[derive(Default)]
pub struct HashDb {
    map: HashMap<[u8; 32], Arc<str>>,
}

const DEFAULT_NAME: &str = "Malware/Any.KnownHash!h";

impl HashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, hash: [u8; 32], name: &str) {
        self.map.insert(hash, Arc::from(name));
    }

    pub fn lookup(&self, hash: &[u8; 32]) -> Option<&str> {
        self.map.get(hash).map(|s| &**s)
    }

    /// Loads a hash list and returns how many entries were added.
    ///
    /// Accepts `sha256[,Detection/Name]` lines, and CSV exports where the first
    /// 64-character hex field is the SHA-256. `#` starts a comment line.
    pub fn load_str(&mut self, text: &str) -> usize {
        let mut added = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line
                .split([',', ';', '\t'])
                .map(|f| f.trim().trim_matches('"').trim())
                .collect();
            let Some(pos) = fields.iter().position(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit())) else {
                continue;
            };
            let mut hash = [0u8; 32];
            if hex::decode_to_slice(fields[pos], &mut hash).is_err() {
                continue;
            }
            // A name is only taken from our own format: the field right after the hash, shaped like Type/Platform.Family!v.
            let name = fields
                .get(pos + 1)
                .filter(|n| n.contains('/') && !n.contains(' '))
                .copied()
                .unwrap_or(DEFAULT_NAME);
            self.insert(hash, name);
            added += 1;
        }
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_plain_and_csv_lines() {
        let mut db = HashDb::new();
        let text = "# comment\n\
            940a2e4e44de86cf81f860ffc06fcac2b1767114f25ad3551be2e4fed8ba24dd,Test/Any.HashMarker!a\n\
            \"2026-11-01 10:00:00\",\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"exe\"\n\
            not a hash line\n";
        assert_eq!(db.load_str(text), 2);
        let mut h = [0u8; 32];
        hex::decode_to_slice("940a2e4e44de86cf81f860ffc06fcac2b1767114f25ad3551be2e4fed8ba24dd", &mut h).unwrap();
        assert_eq!(db.lookup(&h), Some("Test/Any.HashMarker!a"));
        assert_eq!(db.lookup(&[0xAA; 32]), Some(DEFAULT_NAME));
    }
}
