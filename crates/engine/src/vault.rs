//! Quarantine. Files are encrypted with ChaCha20-Poly1305 so they can't run and
//! other scanners don't keep re-flagging them. The key lives beside the vault:
//! this is containment, not secrecy from someone who controls the PC.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EngineError, Result};

const MAGIC: &[u8; 4] = b"HWQ1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub detection: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: DateTime<Utc>,
}

pub struct Vault {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
}

fn err(msg: impl Into<String>) -> EngineError {
    EngineError::Vault(msg.into())
}

impl Vault {
    pub fn default_dir() -> PathBuf {
        crate::data_dir().join("Quarantine")
    }

    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("vault.key");
        let key: Key = match fs::read(&key_path) {
            Ok(bytes) if bytes.len() == 32 => *Key::from_slice(&bytes),
            Ok(_) => return Err(err("vault.key is damaged")),
            Err(_) => {
                let key = ChaCha20Poly1305::generate_key(&mut OsRng);
                fs::write(&key_path, key.as_slice())?;
                key
            }
        };
        Ok(Vault { dir, cipher: ChaCha20Poly1305::new(&key) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn blob(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.hwq"))
    }

    fn meta(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Encrypts the file into the vault, then removes the original.
    /// If the original can't be removed (in use), the vault copy is rolled back.
    pub fn quarantine(&self, path: &Path, detection: &str) -> Result<VaultEntry> {
        let data = fs::read(path)?;
        let mut idb = [0u8; 8];
        OsRng.fill_bytes(&mut idb);
        let id = hex::encode(idb);

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let sealed = self.cipher.encrypt(&nonce, data.as_slice()).map_err(|_| err("encryption failed"))?;
        let entry = VaultEntry {
            id: id.clone(),
            original_path: std::path::absolute(path)?,
            detection: detection.to_string(),
            sha256: hex::encode(Sha256::digest(&data)),
            size: data.len() as u64,
            quarantined_at: Utc::now(),
        };

        let tmp = self.dir.join(format!("{id}.tmp"));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(MAGIC)?;
            f.write_all(&nonce)?;
            f.write_all(&sealed)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.blob(&id))?;
        fs::write(self.meta(&id), serde_json::to_vec_pretty(&entry).map_err(|e| err(e.to_string()))?)?;

        let removed = (|| {
            let mut perms = fs::metadata(path)?.permissions();
            if perms.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                fs::set_permissions(path, perms)?;
            }
            fs::remove_file(path)
        })();
        if let Err(e) = removed {
            let _ = fs::remove_file(self.blob(&id));
            let _ = fs::remove_file(self.meta(&id));
            return Err(err(format!("couldn't remove {} ({e}). It may be in use; close it and try again", path.display())));
        }
        Ok(entry)
    }

    pub fn list(&self) -> Result<Vec<VaultEntry>> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "json")
                && let Ok(entry) = serde_json::from_slice::<VaultEntry>(&fs::read(&p)?)
            {
                out.push(entry);
            }
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.quarantined_at));
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<VaultEntry> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err(format!("no item with id {id}")));
        }
        let bytes = fs::read(self.meta(id)).map_err(|_| err(format!("no item with id {id}")))?;
        serde_json::from_slice(&bytes).map_err(|e| err(e.to_string()))
    }

    fn decrypt(&self, entry: &VaultEntry) -> Result<Vec<u8>> {
        let blob = fs::read(self.blob(&entry.id))?;
        if blob.len() < 16 || &blob[..4] != MAGIC {
            return Err(err("vault file is damaged"));
        }
        let data = self
            .cipher
            .decrypt(Nonce::from_slice(&blob[4..16]), &blob[16..])
            .map_err(|_| err("vault file is damaged or the key changed"))?;
        if hex::encode(Sha256::digest(&data)) != entry.sha256 {
            return Err(err("restored data doesn't match the original hash"));
        }
        Ok(data)
    }

    /// Writes the file back (to its original place unless `to` is given) and removes it from the vault.
    pub fn restore(&self, id: &str, to: Option<&Path>, overwrite: bool) -> Result<PathBuf> {
        let entry = self.get(id)?;
        let data = self.decrypt(&entry)?;
        let target = to.map(Path::to_path_buf).unwrap_or_else(|| entry.original_path.clone());
        if target.exists() && !overwrite {
            return Err(err(format!("{} already exists. Use --overwrite or --to", target.display())));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, data)?;
        self.delete(id)?;
        Ok(target)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let entry = self.get(id)?;
        let _ = fs::remove_file(self.blob(&entry.id));
        fs::remove_file(self.meta(&entry.id))?;
        Ok(())
    }

    /// Deletes items older than `days`. Returns how many were removed.
    pub fn purge_older_than(&self, days: i64) -> Result<usize> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let mut n = 0;
        for e in self.list()? {
            if e.quarantined_at < cutoff {
                self.delete(&e.id)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_restore_delete() {
        let home = tempfile::tempdir().unwrap();
        let vault = Vault::open(home.path().join("vault")).unwrap();
        let file = home.path().join("docs").join("bad.bin");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c").unwrap();

        let entry = vault.quarantine(&file, "Test/Any.HexwardMarker!a").unwrap();
        assert!(!file.exists(), "original is removed");
        let blob = fs::read(vault.blob(&entry.id)).unwrap();
        assert!(!blob.windows(7).any(|w| w == b"HEXWARD"), "stored encrypted");
        assert_eq!(vault.list().unwrap().len(), 1);

        // Restoring onto an existing file needs --overwrite.
        fs::write(&file, b"new file").unwrap();
        assert!(vault.restore(&entry.id, None, false).is_err());
        let back = vault.restore(&entry.id, None, true).unwrap();
        assert_eq!(fs::read(back).unwrap(), b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c");
        assert!(vault.list().unwrap().is_empty());

        let e2 = vault.quarantine(&file, "x/y.z!a").unwrap();
        vault.delete(&e2.id).unwrap();
        assert!(vault.list().unwrap().is_empty());
        assert!(vault.get("../../etc").is_err(), "ids are hex only");
    }

    #[test]
    fn key_persists_between_opens() {
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("a.bin");
        fs::write(&file, b"data").unwrap();
        let id = Vault::open(home.path().join("v")).unwrap().quarantine(&file, "x/y.z!a").unwrap().id;
        let again = Vault::open(home.path().join("v")).unwrap();
        assert_eq!(again.restore(&id, None, false).unwrap(), std::path::absolute(&file).unwrap());
    }
}
