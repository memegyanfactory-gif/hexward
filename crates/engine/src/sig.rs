//! Digital-signature (Authenticode) check.
//!
//! Used to stop pattern rules from quarantining signed software on their own: a
//! signed file with a rule hit is still reported, but only a hash match moves it.
//! Embedded signatures and Windows catalogs (most of Windows itself is catalog-signed), and no
//! network access: revocation isn't checked, so a scan never waits on the internet.

use std::path::Path;

#[cfg(windows)]
pub fn has_valid_signature(path: &Path) -> bool {
    verify_embedded(path).0
}

/// Who signed the file (the signing certificate's display name), when it has a valid embedded signature.
#[cfg(windows)]
pub fn signer_name(path: &Path) -> Option<String> {
    verify_embedded(path).1
}

#[cfg(not(windows))]
pub fn signer_name(_path: &Path) -> Option<String> {
    None
}

#[cfg(windows)]
fn verify_embedded(path: &Path) -> (bool, Option<String>) {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: null_mut(),
        pgKnownSubject: null_mut(),
    };
    // SAFETY: WINTRUST_DATA is a plain C struct; all-zero is a valid starting state.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data`, `file`, `wide` and `action` all outlive both calls; the second call
    // releases the state the first one allocated.
    // The signer's name is read from the verified state before it's released.
    unsafe {
        use windows_sys::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
        use windows_sys::Win32::Security::WinTrust::{WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData};
        let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
        let mut name = None;
        if status == 0 {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            let sgnr = if prov.is_null() { null_mut() } else { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
            if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                let cert = (*(*sgnr).pasCertChain).pCert;
                if !cert.is_null() {
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
                    if n > 1 {
                        name = Some(String::from_utf16_lossy(&buf[..n as usize - 1]));
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
        (status == 0, name)
    }
}

#[cfg(all(test, windows))]
mod signer_tests {
    #[test]
    fn reads_the_signer_of_a_signed_windows_file() {
        let sys = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:Windows".into())).join("System32");
        let found = std::fs::read_dir(&sys)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")))
            .take(400)
            .find_map(|p| super::signer_name(&p));
        assert!(found.is_some_and(|n| n.contains("Microsoft")), "no embedded-signed Microsoft program found in System32");
    }
}

#[cfg(not(windows))]
pub fn has_valid_signature(_path: &Path) -> bool {
    false
}

/// Signed through a Windows security catalog (how most of Windows' own files are signed),
/// checked against the catalogs installed on this PC. No network access.
#[cfg(windows)]
pub fn has_valid_catalog_signature(path: &Path) -> bool {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
        CryptCATCatalogInfoFromContext,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
    };
    let Ok(file) = std::fs::File::open(path) else { return false };
    let handle = file.as_raw_handle();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let sha256: Vec<u16> = "SHA256".encode_utf16().chain(std::iter::once(0)).collect();
    // Newer catalogs use SHA-256 hashes, older ones SHA-1 (the default when no algorithm is named).
    for alg in [sha256.as_ptr(), null()] {
        // SAFETY: every handle acquired here is released before the loop moves on; buffers are
        // sized by the API's own size query and outlive the calls that read them.
        unsafe {
            let mut admin: isize = 0;
            if CryptCATAdminAcquireContext2(&mut admin, null(), alg, null(), 0) == 0 {
                continue;
            }
            let mut cb = 0u32;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle as _, &mut cb, null_mut(), 0);
            let mut hash = vec![0u8; cb.max(1) as usize];
            let mut ok = false;
            if cb > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, handle as _, &mut cb, hash.as_mut_ptr(), 0) != 0 {
                let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), cb, 0, null_mut());
                if cat != 0 {
                    let mut info: CATALOG_INFO = std::mem::zeroed();
                    info.cbStruct = size_of::<CATALOG_INFO>() as u32;
                    if CryptCATCatalogInfoFromContext(cat, &mut info, 0) != 0 {
                        let tag: Vec<u16> = hash[..cb as usize].iter().map(|b| format!("{b:02X}")).collect::<String>().encode_utf16().chain(std::iter::once(0)).collect();
                        let mut ci = WINTRUST_CATALOG_INFO {
                            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                            dwCatalogVersion: 0,
                            pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                            pcwszMemberTag: tag.as_ptr(),
                            pcwszMemberFilePath: wide.as_ptr(),
                            hMemberFile: handle as _,
                            pbCalculatedFileHash: hash.as_mut_ptr(),
                            cbCalculatedFileHash: cb,
                            pcCatalogContext: null_mut(),
                            hCatAdmin: admin,
                        };
                        let mut data: WINTRUST_DATA = std::mem::zeroed();
                        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
                        data.dwUIChoice = WTD_UI_NONE;
                        data.fdwRevocationChecks = WTD_REVOKE_NONE;
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.Anonymous.pCatalog = &mut ci;
                        data.dwStateAction = WTD_STATEACTION_VERIFY;
                        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
                        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
                        data.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
                        ok = status == 0;
                    }
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                }
            }
            CryptCATAdminReleaseContext(admin, 0);
            if ok {
                return true;
            }
        }
    }
    false
}

#[cfg(not(windows))]
pub fn has_valid_catalog_signature(_path: &Path) -> bool {
    false
}

/// Signed either way: embedded Authenticode, or through a Windows catalog.
pub fn is_signed(path: &Path) -> bool {
    has_valid_signature(path) || has_valid_catalog_signature(path)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn unsigned_and_tampered_files_fail() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.exe");
        std::fs::write(&plain, b"MZ not signed").unwrap();
        assert!(!has_valid_signature(&plain));
        assert!(!has_valid_signature(&dir.path().join("missing.dll")));

        // Find any embedded-signed file on this machine; flip one byte and the signature must break.
        let candidates = [
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\ucrt\ucrtbased.dll",
            r"C:\Program Files\Git\git-bash.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ];
        if let Some(signed) = candidates.iter().map(Path::new).find(|p| p.is_file() && has_valid_signature(p)) {
            let mut bytes = std::fs::read(signed).unwrap();
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0xFF;
            let copy = dir.path().join("tampered.dll");
            std::fs::write(&copy, bytes).unwrap();
            assert!(!has_valid_signature(&copy), "a modified copy of {} must not verify", signed.display());
        }
    }

    #[test]
    fn catalog_signed_windows_files_verify() {
        // notepad.exe and most of System32 are signed through catalogs, not embedded signatures.
        let n = Path::new(r"C:\Windows\System32\kernel32.dll");
        assert!(is_signed(n));
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("k.dll");
        let mut bytes = std::fs::read(n).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&copy, bytes).unwrap();
        assert!(!has_valid_catalog_signature(&copy), "a modified copy isn't in any catalog");
    }
}
