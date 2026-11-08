//! Digital-signature (Authenticode) check.
//!
//! Used to stop pattern rules from quarantining signed software on their own: a
//! signed file with a rule hit is still reported, but only a hash match moves it.
//! Embedded signatures only (catalog-signed Windows files report `false`), and no
//! network access: revocation isn't checked, so a scan never waits on the internet.

use std::path::Path;

#[cfg(windows)]
pub fn has_valid_signature(path: &Path) -> bool {
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
    unsafe {
        let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast::<c_void>());
        status == 0
    }
}

#[cfg(not(windows))]
pub fn has_valid_signature(_path: &Path) -> bool {
    false
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
}
