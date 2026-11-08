//! Reads a program's version resource: company name and description ("Google LLC",
//! "Google Chrome"). Used to show who made a running program or startup entry.

use std::path::Path;

#[cfg(windows)]
pub fn version_string(path: &Path, key: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    // SAFETY: buffers are sized by the API's own size query; VerQueryValueW returns pointers into
    // `buf`, which outlives every read, and lengths are checked before slicing.
    unsafe {
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle);
        if size == 0 || size > 4 * 1024 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, buf.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let mut langs: Vec<(u16, u16)> = Vec::new();
        let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if VerQueryValueW(buf.as_ptr().cast(), w("\\VarFileInfo\\Translation").as_ptr(), &mut p, &mut len) != 0 && !p.is_null() {
            let pairs = std::slice::from_raw_parts(p as *const u16, (len as usize / 2).min(32));
            langs.extend(pairs.as_chunks::<2>().0.iter().map(|c| (c[0], c[1])));
        }
        langs.extend([(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]);
        for (lang, cp) in langs {
            let q = w(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\{key}"));
            let mut v: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut n = 0u32;
            if VerQueryValueW(buf.as_ptr().cast(), q.as_ptr(), &mut v, &mut n) != 0 && !v.is_null() && n > 1 {
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(v as *const u16, n as usize - 1)).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
        None
    }
}

#[cfg(not(windows))]
pub fn version_string(_path: &Path, _key: &str) -> Option<String> {
    None
}

pub fn company(path: &Path) -> Option<String> {
    version_string(path, "CompanyName")
}

pub fn description(path: &Path) -> Option<String> {
    version_string(path, "FileDescription")
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn reads_microsoft_metadata() {
        let notepad = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        let company = super::company(notepad).expect("notepad has a company name");
        assert!(company.contains("Microsoft"), "{company}");
        assert!(super::company(std::path::Path::new(r"C:\definitely\missing.exe")).is_none());
    }
}
