//! A program's own icon, read from its .exe (the Chrome logo for chrome.exe, and so on).
//! Used by the task manager, the cleaner's browser list and the startup manager.

use std::path::Path;

/// 32×32 RGBA pixels of the file's icon, as Explorer shows it.
#[cfg(windows)]
pub fn file_icon(path: &Path) -> Option<(u32, u32, Vec<u8>)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Graphics::Gdi::{BI_RGB, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits, ReleaseDC};
    use windows_sys::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGetFileInfoW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: every handle the shell and GDI give us is released before returning; the pixel
    // buffers are sized for the 32-bit DIB we ask GetDIBits to write.
    unsafe {
        let mut info: SHFILEINFOW = std::mem::zeroed();
        let ok = SHGetFileInfoW(wide.as_ptr(), 0, &mut info, std::mem::size_of::<SHFILEINFOW>() as u32, SHGFI_ICON | SHGFI_LARGEICON);
        if ok == 0 || info.hIcon.is_null() {
            return None;
        }
        let hicon = info.hIcon;
        let mut ii: ICONINFO = std::mem::zeroed();
        if GetIconInfo(hicon, &mut ii) == 0 {
            DestroyIcon(hicon);
            return None;
        }
        let read = |bmp, w: i32, h: i32| -> Option<Vec<u8>> {
            let mut bi: BITMAPINFO = std::mem::zeroed();
            bi.bmiHeader = BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down rows
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let mut px = vec![0u8; (w * h * 4) as usize];
            let dc = GetDC(std::ptr::null_mut());
            let lines = GetDIBits(dc, bmp, 0, h as u32, px.as_mut_ptr().cast(), &mut bi, DIB_RGB_COLORS);
            ReleaseDC(std::ptr::null_mut(), dc);
            (lines == h).then_some(px)
        };
        let (w, h) = (32, 32);
        let color = if ii.hbmColor.is_null() { None } else { read(ii.hbmColor, w, h) };
        let mask = if ii.hbmMask.is_null() { None } else { read(ii.hbmMask, w, h) };
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor);
        }
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask);
        }
        DestroyIcon(hicon);
        let mut px = color?;
        let has_alpha = px.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
        for (i, p) in px.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            p.swap(0, 2); // BGRA → RGBA
            if !has_alpha {
                // Old icons without an alpha channel: the AND mask says which pixels are see-through.
                let transparent = mask.as_ref().is_some_and(|m| m[i * 4] != 0);
                p[3] = if transparent { 0 } else { 255 };
            }
        }
        Some((w as u32, h as u32, px))
    }
}

/// The shell's icon lookup wants COM on the calling thread.
#[cfg(windows)]
pub fn init_thread() {
    use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
    // SAFETY: plain per-thread initialization; called once at the start of a worker thread.
    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }
}

#[cfg(not(windows))]
pub fn init_thread() {}

#[cfg(not(windows))]
pub fn file_icon(_path: &Path) -> Option<(u32, u32, Vec<u8>)> {
    None
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn notepad_has_a_visible_icon() {
        let (w, h, px) = super::file_icon(std::path::Path::new(r"C:\Windows\System32\notepad.exe")).expect("icon");
        assert_eq!((w, h, px.len()), (32, 32, 32 * 32 * 4));
        assert!(px.as_chunks::<4>().0.iter().filter(|p| p[3] > 0).count() > 100);
    }
}
