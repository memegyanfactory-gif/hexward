//! Minimal Windows clipboard access for the ClickFix shield.
//! Reading happens on the shield thread; writing happens on the UI thread with a message-only
//! owner window, because other programs send the clipboard owner messages and wait for a reply,
//! and the UI thread is always pumping messages.

#[cfg(windows)]
mod imp {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::UI::WindowsAndMessaging::{CreateWindowExW, GetForegroundWindow, GetWindowThreadProcessId, HWND_MESSAGE};

    const CF_UNICODETEXT: u32 = 13;
    const MAX_CHARS: usize = 64 * 1024;

    pub fn sequence() -> u32 {
        // SAFETY: no arguments, no preconditions.
        unsafe { GetClipboardSequenceNumber() }
    }

    pub fn read_text() -> Option<String> {
        // SAFETY: the clipboard is opened and always closed; the locked buffer is only read up to
        // its NUL terminator (capped) and unlocked before closing.
        unsafe {
            if OpenClipboard(null_mut()) == 0 {
                return None;
            }
            let h = GetClipboardData(CF_UNICODETEXT);
            let text = if h.is_null() {
                None
            } else {
                let p = GlobalLock(h) as *const u16;
                if p.is_null() {
                    None
                } else {
                    let mut n = 0;
                    while n < MAX_CHARS && *p.add(n) != 0 {
                        n += 1;
                    }
                    let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                    GlobalUnlock(h);
                    Some(s)
                }
            };
            CloseClipboard();
            text
        }
    }

    /// A hidden, message-only window to own clipboard data we write. Create it on the UI thread.
    pub fn owner_window() -> HWND {
        let class: Vec<u16> = "STATIC".encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `class` is a valid NUL-terminated string; all other pointers are null as allowed.
        unsafe { CreateWindowExW(0, class.as_ptr(), std::ptr::null(), 0, 0, 0, 0, 0, HWND_MESSAGE, null_mut(), null_mut(), std::ptr::null()) }
    }

    pub fn write_text(owner: HWND, text: &str) -> bool {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the clipboard is opened and always closed; the global block is sized for `wide`,
        // filled while locked, and handed to the clipboard (which then owns it) only on success.
        unsafe {
            if OpenClipboard(owner) == 0 {
                return false;
            }
            EmptyClipboard();
            let h = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2);
            let mut ok = false;
            if !h.is_null() {
                let p = GlobalLock(h) as *mut u16;
                if !p.is_null() {
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
                    GlobalUnlock(h);
                    ok = !SetClipboardData(CF_UNICODETEXT, h).is_null();
                }
            }
            CloseClipboard();
            ok
        }
    }

    /// Process id of the window the user is looking at (where a copy most likely came from).
    pub fn foreground_pid() -> u32 {
        let mut pid = 0u32;
        // SAFETY: GetForegroundWindow may return null, which GetWindowThreadProcessId tolerates.
        unsafe { GetWindowThreadProcessId(GetForegroundWindow(), &mut pid) };
        pid
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(not(windows))]
mod imp_other {
    pub fn sequence() -> u32 {
        0
    }
    pub fn read_text() -> Option<String> {
        None
    }
    pub fn foreground_pid() -> u32 {
        0
    }
}

#[cfg(not(windows))]
pub use imp_other::*;

/// What replaces a ClickFix command on the clipboard: harmless if pasted anywhere.
pub const NEUTRALIZED: &str = "Hexward blocked this paste. A website copied a hidden command that downloads and runs a program, and asked you to paste it. Close that page; real sites never ask you to paste commands.";
