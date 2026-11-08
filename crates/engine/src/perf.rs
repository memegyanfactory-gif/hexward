//! Staying out of the way: background CPU and disk priority for scanning threads, and
//! "quiet mode" detection (a game or video in full screen, a presentation, or Windows' own
//! do-not-disturb), when notifications wait and scheduled work pauses.

/// Puts the calling thread in background mode: low CPU priority and low disk I/O priority,
/// so a scan never makes a game stutter or a file copy crawl.
#[cfg(windows)]
pub fn background_thread() {
    use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN};
    // SAFETY: changes only this thread's own scheduling class.
    unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}

#[cfg(not(windows))]
pub fn background_thread() {}

/// Why it's quiet time, if it is: full-screen game or video, presentation mode, or Focus.
#[cfg(windows)]
pub fn quiet_reason() -> Option<&'static str> {
    use windows_sys::Win32::UI::Shell::{QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_QUIET_TIME, QUNS_RUNNING_D3D_FULL_SCREEN, SHQueryUserNotificationState};
    let mut state = 0;
    // SAFETY: writes one integer.
    if unsafe { SHQueryUserNotificationState(&mut state) } != 0 {
        return None;
    }
    match state {
        QUNS_RUNNING_D3D_FULL_SCREEN => Some("a full-screen game"),
        QUNS_BUSY => Some("a full-screen app"),
        QUNS_PRESENTATION_MODE => Some("a presentation"),
        QUNS_QUIET_TIME => Some("Windows quiet time"),
        _ => None,
    }
}

#[cfg(not(windows))]
pub fn quiet_reason() -> Option<&'static str> {
    None
}

/// Is the PC running on battery?
#[cfg(windows)]
pub fn on_battery() -> bool {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    // SAFETY: fills one plain struct.
    unsafe {
        let mut s: SYSTEM_POWER_STATUS = std::mem::zeroed();
        GetSystemPowerStatus(&mut s) != 0 && s.ACLineStatus == 0
    }
}

#[cfg(not(windows))]
pub fn on_battery() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn queries_do_not_fail() {
        super::background_thread();
        let _ = super::quiet_reason();
        let _ = super::on_battery();
    }
}
