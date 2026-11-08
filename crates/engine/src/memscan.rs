//! Memory scanning: reads the executable memory of running programs and checks it with the
//! YARA rules. Malware that never touches the disk (loaded straight into memory, injected into
//! another process, or unpacked at run time) is only visible here.
//!
//! What's read: committed executable memory that wasn't loaded from a file (code loaded from a
//! program or DLL on disk is what file scans cover), up to 64 MB per region and 192 MB per process. A whole Windows program sitting in private executable memory, not
//! loaded from a file, is reported too: that's what process hollowing and reflective loading
//! leave behind.

use crate::detect::{Detection, Severity, Source};
use crate::scan::Engine;

const MAX_REGION: usize = 64 * 1024 * 1024;
const MAX_PROCESS: usize = 192 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MemoryFinding {
    pub pid: u32,
    pub name: String,
    pub address: usize,
    pub detections: Vec<Detection>,
}

/// Processes Hexward doesn't read: itself, and security software that holds signatures in memory.
const SKIP: &[&str] = &["msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "hexward-app.exe", "hexward.exe", "system", "registry", "secure system", "memory compression"];

/// Scans one process. Errors when Windows won't let us read it (protected or elevated processes).
#[cfg(windows)]
pub fn scan_process(engine: &Engine, pid: u32) -> Result<Vec<(usize, Vec<Detection>)>, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    // SAFETY: the handle is checked and closed; every read goes into our own buffer and is
    // bounded by the region size Windows reports.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if h.is_null() {
            return Err("Windows didn't allow reading this program's memory (it may be protected or run as administrator).".into());
        }
        let mut found = Vec::new();
        let mut scanner = engine.rules().scanner();
        let mut addr: usize = 0;
        let mut total = 0usize;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        while VirtualQueryEx(h, addr as *const _, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            let next = base.saturating_add(size);
            if next <= addr {
                break;
            }
            addr = next;
            let exec = mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0;
            // Code loaded from a file (MEM_IMAGE) is what file scans already cover; what only lives in
            // memory (private or mapped executable pages: unpacked, injected, JIT-written) is the point here.
            if mbi.State != MEM_COMMIT || !exec || mbi.Type == MEM_IMAGE || mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0 || size == 0 {
                continue;
            }
            let len = size.min(MAX_REGION);
            if total + len > MAX_PROCESS {
                break;
            }
            let mut buf = vec![0u8; len];
            let mut read = 0usize;
            if ReadProcessMemory(h, base as *const _, buf.as_mut_ptr().cast(), len, &mut read) == 0 || read == 0 {
                continue;
            }
            buf.truncate(read);
            total += read;
            let (_, dets) = engine.scan_bytes(&mut scanner, std::path::Path::new("memory"), &buf);
            // Only rule and hash matches count here; file-name checks mean nothing for memory.
            let mut dets: Vec<Detection> = dets.into_iter().filter(|d| matches!(d.source, Source::Rule | Source::Hash)).collect();
            let private_pe = mbi.Type == MEM_PRIVATE && buf.starts_with(b"MZ") && buf.len() > 0x200 && {
                let pe = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
                buf.get(pe..pe + 4) == Some(b"PE\0\0")
            };
            if private_pe {
                dets.push(Detection::new(
                    "Suspicious/Win.InjectedImage!mem",
                    Severity::Medium,
                    Source::Heuristic,
                    if mbi.Protect & PAGE_EXECUTE_READWRITE != 0 {
                        "A whole Windows program is sitting in this process's writable, runnable memory without coming from a file: a sign of code injection or process hollowing."
                    } else {
                        "A whole Windows program is loaded in this process's memory without coming from a file: a sign of code injection or reflective loading."
                    },
                ));
            }
            if !dets.is_empty() {
                found.push((base, dets));
            }
        }
        CloseHandle(h);
        Ok(found)
    }
}

#[cfg(not(windows))]
pub fn scan_process(_engine: &Engine, _pid: u32) -> Result<Vec<(usize, Vec<Detection>)>, String> {
    Err("Memory scanning is only available on Windows.".into())
}

/// Scans every running program it's allowed to read. Returns findings and how many were read.
pub fn scan_all(engine: &Engine) -> (Vec<MemoryFinding>, usize) {
    let Ok(mut sys) = sysinfo::System::new() else { return (Vec::new(), 0) };
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, true, sysinfo::ProcessRefreshKind::nothing());
    let me = std::process::id();
    let mut out = Vec::new();
    let mut read = 0;
    for (pid, p) in sys.processes() {
        let name = p.name().to_string_lossy().into_owned();
        if pid.as_u32() == me || pid.as_u32() <= 4 || SKIP.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        if let Ok(hits) = scan_process(engine, pid.as_u32()) {
            read += 1;
            for (address, detections) in hits {
                out.push(MemoryFinding { pid: pid.as_u32(), name: name.clone(), address, detections });
            }
        }
    }
    (out, read)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn finds_a_marker_in_a_running_process() {
        let engine = Engine::load(&[]).unwrap();
        // Our own test process: the built-in rules' harmless marker, placed in executable memory.
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree, MEM_RELEASE};
        let marker = b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c in executable memory";
        unsafe {
            let p = VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;
            assert!(!p.is_null());
            std::ptr::copy_nonoverlapping(marker.as_ptr(), p, marker.len());
            let hits = scan_process(&engine, std::process::id()).unwrap();
            assert!(hits.iter().any(|(_, d)| d.iter().any(|x| x.source == Source::Rule)), "{hits:?}");
            VirtualFree(p.cast(), 0, MEM_RELEASE);
        }
    }

    /// Reads every running program (slow in debug builds): cargo test -- --ignored
    #[test]
    #[ignore]
    fn reads_other_processes_without_error() {
        let engine = Engine::load(&[]).unwrap();
        let (_, read) = scan_all(&engine);
        assert!(read > 0);
    }
}
