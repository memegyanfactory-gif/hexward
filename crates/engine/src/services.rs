//! Running Windows services, read from the Service Control Manager. Gives the program path of
//! services that run as SYSTEM, which a normal user can't read from the process itself.

use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub display: String,
    pub pid: u32,
    pub exe: Option<PathBuf>,
}

/// Running Win32 services, keyed by process id (several services can share one process).
#[cfg(windows)]
pub fn running() -> HashMap<u32, Vec<Service>> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_QUERY_CONFIG, SERVICE_WIN32,
    };
    let wide = |p: *const u16| -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: the SCM returns NUL-terminated strings inside the buffer we own.
        unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    };
    let mut out: HashMap<u32, Vec<Service>> = HashMap::new();
    // SAFETY: handles are checked and closed; buffers are sized by the API's own size answers and
    // kept as u64 so the structures inside them are aligned.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return out;
        }
        let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, std::ptr::null_mut(), 0, &mut needed, &mut count, &mut resume, std::ptr::null());
        let mut buf = vec![0u64; (needed as usize + 4096) / 8 + 1];
        resume = 0;
        let ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut needed, &mut count, &mut resume, std::ptr::null());
        if ok != 0 {
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                let pid = it.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                let name = wide(it.lpServiceName);
                let display = wide(it.lpDisplayName);
                let mut exe = None;
                let svc = OpenServiceW(scm, it.lpServiceName, SERVICE_QUERY_CONFIG);
                if !svc.is_null() {
                    let mut need = 0u32;
                    QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut need);
                    let mut cfg = vec![0u64; need as usize / 8 + 1];
                    if need > 0 && QueryServiceConfigW(svc, cfg.as_mut_ptr().cast(), (cfg.len() * 8) as u32, &mut need) != 0 {
                        let c = &*(cfg.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                        exe = crate::startup::resolve_target(&wide(c.lpBinaryPathName));
                    }
                    CloseServiceHandle(svc);
                }
                out.entry(pid).or_default().push(Service { name, display, pid, exe });
            }
        }
        CloseServiceHandle(scm);
    }
    out
}

#[cfg(not(windows))]
pub fn running() -> HashMap<u32, Vec<Service>> {
    HashMap::new()
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn lists_running_services_with_paths() {
        let all = super::running();
        let svcs: Vec<_> = all.values().flatten().collect();
        assert!(svcs.len() > 10, "only {} services", svcs.len());
        assert!(svcs.iter().filter(|s| s.exe.is_some()).count() > 10);
        assert!(svcs.iter().any(|s| s.exe.as_ref().is_some_and(|e| e.to_string_lossy().to_lowercase().ends_with("svchost.exe"))));
    }
}
