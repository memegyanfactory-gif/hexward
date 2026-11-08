//! `hexward-app --shots <dir>`: renders every screen to PNG with the software renderer and
//! sample data, so the design can be checked (and documented) without a desktop session.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use slint::platform::software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::*;

struct ShotPlatform {
    window: Rc<MinimalSoftwareWindow>,
    clock: Rc<Cell<Duration>>,
}

impl Platform for ShotPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }
    fn duration_since_start(&self) -> Duration {
        self.clock.get()
    }
}

const W: u32 = 1240;
const H: u32 = 800;

fn m<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn s(x: &str) -> SharedString {
    x.into()
}

fn sample(ui: &AppWindow) {
    ui.set_version(s(env!("CARGO_PKG_VERSION")));
    ui.set_engine_ready(true);
    ui.set_engine_status(s("5,134 rules ready"));
    ui.set_rules_count(s("5,134"));
    ui.set_home_state(s("safe"));
    ui.set_home_chip(s("ALL CLEAR"));
    ui.set_home_title(s("No threats waiting"));
    ui.set_home_text(s("Last scan today 09:12: 43,743 files checked, nothing found. Real-time shields arrive in phase 4, so scan regularly until then."));
    ui.set_home_stats(m(vec![
        StatItem { label: s("CHECKED TODAY"), value: s("43,743") },
        StatItem { label: s("FOUND · 30 DAYS"), value: s("2") },
        StatItem { label: s("RULES"), value: s("5,134") },
        StatItem { label: s("RULES UPDATED"), value: s("today 07:58") },
    ]));
    ui.set_status_rows(m(vec![
        StatusRow { name: s("On-demand scanner"), value: s("Ready"), tone: s("safe") },
        StatusRow { name: s("Rule pack"), value: s("5,134 rules"), tone: s("safe") },
        StatusRow { name: s("Startup items"), value: s("Checked today 09:20"), tone: s("safe") },
        StatusRow { name: s("Quarantine"), value: s("2 files"), tone: s("off") },
        StatusRow { name: s("Real-time shields"), value: s("Phase 4"), tone: s("off") },
        StatusRow { name: s("App"), value: s("v0.1.0 · up to date"), tone: s("safe") },
    ]));
    let mut daily = std::collections::BTreeMap::new();
    let today = chrono::Local::now().date_naive();
    for i in 0..360u64 {
        let d = today - chrono::Days::new(i);
        let v = (i * 2654435761) % 97;
        if v > 30 {
            daily.insert(d, (v * 900, if v == 96 || v == 61 { 1 } else { 0 }));
        }
    }
    ui.set_heat_short(m(heat_cells(&daily, 26)));
    ui.set_heat_year(m(heat_cells(&daily, 52)));
    ui.set_drives(m(vec![
        DriveRow { root: s("C:"), label: s("Windows"), info: s("Local disk · 212.4 GB free of 931.5 GB"), selected: true, usage: 0.77 },
        DriveRow { root: s("D:"), label: s("Projects"), info: s("Local disk · 2.2 TB free of 3.7 TB"), selected: true, usage: 0.41 },
        DriveRow { root: s("E:"), label: s("USB"), info: s("USB drive · 3.1 GB free of 29.8 GB"), selected: false, usage: 0.9 },
    ]));
    ui.set_folders(m(vec![s(r"D:\Onuri App\hexward"), s(r"C:\Users\sam\Downloads")]));
    ui.set_threats(m(vec![
        ThreatRow { name: s("Test/Any.HexwardMarker!a"), path: s(r"C:\Users\sam\Downloads\demo\marker.bin"), description: s("Hexward's harmless test marker. It checks that rule scanning works."), chip: s("HIGH"), tone: s("alarm"), selected: true, done: false, confirm_delete: false },
        ThreatRow { name: s("Suspicious/Win.Masquerade!a"), path: s(r"C:\Users\sam\Downloads\demo\holiday-photo.jpg"), description: s("This .jpg file is really a Windows program."), chip: s("SUSPICIOUS"), tone: s("warn"), selected: false, done: false, confirm_delete: true },
        ThreatRow { name: s("Test/Any.HashMarker!a"), path: s(r"C:\Users\sam\Downloads\demo\hash-test.bin"), description: s("This exact file is on Hexward's list of known threats."), chip: s("QUARANTINED"), tone: s("safe"), selected: false, done: true, confirm_delete: false },
    ]));
    ui.set_results_title(s("2 items need a decision"));
    ui.set_results_text(s("Quarantine locks a file away (you can restore it). Delete removes it forever. Allow trusts it, for example an old game Hexward got wrong."));
    ui.set_selected_count(1);
    ui.set_open_count(2);
    ui.set_startup_checked(true);
    ui.set_startup_summary(s("271 items · 269 clean · 0 threats · 2 missing"));
    ui.set_startup_rows(m(vec![StartupRow {
        location: s(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
        name: s("LocalSend"),
        command: s(r#""C:\Program Files\LocalSend\localsend_app.exe""#),
        chip: s("MISSING"),
        tone: s("warn"),
        fixable: true,
        detail: s("The program this points to no longer exists. Usually a leftover from an uninstalled app."),
    }]));
    ui.set_disabled_rows(m(vec![DisabledRow { id: s("1"), name: s("OldUpdater"), info: s(r"HKCU\...\Run · switched off today 09:21") }]));
    ui.set_vault_rows(m(vec![
        VaultRow { id: s("9ebb353ab64f411c"), name: s("Test/Any.HashMarker!a"), path: s(r"C:\Users\sam\Downloads\demo\hash-test.bin"), info: s("Quarantined today 09:13 · 26 B · id 9ebb353ab64f411c"), confirm: false },
        VaultRow { id: s("891d0c4d3e582bc4"), name: s("Test/Any.HexwardMarker!a"), path: s(r"C:\Users\sam\Downloads\demo\marker.bin"), info: s("Quarantined today 09:13 · 35 B · id 891d0c4d3e582bc4"), confirm: true },
    ]));
    ui.set_events(m(vec![
        EventRow { when: s("today 09:13"), title: s("Quick scan"), detail: s("43,743 files · 6.4 GB · 2 found · 0:41"), chip: s("SCAN"), tone: s("alarm") },
        EventRow { when: s("today 09:13"), title: s("Test/Any.HashMarker!a"), detail: s(r"C:\Users\sam\Downloads\demo\hash-test.bin"), chip: s("QUARANTINE"), tone: s("warn") },
        EventRow { when: s("today 07:58"), title: s("Rules updated"), detail: s("YARA Forge: core pack: 5133 rules, built 2026-11-03"), chip: s("UPDATE"), tone: s("scan") },
        EventRow { when: s("Nov 7, 21:00"), title: s("System scan"), detail: s("212,480 files · 61.2 GB · 0 found · 9:52"), chip: s("SCAN"), tone: s("safe") },
    ]));
    ui.set_allow_rows(m(vec![AllowRow { sha: s("ab"), name: s("gta-vc.exe"), path: s(r"D:\Games\GTA Vice City\gta-vc.exe · was flagged as Suspicious/Win.Packed!a") }]));
    ui.set_rules_info(s("core pack · 5,133 rules · updated today 07:58. From YARA Forge on GitHub."));
    ui.set_bazaar_info(s("Needs a free abuse.ch Auth-Key: create one at auth.abuse.ch, set HEXWARD_ABUSECH_KEY, restart Hexward and update."));
    ui.set_data_dir(s(r"C:\Users\sam\AppData\Local\Hexward"));
    ui.set_app_update_status(s("You have the latest version (0.1.0)."));
}

fn scanning(ui: &AppWindow, frame: i32) {
    ui.set_scan_started(true);
    ui.set_scanning(true);
    ui.set_scan_kind(s("SYSTEM SCAN"));
    ui.set_scan_title(s("Scanning your PC"));
    ui.set_scan_text(s("94,210 of 224,018 files · 42% · about 5:31 left"));
    ui.set_scan_path(s(r"C:\Program Files\Mozilla Firefox\xul.dll"));
    ui.set_scan_bytes(s("4D 5A 90 00 03 00 00 00
04 00 00 00 FF FF 00 00
MZ··············"));
    ui.set_scan_files(s("94,210"));
    ui.set_scan_threats(1);
    ui.set_scan_speed(s("1,912"));
    ui.set_scan_time(s("4:02"));
    ui.set_scan_fraction(0.42);
    let lit = (0.42 * 288.0) as usize;
    ui.set_grid_cells(m((0..288).map(|i| if i == 77 { 3 } else if i == lit { 2 } else if i < lit { 1 } else { 0 }).collect::<Vec<i32>>()));
    ui.set_frame(frame);
}

pub fn run(dir: PathBuf) -> Result<(), PlatformError> {
    std::fs::create_dir_all(&dir).map_err(|e| PlatformError::Other(e.to_string()))?;
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    let clock = Rc::new(Cell::new(Duration::ZERO));
    slint::platform::set_platform(Box::new(ShotPlatform { window: window.clone(), clock: clock.clone() })).map_err(|e| PlatformError::Other(e.to_string()))?;
    window.set_size(slint::PhysicalSize::new(W, H));

    let ui = AppWindow::new()?;
    set_assets(&ui);
    sample(&ui);
    ui.show()?;

    let snap = |name: &str| -> Result<(), PlatformError> {
        let mut buf = vec![PremultipliedRgbaColor::default(); (W * H) as usize];
        // Two passes: the first creates the screen, then the clock jumps past every entrance animation.
        for _ in 0..2 {
            window.request_redraw();
            slint::platform::update_timers_and_animations();
            window.draw_if_needed(|r| {
                r.render(&mut buf, W as usize);
            });
            clock.set(clock.get() + Duration::from_secs(3));
        }
        let rgba: Vec<u8> = buf
            .iter()
            .flat_map(|p| {
                let a = p.alpha.max(1) as u32;
                [(p.red as u32 * 255 / a) as u8, (p.green as u32 * 255 / a) as u8, (p.blue as u32 * 255 / a) as u8, 255]
            })
            .collect();
        let file = std::fs::File::create(dir.join(format!("{name}.png"))).map_err(|e| PlatformError::Other(e.to_string()))?;
        let mut enc = png::Encoder::new(std::io::BufWriter::new(file), W, H);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header().and_then(|mut w| w.write_image_data(&rgba)).map_err(|e| PlatformError::Other(e.to_string()))?;
        println!("wrote {name}.png");
        Ok(())
    };

    let go = |page: &str| ui.set_page(page.into());
    go("home");
    snap("01-home")?;
    ui.set_scan_choice(s("custom"));
    go("scan");
    snap("02-scan-choose")?;
    scanning(&ui, 37);
    snap("03-scan-running")?;
    ui.set_flash(true);
    scanning(&ui, 40);
    snap("04-scan-threat-flash")?;
    ui.set_flash(false);
    go("results");
    snap("05-results")?;
    go("startup");
    snap("06-startup")?;
    go("vault");
    snap("07-quarantine")?;
    go("history");
    snap("08-history")?;
    go("settings");
    snap("09-settings")?;
    ui.set_app_update_available(true);
    ui.set_app_update_version(s("0.2.0"));
    ui.set_app_update_notes(s("Custom scans, tray icon, signed self-update"));
    ui.set_app_update_status(s("Version 0.2.0 is signed and ready. Hexward restarts to finish."));
    go("about");
    snap("10-about-update")?;
    ui.set_toast_visible(true);
    ui.set_toast_state(s("alarm"));
    ui.set_toast_title(s("1 found by the system scan"));
    ui.set_toast_text(s("Nothing was changed. Open Hexward to choose: quarantine, delete or allow."));
    go("home");
    snap("11-home-update-toast")?;
    ui.set_toast_visible(false);
    ui.global::<Theme>().set_dark(false);
    snap("12-home-light")?;
    go("results");
    snap("13-results-light")?;
    Ok(())
}
