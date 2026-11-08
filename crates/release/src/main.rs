//! `hexward-release`: signing tool for the release pipeline.
//!
//!   hexward-release keygen <secret-file>                 make a key pair; prints the public key
//!   hexward-release sign <file> --version <v>            writes <file>.sig (key from HEXWARD_SIGNING_KEY)
//!   hexward-release verify <file> --version <v> [--public <hex>]

use std::path::Path;

use anyhow::{Context, Result, bail};
use hexward_update::app;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn file_name(p: &Path) -> Result<String> {
    Ok(p.file_name().context("no file name")?.to_string_lossy().into_owned())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let out = args.get(1).context("usage: keygen <secret-file>")?;
            if Path::new(out).exists() {
                bail!("{out} already exists; refusing to overwrite a signing key");
            }
            let (secret, public) = app::keygen()?;
            std::fs::write(out, &secret)?;
            println!("Secret key written to {out}. Keep it private; never commit it.");
            println!("Public key (put in crates/update/src/app.rs PUBLIC_KEY_HEX):");
            println!("{public}");
        }
        Some("sign") => {
            let file = Path::new(args.get(1).context("usage: sign <file> --version <v>")?);
            let version = arg(&args, "--version").context("--version is required")?;
            let secret = std::env::var("HEXWARD_SIGNING_KEY").context("HEXWARD_SIGNING_KEY isn't set")?;
            let data = std::fs::read(file)?;
            let name = file_name(file)?;
            let sig = app::sign(&name, &version, &data, &secret)?;
            // Check against the key the app ships with, so a wrong secret fails the build, not the users.
            app::verify(&name, &version, &data, &sig, app::PUBLIC_KEY_HEX).context("signature doesn't match the app's built-in public key")?;
            std::fs::write(format!("{}.sig", file.display()), sig)?;
            println!("signed {name} {version}");
        }
        Some("verify") => {
            let file = Path::new(args.get(1).context("usage: verify <file> --version <v>")?);
            let version = arg(&args, "--version").context("--version is required")?;
            let public = arg(&args, "--public").unwrap_or_else(|| app::PUBLIC_KEY_HEX.to_string());
            let sig = std::fs::read_to_string(format!("{}.sig", file.display()))?;
            app::verify(&file_name(file)?, &version, &std::fs::read(file)?, &sig, &public)?;
            println!("signature OK");
        }
        Some("channel") => {
            // hexward-release channel [--current channel.json] [--pack <file> --version <v> --rules <n>] [--kill <v>] --out <dir>
            use hexward_update::channel::{self, Channel, PackEntry};
            use sha2::Digest;
            let secret = std::env::var("HEXWARD_SIGNING_KEY").context("HEXWARD_SIGNING_KEY isn't set")?;
            let out = Path::new(&arg(&args, "--out").context("--out <dir> is required")?).to_path_buf();
            std::fs::create_dir_all(&out)?;
            let current: Channel = match arg(&args, "--current") {
                Some(p) if Path::new(&p).exists() => serde_json::from_slice(&std::fs::read(&p)?).context("current channel.json is unreadable")?,
                _ => Channel::default(),
            };
            let new = match arg(&args, "--pack") {
                Some(p) => {
                    let p = Path::new(&p);
                    let version = arg(&args, "--version").context("--version is required with --pack")?;
                    let rules: usize = arg(&args, "--rules").and_then(|r| r.parse().ok()).unwrap_or(0);
                    let data = std::fs::read(p)?;
                    let file = format!("hexward-rules-{version}.yar");
                    let sig = app::sign(&file, &version, &data, &secret)?;
                    app::verify(&file, &version, &data, &sig, app::PUBLIC_KEY_HEX).context("signature doesn't match the app's built-in public key")?;
                    std::fs::write(out.join(&file), &data)?;
                    std::fs::write(out.join(format!("{file}.sig")), sig)?;
                    Some(PackEntry { version, file, sha256: hex::encode(sha2::Sha256::digest(&data)), rules, published: chrono::Utc::now(), percent: 0 })
                }
                None => None,
            };
            let staged = channel::stage(current, new, arg(&args, "--kill").as_deref(), chrono::Utc::now());
            let body = serde_json::to_vec_pretty(&staged)?;
            let sig = app::sign("channel.json", "channel", &body, &secret)?;
            app::verify("channel.json", "channel", &body, &sig, app::PUBLIC_KEY_HEX)?;
            std::fs::write(out.join("channel.json"), &body)?;
            std::fs::write(out.join("channel.json.sig"), sig)?;
            for p in &staged.packs {
                println!("{} {:>3}%{}", p.version, p.percent, if staged.killed.contains(&p.version) { " (killed)" } else { "" });
            }
        }
        _ => bail!("usage: hexward-release keygen <secret-file> | sign <file> --version <v> | verify <file> --version <v> | channel …"),
    }
    Ok(())
}
