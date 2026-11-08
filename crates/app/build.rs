// Compiles the Slint UI and, on Windows, embeds the pixel-shield icon into the .exe.

#[allow(dead_code)]
mod art {
    include!("src/art.rs");
}

fn main() {
    slint_build::compile_with_config("ui/app.slint", slint_build::CompilerConfiguration::new().with_style("fluent".into()))
        .expect("Slint UI compiles");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let ico_path = out.join("hexward.ico");
        let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
        for scale in [1usize, 2, 3, 4, 16] {
            // Ink tile behind the mark from 32 px up; transparent at 16 px so the tray stays crisp.
            let (w, h, mut rgba) = art::render(&art::MARK, scale, art::mark_color(art::MOSS_HI, art::MOSS_LO, Some(art::OXIDE)));
            if scale >= 2 {
                for px in rgba.as_chunks_mut::<4>().0 {
                    if px[3] == 0 {
                        px.copy_from_slice(&art::INK);
                    }
                }
            }
            let img = ico::IconImage::from_rgba_data(w, h, rgba);
            dir.add_entry(ico::IconDirEntry::encode(&img).expect("icon encodes"));
        }
        dir.write(std::fs::File::create(&ico_path).unwrap()).unwrap();
        let rc = out.join("hexward.rc");
        std::fs::write(&rc, format!("1 ICON \"{}\"\n", ico_path.display().to_string().replace('\\', "\\\\"))).unwrap();
        embed_resource::compile(&rc, embed_resource::NONE).manifest_optional().unwrap();
    }
    println!("cargo:rerun-if-changed=src/art.rs");
    println!("cargo:rerun-if-changed=ui");
}
