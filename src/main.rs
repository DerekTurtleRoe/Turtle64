mod app;
mod batch;
mod bootcode;
mod checksum;
mod cjk;
mod confidence;
mod dat;
mod dd_cic;
mod dd_convert;
mod dd_disk;
mod dd_geometry;
mod dd_mfs;
mod hashes;
mod header;
mod rom;
mod rom_format;

use app::Turtle64App;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let icon = load_icon();
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 780.0])
            .with_min_inner_size([700.0, 500.0])
            .with_title("Turtle64")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native("Turtle64", native_options, Box::new(|cc| Ok(Box::new(Turtle64App::new(cc)))))
}

/// Loads the bundled 256x256 raw-RGBA8 app icon (pre-rendered by
/// `assets/icons/gen_icon.py`) for the window/taskbar icon, decoding plain
/// bytes rather than pulling in a PNG-decoding dependency at runtime.
fn load_icon() -> egui::IconData {
    const RGBA: &[u8] = include_bytes!("../assets/icons/turtle64_256.rgba");
    egui::IconData { rgba: RGBA.to_vec(), width: 256, height: 256 }
}
