mod app;
mod batch;
mod bootcode;
mod checksum;
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
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 780.0])
            .with_min_inner_size([700.0, 500.0])
            .with_title("Turtle64"),
        ..Default::default()
    };

    eframe::run_native("Turtle64", native_options, Box::new(|cc| Ok(Box::new(Turtle64App::new(cc)))))
}
