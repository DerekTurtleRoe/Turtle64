//! "iQue" tab: iQue Player specific information. Currently shows the iQue
//! details of the ROM loaded in the Single ROM tab; support for other
//! iQue-related files is planned.

use super::Turtle64App;
use crate::checksum::Cic;
use eframe::egui;

impl Turtle64App {
    pub(super) fn ui_ique(&mut self, ui: &mut egui::Ui) {
        ui.heading("🐲 iQue Player");
        ui.weak("Support for more iQue-related file types is planned. For now, this tab summarises iQue details of the ROM open in the Single ROM tab.");
        ui.add_space(8.0);
        ui.separator();

        let Some(rom) = &self.single_rom else {
            ui.add_space(8.0);
            ui.weak("Open a ROM in the Single ROM tab to see its iQue details here.");
            return;
        };

        ui.add_space(8.0);
        egui::Grid::new("ique_grid").num_columns(2).show(ui, |ui| {
            ui.strong("File");
            ui.label(rom.path.display().to_string());
            ui.end_row();

            ui.strong("iQue container header");
            if rom.has_ique_header {
                ui.colored_label(egui::Color32::LIGHT_GREEN, "Present (32-byte header detected and parsed)");
            } else {
                ui.label("Not present");
            }
            ui.end_row();

            ui.strong("CIC boot chip");
            if rom.cic == Cic::CicIque {
                ui.colored_label(egui::Color32::LIGHT_GREEN, rom.cic.label());
            } else {
                ui.label(rom.cic.label());
            }
            ui.end_row();

            if let Some(h) = &rom.header {
                ui.strong("Destination");
                ui.label(format!("{} ({})", h.destination_name, h.destination_code));
                ui.end_row();
                ui.strong("Game title");
                ui.label(&h.game_title);
                ui.end_row();
            }
        });

        ui.add_space(12.0);
        ui.separator();
        ui.weak("Text decoding is limited to ASCII and JIS X 0201, thanks to guidance from Jhynjhiruu.");
    }
}
