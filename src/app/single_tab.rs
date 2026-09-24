//! "Single ROM" tab: open one ROM, inspect header/hashes/verification, and
//! convert it to another format.

use super::Turtle64App;
use crate::header::category_name;
use crate::rom_format::RomFormat;
use eframe::egui;

impl Turtle64App {
    pub(super) fn ui_single(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("📂 Open ROM…").clicked() {
                self.open_rom_dialog();
            }
            if let Some(rom) = &self.single_rom {
                ui.label(format!("{}", rom.path.display()));
                if ui.button("📝 Export Info to Text…").clicked() {
                    self.export_rom_info_dialog();
                }
            }
        });

        if let Some(status) = &self.single_status {
            ui.colored_label(egui::Color32::LIGHT_GREEN, status);
        }

        if let Some(err) = &self.single_error {
            ui.colored_label(egui::Color32::LIGHT_RED, err);
        }

        let Some(rom) = self.single_rom.clone() else {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.weak("Open an N64 ROM to see header information, checksums, and hashes.");
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("basic_info_grid").num_columns(2).show(ui, |ui| {
                ui.strong("File size");
                ui.label(format!("{} bytes ({:.2} MiB)", rom.file_size, rom.file_size as f64 / (1024.0 * 1024.0)));
                ui.end_row();

                ui.strong("Detected format");
                ui.label(rom.detected_format.label());
                ui.end_row();

                ui.strong("CIC boot chip");
                ui.label(rom.cic.label());
                ui.end_row();

                if rom.has_ique_header {
                    ui.strong("iQue container header");
                    ui.colored_label(egui::Color32::LIGHT_BLUE, "32-byte iQue header detected and parsed");
                    ui.end_row();
                }
            });

            ui.add_space(8.0);
            ui.separator();

            if let Some(header) = &rom.header {
                egui::CollapsingHeader::new("📋 ROM Header").default_open(true).show(ui, |ui| {
                    egui::Grid::new("header_grid").num_columns(2).striped(true).show(ui, |ui| {
                        ui.strong("Game title");
                        ui.label(&header.game_title);
                        ui.end_row();

                        ui.strong("Game code");
                        ui.label(format!("{}{} ({})", header.category_code, header.unique_code, category_name(header.category_code)));
                        ui.end_row();

                        ui.strong("Region");
                        ui.label(format!("{} - {}", header.destination_code, header.destination_name));
                        ui.end_row();

                        ui.strong("ROM version");
                        ui.label(format!("1.{}", header.rom_version));
                        ui.end_row();

                        ui.strong("Boot address (entry point)");
                        ui.label(format!("0x{:08X}", header.boot_address));
                        ui.end_row();

                        ui.strong("Clock rate (raw)");
                        ui.label(format!("0x{:08X}", header.clock_rate_raw));
                        ui.end_row();

                        ui.strong("Libultra version");
                        ui.label(format!("{} (raw 0x{:08X})", header.libultra_version, header.libultra_version_raw));
                        ui.end_row();

                        ui.strong("PI BSD DOM1 config / PI timings");
                        let pi_color = match rom.pi_timings_status {
                            Some(crate::checksum::PiTimingsStatus::NonStandard) => egui::Color32::YELLOW,
                            Some(_) => egui::Color32::LIGHT_GREEN,
                            None => ui.visuals().text_color(),
                        };
                        ui.colored_label(
                            pi_color,
                            format!("0x{:08X}  {}", header.pi_timings, rom.pi_timings_status.map(|s| s.label()).unwrap_or("")),
                        );
                        ui.end_row();

                        ui.strong("Header check code");
                        ui.label(format!("0x{:016X}", header.check_code));
                        ui.end_row();

                        ui.strong("Header CRC1 / CRC2");
                        ui.label(format!("0x{:08X} / 0x{:08X}", header.crc1, header.crc2));
                        ui.end_row();
                    });
                });

                if let Some(hb) = &header.homebrew {
                    egui::CollapsingHeader::new("🛠 Advanced Homebrew ROM Header").default_open(true).show(ui, |ui| {
                        egui::Grid::new("homebrew_grid").num_columns(2).striped(true).show(ui, |ui| {
                            ui.strong("Controller 1");
                            ui.label(&hb.controller1);
                            ui.end_row();
                            ui.strong("Controller 2");
                            ui.label(&hb.controller2);
                            ui.end_row();
                            ui.strong("Controller 3");
                            ui.label(&hb.controller3);
                            ui.end_row();
                            ui.strong("Controller 4");
                            ui.label(&hb.controller4);
                            ui.end_row();
                            ui.strong("Save type");
                            ui.label(&hb.savetype);
                            ui.end_row();
                            ui.strong("Uses RTC");
                            ui.label(if hb.uses_rtc { "Yes" } else { "No" });
                            ui.end_row();
                            ui.strong("Region-free");
                            ui.label(if hb.region_free { "Yes" } else { "No" });
                            ui.end_row();
                            ui.strong("Embedded metadata ZIP");
                            ui.label(if hb.has_metadata { "Yes" } else { "No" });
                            ui.end_row();
                        });
                    });
                } else {
                    ui.weak("No Advanced Homebrew ROM Header detected (no \"ED\" marker at 0x3C).");
                }
            } else {
                ui.colored_label(egui::Color32::LIGHT_RED, "ROM too small to contain a valid header.");
            }

            ui.add_space(8.0);
            ui.separator();

            egui::CollapsingHeader::new("🧮 Checksums & Hashes").default_open(true).show(ui, |ui| {
                egui::Grid::new("checksum_grid").num_columns(2).striped(true).show(ui, |ui| {
                    ui.strong("Calculated CRC1 / CRC2");
                    match (rom.calculated_crc1, rom.calculated_crc2) {
                        (Some(c1), Some(c2)) => {
                            let color = match rom.checksum_valid {
                                Some(true) => egui::Color32::LIGHT_GREEN,
                                Some(false) => egui::Color32::LIGHT_RED,
                                None => ui.visuals().text_color(),
                            };
                            let status = match rom.checksum_valid {
                                Some(true) => "(matches header ✅)",
                                Some(false) => "(MISMATCH ⚠)",
                                None => "",
                            };
                            ui.colored_label(color, format!("0x{:08X} / 0x{:08X} {}", c1, c2, status));
                        }
                        _ => {
                            ui.weak("Unable to calculate (unrecognized CIC or truncated ROM)");
                        }
                    }
                    ui.end_row();

                    ui.strong("CRC32");
                    ui.label(format!("{:08X}", rom.hashes.crc32));
                    ui.end_row();

                    ui.strong("MD5");
                    ui.label(&rom.hashes.md5);
                    ui.end_row();

                    ui.strong("SHA-1");
                    ui.label(&rom.hashes.sha1);
                    ui.end_row();
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong("No-Intro verification:");
                ui.label(rom.verification.label());
            });

            ui.add_space(12.0);
            ui.separator();
            ui.heading("Convert this ROM");
            ui.horizontal(|ui| {
                ui.label("Target format:");
                egui::ComboBox::from_id_salt("single_target_format").selected_text(self.single_target_format.label()).show_ui(ui, |ui| {
                    for fmt in RomFormat::all_targets() {
                        ui.selectable_value(&mut self.single_target_format, fmt, fmt.label());
                    }
                });
                if ui.button("💾 Convert & Save As…").clicked() {
                    let default_name = rom
                        .path
                        .file_stem()
                        .map(|s| format!("{}.{}", s.to_string_lossy(), self.single_target_format.extension()))
                        .unwrap_or_else(|| format!("output.{}", self.single_target_format.extension()));
                    if let Some(out_path) = rfd::FileDialog::new().set_file_name(&default_name).save_file() {
                        if let Err(e) = rom.convert_to_file(self.single_target_format, &out_path) {
                            self.single_error = Some(format!("Conversion failed: {e}"));
                        } else {
                            self.single_error = None;
                        }
                    }
                }
            });

            ui.add_space(12.0);
            ui.separator();
            ui.heading("🥾 IPL3 Boot Code");
            ui.label(format!("Detected CIC: {} — IPL3 spans ROM offset 0x40-0x1000 (0xFC0 bytes)", rom.cic.label()));

            ui.horizontal(|ui| {
                if ui.button("📤 Dump IPL3 to file…").clicked() {
                    self.dump_ipl3_dialog();
                }
                ui.label(format!("Bootcodes folder: {}", crate::bootcode::bootcodes_dir().display()));
                if ui.button("🔄 Refresh list").clicked() {
                    self.refresh_bootcode_list();
                }
            });

            ui.horizontal(|ui| {
                ui.label("Available dumped IPL3s:");
                let selected_label = self
                    .selected_bootcode
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "(none selected)".to_string());
                egui::ComboBox::from_id_salt("bootcode_select").selected_text(selected_label).show_ui(ui, |ui| {
                    for path in self.bootcode_list.clone() {
                        let label = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.display().to_string());
                        ui.selectable_value(&mut self.selected_bootcode, Some(path), label);
                    }
                });
            });
            if self.bootcode_list.is_empty() {
                ui.weak(format!(
                    "No 0xFC0-byte IPL3 dumps found. Drop some into {} (any filename, must be exactly 4032 bytes).",
                    crate::bootcode::bootcodes_dir().display()
                ));
            }

            ui.checkbox(&mut self.fix_crc_on_patch, "Recalculate & rewrite header CRC1/CRC2 for the new IPL3/CIC pairing");

            ui.add_enabled_ui(self.selected_bootcode.is_some(), |ui| {
                if ui.button("🩹 Patch selected IPL3 into this ROM").clicked() {
                    self.patch_selected_bootcode();
                }
            });

            if let Some(err) = &self.patch_error {
                ui.colored_label(egui::Color32::LIGHT_RED, err);
            }
            if let Some(status) = &self.patch_status {
                ui.colored_label(egui::Color32::LIGHT_GREEN, status);
            }

            if let Some(patched) = self.patched_rom.clone() {
                egui::CollapsingHeader::new("🔍 Patched ROM preview").default_open(true).show(ui, |ui| {
                    egui::Grid::new("patched_preview_grid").num_columns(2).striped(true).show(ui, |ui| {
                        ui.strong("New CIC boot chip");
                        ui.label(patched.cic.label());
                        ui.end_row();

                        ui.strong("New calculated CRC1 / CRC2");
                        match (patched.calculated_crc1, patched.calculated_crc2) {
                            (Some(c1), Some(c2)) => {
                                ui.label(format!("0x{:08X} / 0x{:08X}", c1, c2));
                            }
                            _ => {
                                ui.weak("Unable to calculate (unrecognized CIC)");
                            }
                        }
                        ui.end_row();

                        if let Some(h) = &patched.header {
                            ui.strong("Header CRC1 / CRC2 (after patch)");
                            ui.label(format!("0x{:08X} / 0x{:08X}", h.crc1, h.crc2));
                            ui.end_row();
                        }

                        ui.strong("Checksum matches header");
                        match patched.checksum_valid {
                            Some(true) => {
                                ui.colored_label(egui::Color32::LIGHT_GREEN, "Yes ✅");
                            }
                            Some(false) => {
                                ui.colored_label(egui::Color32::LIGHT_RED, "No ⚠");
                            }
                            None => {
                                ui.weak("Unknown");
                            }
                        }
                        ui.end_row();
                    });
                    if ui.button("💾 Save patched ROM As…").clicked() {
                        self.save_patched_rom_dialog();
                    }
                });
            }
        });
    }
}
