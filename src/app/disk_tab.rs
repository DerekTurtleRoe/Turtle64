//! "64DD Disk" tab: open a .d64/.ndd disk image (NDD and MAME-format images
//! both conventionally use the .ndd extension; they're told apart by file
//! content, not by extension), inspect System Data /
//! Disk ID / MFS filesystem, and convert between the three disk formats.

use super::Turtle64App;
use crate::dd_disk::DiskFormat;
use eframe::egui;

impl Turtle64App {
    pub(super) fn ui_disk(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("💽 Open Disk Image…").clicked() {
                self.open_disk_dialog();
            }
            if let Some(disk) = &self.disk_info {
                ui.label(format!("{}", disk.path.display()));
                if ui.button("📝 Export Info to Text…").clicked() {
                    self.export_disk_info_dialog();
                }
            }
        });

        if let Some(err) = &self.disk_error {
            ui.colored_label(egui::Color32::LIGHT_RED, err);
        }

        let Some(disk) = &self.disk_info else {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.weak("Open a 64DD disk image (.d64 / .ndd) to see disk info, checksums, and MFS contents.");
                ui.weak("Format (NDD vs. MAME vs. D64) is detected from the file's contents, not its extension — NDD and MAME dumps both conventionally use .ndd.");
            });
            return;
        };

        let mut extract_request: Option<crate::dd_mfs::MfsEntry> = None;
        let mut convert_clicked = false;

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("dd_basic_info_grid").num_columns(2).show(ui, |ui| {
                ui.strong("File size");
                ui.label(format!("{} bytes ({:.2} MiB)", disk.file_size, disk.file_size as f64 / (1024.0 * 1024.0)));
                ui.end_row();

                ui.strong("Detected format");
                ui.label(disk.format.label());
                ui.end_row();

                ui.strong("Region");
                ui.label(disk.sys.region_name());
                ui.end_row();

                ui.strong("Disk type");
                ui.label(format!("{} ({})", disk.sys.disk_type, if disk.sys.retail { "retail" } else { "development" }));
                ui.end_row();

                ui.strong("64DD IPL CIC");
                ui.label(disk.cic.label());
                ui.end_row();

                if disk.has_defect_tracks {
                    ui.strong("⚠ Defect tracks");
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "This disk reports bad/defect tracks. MAME-format conversion does not model these and may not be bit-exact.",
                    );
                    ui.end_row();
                }
            });

            ui.add_space(8.0);
            ui.separator();

            egui::CollapsingHeader::new("📋 System Data / Disk ID").default_open(true).show(ui, |ui| {
                egui::Grid::new("dd_header_grid").num_columns(2).show(ui, |ui| {
                    ui.strong("Game code");
                    ui.label(&disk.disk_id.game_code);
                    ui.end_row();
                    ui.strong("Game version");
                    ui.label(format!("{}", disk.disk_id.game_version));
                    ui.end_row();
                    ui.strong("Disk number");
                    ui.label(format!("{}", disk.disk_id.disk_number));
                    ui.end_row();
                    ui.strong("Destination");
                    ui.label(format!("{} (0x{:02X})", disk.destination_name(), disk.destination_code));
                    ui.end_row();
                    ui.strong("Company code");
                    ui.label(&disk.disk_id.company_code);
                    ui.end_row();
                    ui.strong("Production date/time");
                    ui.label(&disk.disk_id.production_datetime);
                    ui.end_row();
                    ui.strong("IPL load address");
                    ui.label(format!("0x{:08X}", disk.sys.ipl_load_address));
                    ui.end_row();
                    ui.strong("IPL load size (blocks)");
                    ui.label(format!("{}", disk.sys.ipl_load_size));
                    ui.end_row();
                    ui.strong("ROM end LBA");
                    ui.label(format!("{}", disk.sys.rom_end_lba));
                    ui.end_row();
                    ui.strong("RAM used (MFS)");
                    ui.label(if disk.disk_id.ram_use { "yes" } else { "no" });
                    ui.end_row();
                });
            });

            ui.add_space(8.0);
            egui::CollapsingHeader::new("🔢 Checksums / Hashes").default_open(true).show(ui, |ui| {
                egui::Grid::new("dd_hash_grid").num_columns(2).show(ui, |ui| {
                    ui.strong("CRC32 (whole file)");
                    ui.label(format!("{:08X}", disk.hashes.crc32));
                    ui.end_row();
                    ui.strong("MD5 (whole file)");
                    ui.label(&disk.hashes.md5);
                    ui.end_row();
                    ui.strong("SHA-1 (whole file)");
                    ui.label(&disk.hashes.sha1);
                    ui.end_row();
                    if let Some(rom_sha1) = &disk.rom_area_sha1 {
                        ui.strong("SHA-1 (ROM Area only)");
                        ui.label(rom_sha1);
                        ui.end_row();
                    }
                });
            });

            ui.add_space(8.0);
            if let Some(mfs) = &disk.mfs {
                egui::CollapsingHeader::new("🗂 MFS Filesystem").default_open(true).show(ui, |ui| {
                    ui.label(format!("Volume: {} — formatted {}", mfs.volname, mfs.format_datetime));
                    ui.label(format!("Renewal counter: {}  •  checksum: 0x{:08X}", mfs.renewal_counter, mfs.checksum));
                    ui.weak("File extraction is best-effort (experimental) — see README for details.");
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical().max_height(240.0).id_salt("mfs_scroll").show(ui, |ui| {
                        egui::Grid::new("mfs_grid").num_columns(4).striped(true).show(ui, |ui| {
                            ui.strong("Path");
                            ui.strong("Size");
                            ui.strong("Date");
                            ui.strong("");
                            ui.end_row();
                            for entry in &mfs.entries {
                                if entry.is_dir {
                                    continue;
                                }
                                ui.label(mfs.full_path(entry));
                                ui.label(format!("{} bytes", entry.size));
                                ui.label(&entry.datetime);
                                if ui.button("💾 Extract").clicked() {
                                    extract_request = Some(entry.clone());
                                }
                                ui.end_row();
                            }
                        });
                    });
                });
            } else if disk.disk_id.ram_use {
                ui.colored_label(egui::Color32::YELLOW, "Disk ID indicates MFS should be present, but it could not be parsed.");
            } else {
                ui.weak("No MFS filesystem on this disk (RAM Area unused).");
            }

            ui.add_space(8.0);
            ui.separator();
            egui::CollapsingHeader::new("🔄 Convert Disk Format").default_open(true).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Target format:");
                    egui::ComboBox::from_id_salt("dd_target_format").selected_text(self.disk_target_format.label()).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.disk_target_format, DiskFormat::Ndd, DiskFormat::Ndd.label());
                        ui.selectable_value(&mut self.disk_target_format, DiskFormat::D64, DiskFormat::D64.label());
                        ui.selectable_value(&mut self.disk_target_format, DiskFormat::Mame, DiskFormat::Mame.label());
                    });
                    if ui.button("💾 Convert & Save As…").clicked() {
                        convert_clicked = true;
                    }
                });
                ui.checkbox(&mut self.disk_export_info_after_convert, "Also export info .txt immediately after conversion");
                if self.disk_target_format.is_lossy() {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "⚠ D64 is a lossy, trimmed format: it keeps only the System Data, Disk ID, and used ROM/RAM Area, \
                         discarding the defect-track table, exact physical LBA sizing, and all disk padding. The output \
                         will be much smaller than the original, and converting a D64 back to NDD/MAME cannot restore \
                         what was trimmed — it produces an idealized, defect-free disk rather than a bit-exact copy. \
                         Prefer NDD or MAME if you need an archival, round-trippable dump.",
                    );
                }
                if disk.format.is_lossy() {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "⚠ This disk was itself loaded from a D64 file, which already discarded formatting data on \
                         creation — info shown here (and any re-conversion) reflects that trimmed, idealized disk, \
                         not the original physical dump.",
                    );
                }
                if let Some(status) = &self.disk_status {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, status);
                }
            });
        });

        if convert_clicked {
            self.save_converted_disk_dialog();
        }
        if let Some(entry) = extract_request {
            self.extract_mfs_entry(entry);
        }
    }
}
