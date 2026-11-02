//! "Single ROM" tab: open one ROM, inspect header/hashes/verification, and
//! convert it to another format.

use super::Turtle64App;
use crate::confidence::{self, ConfidenceLevel, Severity};
use crate::header::category_name;
use crate::rom_format::RomFormat;
use eframe::egui;

/// Explains the "Check code" name, which is more commonly called CRC1/CRC2
/// (or CRC Hi/CRC Lo), although it is not a true CRC.
const CHECK_CODE_NOTE: &str = "The 'check code' is commonly called CRC1/CRC2 or CRC Hi/CRC Lo (header bytes 0x10-0x17).";

fn sev_color(s: Severity) -> egui::Color32 {
    match s {
        Severity::Good => egui::Color32::LIGHT_GREEN,
        Severity::Warn => egui::Color32::YELLOW,
        Severity::Bad => egui::Color32::LIGHT_RED,
        Severity::Unknown => egui::Color32::GRAY,
    }
}

impl Turtle64App {
    /// N64brew ROM Metadata section (external `.meta` or embedded ZIP).
    fn ui_metadata(&mut self, ui: &mut egui::Ui, rom: &crate::rom::RomInfo) {
        let Some(m) = &rom.metadata else {
            if rom.header.as_ref().and_then(|h| h.homebrew.as_ref()).is_some_and(|h| h.has_metadata) {
                ui.colored_label(egui::Color32::YELLOW, "The header flags embedded metadata, but no readable metadata ZIP was found.");
            } else {
                ui.weak("No ROM metadata found (no .meta file beside the ROM and no embedded ZIP).");
            }
            return;
        };
        egui::CollapsingHeader::new("📁 ROM Metadata").default_open(true).show(ui, |ui| {
            ui.weak(format!("Source: {}", m.source.label()));
            let langs = m.languages();
            if !langs.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Language:");
                    let current = self.metadata_lang.clone();
                    egui::ComboBox::from_id_salt("meta_lang")
                        .selected_text(current.clone().unwrap_or_else(|| "default (en)".to_string()))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.metadata_lang, None, "default (en)");
                            for l in &langs {
                                ui.selectable_value(&mut self.metadata_lang, Some(l.clone()), l);
                            }
                        });
                });
            }
            let lang = self.metadata_lang.as_deref().filter(|l| langs.iter().any(|x| x == l));
            egui::Grid::new("metadata_grid").num_columns(2).striped(true).show(ui, |ui| {
                for (label, key) in [
                    ("Name", "name"),
                    ("Author", "author"),
                    ("Release date", "release-date"),
                    ("License (SPDX)", "osi-license"),
                    ("Website", "website"),
                    ("Age rating", "age-rating"),
                    ("Players", "num-players"),
                    ("Short description", "short-desc"),
                ] {
                    if let Some(v) = m.get_localized(lang, key) {
                        ui.strong(label);
                        ui.label(v);
                        ui.end_row();
                    }
                }
            });
            if let Some(d) = &m.long_desc {
                ui.add_space(4.0);
                ui.strong("Long description");
                ui.label(d);
            }
            let images = m.referenced_images();
            if !images.is_empty() {
                ui.add_space(4.0);
                ui.strong("Images");
                for (label, file) in images {
                    if m.has_entry(&file) {
                        ui.label(format!("{label}: {file}"));
                    } else {
                        ui.colored_label(egui::Color32::LIGHT_RED, format!("{label}: {file} (missing from ZIP)"));
                    }
                }
            }
            for w in &m.warnings {
                ui.colored_label(egui::Color32::YELLOW, format!("⚠ {w}"));
            }
            ui.add_space(4.0);
            ui.collapsing(format!("Files in metadata ZIP ({})", m.entries.len()), |ui| {
                for e in &m.entries {
                    ui.label(format!("{} ({} bytes{})", e.name, e.size, if e.stored { "" } else { ", compressed" }));
                }
            });
            if ui.button("📤 Extract metadata files…").clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.single_status = Some(match crate::metadata::extract_all(&m.source, &rom.be_data, &dir) {
                        Ok(n) => format!("Extracted {n} metadata file(s) to {}", dir.display()),
                        Err(e) => format!("Metadata extraction failed: {e}"),
                    });
                }
            }
        });
    }
}

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

        if ui
            .checkbox(
                &mut self.single_use_native_hashes,
                "Don't convert to big-endian when checking ROM info (show native-order hashes too)",
            )
            .changed()
        {
            self.reload_single_rom();
        }
        if self.single_use_native_hashes {
            ui.weak(
                "Header fields, CIC detection, and check code (CRC1/CRC2) always use the normalized big-endian form (required to be meaningful); \
                 only the extra CRC32/MD5/SHA-1/FNV-1a/xxHash set below reflects the ROM's original, native byte order.",
            );
        }

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
            let assessment = confidence::assess(&rom);
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
            });

            ui.add_space(8.0);
            ui.separator();

            if let Some(header) = &rom.header {
                egui::CollapsingHeader::new("📋 ROM Header").default_open(true).show(ui, |ui| {
                    egui::Grid::new("header_grid").num_columns(2).striped(true).show(ui, |ui| {
                        ui.strong("Game title");
                        ui.colored_label(sev_color(assessment.severity_of("Game title")), &header.game_title);
                        ui.end_row();

                        ui.strong("Game code");
                        ui.colored_label(
                            sev_color(assessment.severity_of("Game code")),
                            format!("{}{} ({})", header.category_code, header.unique_code, category_name(header.category_code)),
                        );
                        ui.end_row();

                        ui.strong("Region");
                        ui.colored_label(
                            sev_color(assessment.severity_of("Region")),
                            format!("{} - {}", header.destination_code, header.destination_name),
                        );
                        ui.end_row();

                        ui.strong("ROM version");
                        ui.colored_label(sev_color(assessment.severity_of("ROM version")), format!("1.{}", header.rom_version));
                        ui.end_row();

                        ui.strong("Boot address (entry point)");
                        ui.label(format!(
                            "0x{:08X} (effective after IPL3: 0x{:08X})",
                            header.boot_address,
                            header.effective_boot_address(&rom.cic)
                        ));
                        ui.end_row();

                        ui.strong("Clock rate (raw)");
                        ui.label(format!(
                            "0x{:08X} (libultra Count rate: {} Hz)",
                            header.clock_rate_raw,
                            header.effective_clock_rate()
                        ));
                        ui.end_row();

                        ui.strong("Reserved (0x00)");
                        ui.label(format!("0x{:02X}", header.reserved_00));
                        ui.end_row();

                        ui.strong("Reserved (0x18-0x1F)");
                        ui.label(crate::header::hex_bytes(&header.reserved_18));
                        ui.end_row();

                        ui.strong("Reserved (0x34-0x3A)");
                        ui.label(crate::header::hex_bytes(&header.reserved_34));
                        ui.end_row();

                        ui.strong("Libultra version");
                        ui.label(format!("{} (raw 0x{:08X})", header.libultra_version, header.libultra_version_raw));
                        ui.end_row();

                        ui.strong("PI BSD DOM1 config / PI timings");
                        let pi_color = match rom.pi_timings_status {
                            Some(_) => sev_color(assessment.severity_of("PI timings")),
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

                        ui.strong("Header check code").on_hover_text(CHECK_CODE_NOTE);
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
                            ui.strong("Raw flags (0x38) / savetype byte (0x3F)");
                            ui.label(format!("0x{:02X} / 0x{:02X}", hb.flags_raw, hb.savetype_raw));
                            ui.end_row();
                        });
                    });
                } else {
                    ui.weak("No Advanced Homebrew ROM Header detected (no \"ED\" marker at 0x3C).");
                }

                self.ui_metadata(ui, &rom);
            } else {
                ui.colored_label(egui::Color32::LIGHT_RED, "ROM too small to contain a valid header.");
            }

            ui.add_space(8.0);
            ui.separator();

            egui::CollapsingHeader::new("🔢 Checksums & Hashes").default_open(true).show(ui, |ui| {
                egui::Grid::new("checksum_grid").num_columns(2).striped(true).show(ui, |ui| {
                    ui.strong("Calculated check code").on_hover_text(CHECK_CODE_NOTE);
                    match (rom.calculated_crc1, rom.calculated_crc2) {
                        (Some(c1), Some(c2)) => {
                            let color = sev_color(assessment.severity_of("Check code"));
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
                    ui.strong("FNV-1a (64)");
                    ui.label(format!("{:016X}", rom.hashes.fnv1a64));
                    ui.end_row();
                    ui.strong("XXH64");
                    ui.label(format!("{:016X}", rom.hashes.xxh64));
                    ui.end_row();
                });
            });

            if let Some(native) = &rom.native_hashes {
                ui.add_space(4.0);
                egui::CollapsingHeader::new("🔢 Native byte-order hashes (not converted to big-endian)").default_open(true).show(
                    ui,
                    |ui| {
                        egui::Grid::new("native_hash_grid").num_columns(2).striped(true).show(ui, |ui| {
                            ui.strong("CRC32");
                            ui.label(format!("{:08X}", native.crc32));
                            ui.end_row();
                            ui.strong("MD5");
                            ui.label(&native.md5);
                            ui.end_row();
                            ui.strong("SHA-1");
                            ui.label(&native.sha1);
                            ui.end_row();
                            ui.strong("FNV-1a (64)");
                            ui.label(format!("{:016X}", native.fnv1a64));
                            ui.end_row();
                            ui.strong("XXH64");
                            ui.label(format!("{:016X}", native.xxh64));
                            ui.end_row();
                        });
                        ui.weak("Reference only — No-Intro/Redump verification above always uses the normalized hashes.");
                    },
                );
            }

            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong("No-Intro verification:");
                let c = match assessment.severity_of("No-Intro") {
                    Severity::Unknown => ui.visuals().weak_text_color(),
                    s => sev_color(s),
                };
                ui.colored_label(c, rom.verification.label());
            });

            ui.add_space(8.0);
            ui.separator();
            egui::CollapsingHeader::new("🎯 Estimated dump confidence (educated guess only)").default_open(true).show(ui, |ui| {
                let level_color = match assessment.level {
                    ConfidenceLevel::VeryHigh | ConfidenceLevel::High => egui::Color32::LIGHT_GREEN,
                    ConfidenceLevel::Medium => egui::Color32::YELLOW,
                    ConfidenceLevel::Low | ConfidenceLevel::VeryLow => egui::Color32::LIGHT_RED,
                };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(assessment.level.label()).strong().size(18.0).color(level_color));
                    ui.weak(format!("(rough score {:.0}%)", assessment.score * 100.0));
                });
                ui.colored_label(egui::Color32::YELLOW, format!("⚠ {}", confidence::DISCLAIMER));
                ui.add_space(4.0);
                egui::Grid::new("confidence_grid").num_columns(2).striped(true).show(ui, |ui| {
                    for c in &assessment.checks {
                        let color = match c.severity {
                            Severity::Unknown => ui.visuals().weak_text_color(),
                            s => sev_color(s),
                        };
                        ui.strong(c.name);
                        ui.colored_label(color, &c.note);
                        ui.end_row();
                    }
                });
                ui.weak("Colour key: green = looks correct, yellow = unusual or couldn't be fully checked, red = missing, invalid, or doesn't match, grey = not checked (e.g. no DAT loaded).");
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
            });
            ui.checkbox(&mut self.single_export_info_after_convert, "Also export info .txt immediately after conversion");
            if ui.button("💾 Convert & Save As…").clicked() {
                let default_name = rom
                    .path
                    .file_stem()
                    .map(|s| format!("{}.{}", s.to_string_lossy(), self.single_target_format.extension()))
                    .unwrap_or_else(|| format!("output.{}", self.single_target_format.extension()));
                if let Some(out_path) = rfd::FileDialog::new().set_file_name(&default_name).save_file() {
                    let target = self.single_target_format;
                    if let Err(e) = rom.convert_to_file(target, &out_path) {
                        self.single_error = Some(format!("Conversion failed: {e}"));
                    } else {
                        self.single_error = None;
                        self.single_status = Some(format!("✅ Converted and saved to {}", out_path.display()));
                        if self.single_export_info_after_convert {
                            let info_out_path = super::append_to_file_name(&out_path, "_info.txt");
                            let report = rom.conversion_info_text(target, &out_path);
                            match std::fs::write(&info_out_path, report) {
                                Ok(()) => {
                                    self.single_status = Some(format!(
                                        "✅ Converted and saved to {}; info exported to {}",
                                        out_path.display(),
                                        info_out_path.display()
                                    ));
                                }
                                Err(e) => self.single_error = Some(format!("Conversion succeeded, but info export failed: {e}")),
                            }
                        }
                    }
                }
            }

            ui.add_space(12.0);
            ui.separator();
            ui.heading("🚀 IPL3 Boot Code");
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
            ui.weak("libdragon_r1.bin .. libdragon_r8.bin (all 8 libdragon open-source IPL3 revisions) are bundled and seeded into the bootcodes folder automatically.");
            if self.bootcode_list.is_empty() {
                ui.weak(format!(
                    "No 0xFC0-byte IPL3 dumps found. Drop some into {} (any filename, must be exactly 4032 bytes).",
                    crate::bootcode::bootcodes_dir().display()
                ));
            }

            ui.checkbox(&mut self.fix_crc_on_patch, "Recalculate & rewrite header check code (CRC1/CRC2) for the new IPL3/CIC pairing");

            ui.add_enabled_ui(self.selected_bootcode.is_some(), |ui| {
                if ui.button("🔧 Patch selected IPL3 into this ROM").clicked() {
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

                        ui.strong("New calculated check code").on_hover_text(CHECK_CODE_NOTE);
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
                            ui.strong("Header check code (after patch)").on_hover_text(CHECK_CODE_NOTE);
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
