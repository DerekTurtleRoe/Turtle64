//! "iQue" tab: iQue Player specific information. Shows iQue details of the
//! ROM loaded in the Single ROM tab and any `.cmd` (content metadata) file
//! found alongside it or opened manually. Support for other iQue-related
//! files is planned.
//!
//! Text decoding is limited to ASCII / JIS X 0201 (credit: Jhynjhiruu).
//! `.cmd` layout: iQueBrew wiki "CMD" page and jbop1626/iquecrypt.

use super::Turtle64App;
use crate::checksum::Cic;
use crate::cmd::{hex, CmdFile, CmdMatch};
use eframe::egui;

fn verdict(ui: &mut egui::Ui, m: &CmdMatch, ok: &str, bad: &str) {
    match m {
        CmdMatch::Match => ui.colored_label(egui::Color32::LIGHT_GREEN, ok),
        CmdMatch::Mismatch => ui.colored_label(egui::Color32::YELLOW, bad),
    };
}

impl Turtle64App {
    pub(super) fn ui_ique(&mut self, ui: &mut egui::Ui) {
        ui.heading("🐲 iQue Player");
        ui.weak("Support for more iQue-related file types is planned.");
        ui.colored_label(
            egui::Color32::YELLOW,
            "Note: the 'C' (China) region code in the ROM header has never been used by any official N64 game, and never by iQue Player ROMs. \
             It cannot be used to tell whether a ROM is an iQue ROM, and neither can a .cmd file sitting next to it — nothing is assumed.",
        );
        ui.add_space(4.0);
        if ui.button("📂 Open .CMD…").clicked() {
            if let Some(p) =
                rfd::FileDialog::new().add_filter("iQue content metadata", &["cmd"]).add_filter("All files", &["*"]).pick_file()
            {
                match CmdFile::load(&p) {
                    Ok(c) => {
                        self.ique_cmd = Some(c);
                        self.ique_cmd_error = None;
                        self.ique_cmd_auto = false;
                    }
                    Err(e) => self.ique_cmd_error = Some(format!("Failed to read {}: {e}", p.display())),
                }
            }
        }
        if let Some(e) = &self.ique_cmd_error {
            ui.colored_label(egui::Color32::LIGHT_RED, e);
        }
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            if let Some(rom) = &self.single_rom {
                egui::Grid::new("ique_grid").num_columns(2).show(ui, |ui| {
                    ui.strong("ROM");
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
            } else {
                ui.weak("Open a ROM in the Single ROM tab to see its iQue details and compare it with a .cmd file.");
            }

            let Some(cmd) = &self.ique_cmd else {
                ui.add_space(8.0);
                ui.weak("No .cmd file loaded. A .cmd with the same name next to the ROM is picked up automatically.");
                return;
            };
            ui.add_space(8.0);
            ui.separator();
            ui.heading("Content metadata (.cmd)");
            ui.label(format!(
                "{}{} — {} bytes, {}",
                cmd.path.display(),
                if self.ique_cmd_auto { " (found alongside the ROM)" } else { "" },
                cmd.file_size,
                if cmd.desc.is_some() { "with contentDesc" } else { "head only (no contentDesc)" }
            ));

            if let Some(rom) = &self.single_rom {
                let cmp = cmd.compare_to_rom(rom.file_size, &rom.hashes.sha1);
                egui::Grid::new("cmd_cmp").num_columns(2).show(ui, |ui| {
                    ui.strong("Size vs. ROM");
                    verdict(ui, &cmp.size, "Matches the ROM's size", "Differs from the ROM's size");
                    ui.end_row();
                    ui.strong("SHA-1 vs. ROM");
                    verdict(ui, &cmp.hash, "Matches the ROM's SHA-1", "Does not match the ROM's SHA-1");
                    ui.end_row();
                });
                ui.weak("A .cmd describes the decrypted app, so an encrypted, modified or unrelated ROM will not match.");
            }

            egui::CollapsingHeader::new("BbContentMetaDataHead").default_open(true).show(ui, |ui| {
                let h = &cmd.head;
                egui::Grid::new("cmd_head").num_columns(2).show(ui, |ui| {
                    let mut row = |k: &str, v: String| {
                        ui.strong(k);
                        ui.label(v);
                        ui.end_row();
                    };
                    row("Content ID", format!("{:08X}", h.content_id));
                    row("App size", format!("{} bytes (0x{:X})", h.size, h.size));
                    row("App SHA-1 (plaintext)", hex(&h.hash));
                    row("Issuer", h.issuer.clone());
                    row("CA / CP CRL version", format!("{} / {}", h.ca_crl_version, h.cp_crl_version));
                    row("Desc flags", format!("0x{:08X}{}", h.desc_flags, if h.desc_flags & 1 != 0 { " (SA)" } else { "" }));
                    row(
                        "Exec flags",
                        format!("0x{:08X}{}", h.exec_flags, if h.exec_flags & 2 != 0 { " (re-encrypt on first launch)" } else { "" }),
                    );
                    row("Hardware access rights", format!("0x{:08X}", h.hw_access_rights));
                    row("Secure kernel rights", format!("0x{:08X}", h.secure_kernel_rights));
                    row("BBID", if h.bbid == 0 { "0 (any console)".to_string() } else { format!("0x{:08X}", h.bbid) });
                    row("Title key IV", hex(&h.title_key_iv));
                    row("Content IV", hex(&h.content_iv));
                    row("Title key (still encrypted)", hex(&h.encrypted_title_key));
                    row("Signature", if h.signature_present { "present (not verified)".into() } else { "all zero".into() });
                });
            });

            if let Some(d) = &cmd.desc {
                egui::CollapsingHeader::new("contentDesc").default_open(true).show(ui, |ui| {
                    egui::Grid::new("cmd_desc").num_columns(2).show(ui, |ui| {
                        let mut row = |k: &str, v: String| {
                            ui.strong(k);
                            ui.label(v);
                            ui.end_row();
                        };
                        let save = |a: u32, s: u32| if a == 0 && s == 0 { "unused".to_string() } else { format!("{s} bytes @ 0x{a:08X}") };
                        row("EEPROM", save(d.eeprom_addr, d.eeprom_size));
                        row("Flash", save(d.flash_addr, d.flash_size));
                        row("SRAM", save(d.sram_addr, d.sram_size));
                        let paks: Vec<String> =
                            d.cpak_addrs.iter().enumerate().filter(|(_, a)| **a != 0).map(|(i, a)| format!("#{i} @ 0x{a:08X}")).collect();
                        row(
                            "Controller Pak",
                            if paks.is_empty() { "unused".into() } else { format!("{} bytes each, {}", d.cpak_size, paks.join(", ")) },
                        );
                        row(
                            "osRomBase / osTvType / osMemSize",
                            format!("0x{:08X} / {} / 0x{:X}", d.os_rom_base, d.os_tv_type, d.os_mem_size),
                        );
                        row("Tag / file count", format!("\"{}\" / {}", d.tag, d.unknown_count));
                        row("Thumb / title image sizes", format!("{} / {} bytes (compressed)", d.thumb_len, d.title_img_len));
                        row("Title text", if d.title_text.is_empty() { "(none)".into() } else { d.title_text.join("  |  ") });
                    });
                    ui.weak("Title text is shown as ASCII / JIS X 0201 only; other bytes appear as �.");
                });
            }
        });
    }
}
