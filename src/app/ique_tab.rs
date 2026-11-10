//! "iQue" tab: iQue Player specific information. Shows iQue details of the
//! ROM loaded in the Single ROM tab and any `.cmd` (content metadata) file
//! found alongside it or opened manually. Support for other iQue-related
//! files is planned.
//!
//! CMD title text is decoded with GBK preferred; font coverage varies.
//! `.cmd` layout: iQueBrew wiki "CMD" page and jbop1626/iquecrypt.

use super::Turtle64App;
use crate::checksum::Cic;
use crate::cmd::{hex, CmdFile, CmdMatch};
use crate::ique_crypto::{self as qc, KeySource};
use eframe::egui;
use std::path::PathBuf;

#[derive(Default, PartialEq, Clone, Copy)]
pub(super) enum DecMode {
    #[default]
    CommonKey,
    Recrypt,
    Ticket,
    Sksa,
    Direct,
}

/// User-supplied secrets live only in memory and are never saved.
#[derive(Default)]
pub(super) struct IqueDecryptState {
    mode: DecMode,
    input: Option<PathBuf>,
    common_key: String,
    key: String,
    iv: String,
    content_id: String,
    virage2: Option<PathBuf>,
    recrypt_sys: Option<PathBuf>,
    ticket: Option<PathBuf>,
    ticket_content_id: String,
    sk_key: String,
    sk_iv: String,
    decompress_sa2: bool,
    status: Option<(bool, String)>,
}

fn verdict(ui: &mut egui::Ui, m: &CmdMatch, ok: &str, bad: &str) {
    match m {
        CmdMatch::Match => ui.colored_label(egui::Color32::LIGHT_GREEN, ok),
        CmdMatch::Mismatch => ui.colored_label(egui::Color32::YELLOW, bad),
    };
}

fn pick_row(ui: &mut egui::Ui, label: &str, slot: &mut Option<PathBuf>) {
    ui.horizontal(|ui| {
        if ui.button(label).clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                *slot = Some(p);
            }
        }
        ui.label(slot.as_ref().map_or("(none)".to_string(), |p| p.display().to_string()));
    });
}

fn key_row(ui: &mut egui::Ui, label: &str, text: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(text).desired_width(300.0).hint_text("32 hex digits"));
        if ui.button("From file…").clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                if let Ok(k) = qc::read_key_file(&p) {
                    *text = hex(&k);
                }
            }
        }
    });
}

/// Decrypts SA1/SA2 (and the SK if a key and IV are given) from an SKSA image
/// into a folder chosen by the user.
fn run_sksa(st: &IqueDecryptState, input: &std::path::Path) -> anyhow::Result<String> {
    let data = std::fs::read(input)?;
    let common = qc::parse_hex16(&st.common_key).map_err(|e| anyhow::anyhow!("common key: {e}"))?;
    let apps = [qc::sksa_decrypt_sa(&data, 1, &common)?, qc::sksa_decrypt_sa(&data, 2, &common)?];
    let expanded_sa2 = if st.decompress_sa2 {
        let sa2 = apps[1].as_ref().ok_or_else(|| anyhow::anyhow!("SA2 is absent; cannot decompress it"))?;
        if !sa2.sha1_ok {
            anyhow::bail!("SA2 SHA-1 does not match the CMD; refusing to decompress unverified data");
        }
        Some(qc::decompress_sa2(&sa2.data)?)
    } else {
        None
    };
    let sk = if st.sk_key.trim().is_empty() && st.sk_iv.trim().is_empty() {
        None
    } else {
        let key = qc::parse_hex16(&st.sk_key).map_err(|e| anyhow::anyhow!("SK key: {e}"))?;
        let iv = qc::parse_hex16(&st.sk_iv).map_err(|e| anyhow::anyhow!("SK IV: {e}"))?;
        Some(qc::sksa_decrypt_sk(&data, &key, &iv)?)
    };
    let Some(dir) = rfd::FileDialog::new().set_title("Choose output folder").pick_folder() else {
        anyhow::bail!("save cancelled");
    };
    let mut report = Vec::new();
    for (index, app) in apps.into_iter().enumerate() {
        let which = index + 1;
        match app {
            Some(sa) => {
                std::fs::write(dir.join(format!("sa{which}.bin")), &sa.data)?;
                let v = if sa.sha1_ok { "SHA-1 ✔" } else { "⚠ SHA-1 mismatch (wrong common key?)" };
                report.push(format!("SA{which} (content ID {:08X}, {} bytes) {v}", sa.content_id, sa.data.len()));
            }
            None => report.push(format!("SA{which} absent")),
        }
    }
    if let Some(expanded) = expanded_sa2 {
        std::fs::write(dir.join("sa2-decompressed.bin"), &expanded)?;
        report.push(format!("Decompressed SA2: {} bytes (not separately verified)", expanded.len()));
    }
    if let Some(sk) = sk {
        std::fs::write(dir.join("sk.bin"), sk)?;
        report.push("SK written (not verifiable here)".into());
    }
    Ok(format!("Wrote to {}: {}", dir.display(), report.join("; ")))
}

impl Turtle64App {
    fn run_ique_decrypt(&mut self) -> anyhow::Result<String> {
        let st = &self.ique_dec;
        let input = st.input.clone().ok_or_else(|| anyhow::anyhow!("choose the encrypted input file"))?;
        if st.mode == DecMode::Sksa {
            return run_sksa(st, &input);
        }
        let cmd = self.ique_cmd.as_ref();
        let iv_from_ui = || qc::parse_hex16(&st.iv).map_err(|e| anyhow::anyhow!("IV: {e}"));
        let source = match st.mode {
            DecMode::CommonKey => {
                let c = cmd.ok_or_else(|| anyhow::anyhow!("this mode needs a .cmd file"))?;
                KeySource::CommonKey {
                    common_key: qc::parse_hex16(&st.common_key).map_err(|e| anyhow::anyhow!("common key: {e}"))?,
                    encrypted_title_key: c.head.encrypted_title_key,
                    title_key_iv: c.head.title_key_iv,
                    content_iv: c.head.content_iv,
                }
            }
            DecMode::Sksa => unreachable!("handled above"),
            DecMode::Ticket => {
                let ticket = std::fs::read(st.ticket.as_ref().ok_or_else(|| anyhow::anyhow!("choose the ticket file"))?)?;
                let v2 = std::fs::read(st.virage2.as_ref().ok_or_else(|| anyhow::anyhow!("choose the Virage2 dump"))?)?;
                let common = qc::parse_hex16(&st.common_key).map_err(|e| anyhow::anyhow!("common key: {e}"))?;
                let ticket_data = if ticket.len() == qc::TICKET_LEN {
                    ticket.as_slice()
                } else {
                    let cid = st.ticket_content_id.trim().trim_start_matches("0x").trim_start_matches("0X");
                    let cid = u32::from_str_radix(cid, 16)
                        .map_err(|_| anyhow::anyhow!("enter the ticket.sys content ID as up to 8 hexadecimal digits"))?;
                    qc::select_ticket(&ticket, cid)?
                };
                let tk = qc::ticket_title_key(ticket_data, &v2, &common)?;
                let warn = if tk.bbid_matches { "" } else { " ⚠ ticket bbId differs from the Virage2 bbId (wrong console's files?)." };
                let msg =
                    self.finish_ique_decrypt(&input, &KeySource::Direct { key: tk.title_key, iv: tk.cmd.head.content_iv }, Some(&tk.cmd))?;
                return Ok(format!("{msg}{warn}"));
            }
            DecMode::Direct => KeySource::Direct {
                key: qc::parse_hex16(&st.key).map_err(|e| anyhow::anyhow!("key: {e}"))?,
                iv: match (cmd, st.iv.trim().is_empty()) {
                    (Some(c), true) => c.head.content_iv,
                    _ => iv_from_ui()?,
                },
            },
            DecMode::Recrypt => {
                let v2 = std::fs::read(st.virage2.as_ref().ok_or_else(|| anyhow::anyhow!("choose the Virage2 dump"))?)?;
                let rs = std::fs::read(st.recrypt_sys.as_ref().ok_or_else(|| anyhow::anyhow!("choose recrypt.sys"))?)?;
                let content_id = match (cmd, st.content_id.trim().is_empty()) {
                    (Some(c), true) => c.head.content_id,
                    _ => u32::from_str_radix(st.content_id.trim().trim_start_matches("0x"), 16)
                        .map_err(|_| anyhow::anyhow!("content ID must be up to 8 hex digits"))?,
                };
                let content_iv = match (cmd, st.iv.trim().is_empty()) {
                    (Some(c), true) => c.head.content_iv,
                    _ => iv_from_ui()?,
                };
                return self.finish_ique_decrypt(
                    &input,
                    &KeySource::Recrypt { virage2: &v2, recrypt_sys: &rs, content_id, content_iv },
                    None,
                );
            }
        };
        self.finish_ique_decrypt(&input, &source, None)
    }

    fn finish_ique_decrypt(&self, input: &std::path::Path, source: &KeySource, cmd_override: Option<&CmdFile>) -> anyhow::Result<String> {
        let data = std::fs::read(input)?;
        let mut plain = qc::decrypt(&data, source)?;
        let note: String;
        match cmd_override.or(self.ique_cmd.as_ref()) {
            Some(c) => {
                if qc::verify(&plain, c.head.size, &c.head.hash) {
                    plain.truncate(c.head.size as usize);
                    note = "SHA-1 matches the .cmd ✔ (padding removed)".into();
                } else {
                    note = "⚠ SHA-1 does NOT match the .cmd — wrong key/files, or a different app".into();
                }
            }
            None if qc::looks_like_rom(&plain) => note = "Output looks like an N64 ROM (no .cmd to verify against)".into(),
            None => note = "⚠ Output does not look like an N64 ROM and there is no .cmd to verify it".into(),
        }
        let name = input.file_stem().map_or("decrypted".into(), |s| s.to_string_lossy().into_owned());
        let Some(out) = rfd::FileDialog::new().set_file_name(format!("{name}.z64")).save_file() else {
            anyhow::bail!("save cancelled");
        };
        std::fs::write(&out, &plain)?;
        Ok(format!("Wrote {} ({} bytes). {note}", out.display(), plain.len()))
    }

    fn ui_ique_decrypt(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("🔓 Decrypt iQue content (.app / .rec)").show(ui, |ui| {
            ui.colored_label(
                egui::Color32::YELLOW,
                "You must supply every key and file yourself, from your own console or files you may legally use. \
                 Turtle64 includes no keys, and nothing you enter is saved or sent anywhere.",
            );
            ui.weak("SHA-1 checks compare against the supplied metadata; CMD, ticket and recrypt.sys signatures are not verified.");
            let st = &mut self.ique_dec;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut st.mode, DecMode::CommonKey, ".app (common key + .cmd)");
                ui.selectable_value(&mut st.mode, DecMode::Recrypt, ".rec (Virage2 + recrypt.sys)");
                ui.selectable_value(&mut st.mode, DecMode::Ticket, "Non-SA app (ticket + Virage2)");
                ui.selectable_value(&mut st.mode, DecMode::Sksa, "SKSA");
                ui.selectable_value(&mut st.mode, DecMode::Direct, "Direct key");
            });
            pick_row(ui, if st.mode == DecMode::Sksa { "📂 SKSA image…" } else { "📂 Encrypted file…" }, &mut st.input);
            match st.mode {
                DecMode::Ticket => {
                    pick_row(ui, "📂 Ticket or ticket.sys…", &mut st.ticket);
                    pick_row(ui, "📂 Virage2 dump (256+ bytes)…", &mut st.virage2);
                    key_row(ui, "Common key", &mut st.common_key);
                    ui.horizontal(|ui| {
                        ui.label("Content ID (ticket.sys only)");
                        ui.add(egui::TextEdit::singleline(&mut st.ticket_content_id).desired_width(100.0).hint_text("hex, e.g. 0010CD30"));
                    });
                    ui.weak(
                        "Unwraps the title key with the console's ECC private key (Virage2) and the ticket's server key (ECDH), \
                         then the common key. For ticket.sys, select a unique content ID. The ticket's CMD is used to check the SHA-1.",
                    );
                }
                DecMode::Sksa => {
                    key_row(ui, "Common key", &mut st.common_key);
                    key_row(ui, "SK key (optional)", &mut st.sk_key);
                    key_row(ui, "SK IV (optional)", &mut st.sk_iv);
                    ui.checkbox(&mut st.decompress_sa2, "Also decompress SA2 (raw DEFLATE)");
                    ui.weak(
                        "Writes sa1.bin / sa2.bin (SHA-1 checked) and, if an SK key and IV are given, sk.bin, into a folder. \
                         Optional decompression writes sa2-decompressed.bin separately, with a 64 MiB limit. \
                         SHA-1 is checked before decompression.",
                    );
                }
                DecMode::CommonKey => {
                    key_row(ui, "Common key", &mut st.common_key);
                    ui.weak(
                        "Needs a loaded .cmd (title key and IVs come from it). Works for apps with the SA flag; other apps use the ticket mode.",
                    );
                }
                DecMode::Recrypt => {
                    pick_row(ui, "📂 Virage2 dump (256+ bytes)…", &mut st.virage2);
                    pick_row(ui, "📂 recrypt.sys…", &mut st.recrypt_sys);
                    ui.horizontal(|ui| {
                        ui.label("Content ID");
                        ui.weak("(hex, as in the file name, e.g. 0010CD30 — not the decimal 1101104)");
                        ui.add(egui::TextEdit::singleline(&mut st.content_id).desired_width(100.0).hint_text("hex, from .cmd"));
                        ui.label("Content IV");
                        ui.add(egui::TextEdit::singleline(&mut st.iv).desired_width(300.0).hint_text("from .cmd"));
                    });
                }
                DecMode::Direct => {
                    key_row(ui, "AES key", &mut st.key);
                    ui.horizontal(|ui| {
                        ui.label("IV");
                        ui.add(egui::TextEdit::singleline(&mut st.iv).desired_width(300.0).hint_text("blank = content IV from .cmd"));
                    });
                }
            }
            if ui.button("🔓 Decrypt and save…").clicked() {
                self.ique_dec.status = Some(match self.run_ique_decrypt() {
                    Ok(m) => (true, m),
                    Err(e) => (false, e.to_string()),
                });
            }
            if let Some((ok, m)) = &self.ique_dec.status {
                ui.colored_label(if *ok { egui::Color32::LIGHT_GREEN } else { egui::Color32::LIGHT_RED }, m);
            }
        });
    }
}

impl Turtle64App {
    pub(super) fn ui_ique(&mut self, ui: &mut egui::Ui) {
        ui.heading("🐲 iQue Player");
        ui.weak("iQue-specific tools: container header, content metadata (.cmd) and decryption of encrypted content.");
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
        self.ui_ique_decrypt(ui);
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
                    ui.weak("Title text prefers GBK; display depends on the available font's character coverage.");
                });
            }
        });
    }
}
