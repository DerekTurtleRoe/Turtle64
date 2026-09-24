//! Turtle64 egui application: UI glue tying together ROM loading, header
//! display, hashing, DAT verification, single-file conversion, and batch
//! conversion with progress reporting.

use crate::batch::{BatchEvent, BatchJob};
use crate::dat::DatDatabase;
use crate::dd_disk::{DdDiskInfo, DiskFormat};
use crate::dd_mfs::MfsEntry;
use crate::rom::RomInfo;
use crate::rom_format::RomFormat;
use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Single,
    Batch,
    Disk,
    About,
}

pub struct Turtle64App {
    tab: Tab,

    // DAT database (shared, immutable once loaded)
    dat: Option<Arc<DatDatabase>>,
    dat_error: Option<String>,

    // Single ROM tab
    single_rom: Option<RomInfo>,
    single_error: Option<String>,
    single_status: Option<String>,
    single_target_format: RomFormat,

    // IPL3 boot-code dump/patch (Single ROM tab)
    bootcode_list: Vec<PathBuf>,
    selected_bootcode: Option<PathBuf>,
    fix_crc_on_patch: bool,
    patched_rom: Option<RomInfo>,
    patch_error: Option<String>,
    patch_status: Option<String>,

    // Batch tab
    batch_inputs: Vec<PathBuf>,
    batch_target_format: RomFormat,
    batch_mode_is_export: bool,
    batch_output_dir: Option<PathBuf>,
    batch_same_as_source: bool,
    batch_job: Option<BatchJob>,
    batch_log: Vec<String>,
    batch_error_count: usize,

    // 64DD Disk tab
    disk_info: Option<DdDiskInfo>,
    disk_error: Option<String>,
    disk_target_format: DiskFormat,
    disk_status: Option<String>,
}

impl Default for Turtle64App {
    fn default() -> Self {
        Self {
            tab: Tab::Single,
            dat: None,
            dat_error: None,
            single_rom: None,
            single_error: None,
            single_status: None,
            single_target_format: RomFormat::BigEndian,
            bootcode_list: crate::bootcode::list_bootcodes(),
            selected_bootcode: None,
            fix_crc_on_patch: true,
            patched_rom: None,
            patch_error: None,
            patch_status: None,
            batch_inputs: Vec::new(),
            batch_target_format: RomFormat::BigEndian,
            batch_mode_is_export: false,
            batch_output_dir: None,
            batch_same_as_source: true,
            batch_job: None,
            batch_log: Vec::new(),
            batch_error_count: 0,
            disk_info: None,
            disk_error: None,
            disk_target_format: DiskFormat::Ndd,
            disk_status: None,
        }
    }
}

impl Turtle64App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_style(&cc.egui_ctx);
        Self::default()
    }

    fn load_dat_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("No-Intro DAT", &["dat", "xml"]).pick_file() {
            match DatDatabase::load_from_file(&path) {
                Ok(db) => {
                    self.dat_error = None;
                    self.dat = Some(Arc::new(db));
                }
                Err(e) => {
                    self.dat_error = Some(format!("Failed to load DAT: {e}"));
                }
            }
        }
    }

    fn open_rom_dialog(&mut self) {
        if let Some(path) =
            rfd::FileDialog::new().add_filter("N64 ROMs", &["z64", "n64", "v64", "rom", "bin"]).add_filter("All files", &["*"]).pick_file()
        {
            self.load_single_rom(path);
        }
    }

    fn load_single_rom(&mut self, path: PathBuf) {
        match RomInfo::load(&path, self.dat.as_deref()) {
            Ok(info) => {
                self.single_error = None;
                self.single_status = None;
                self.single_rom = Some(info);
                self.patched_rom = None;
                self.patch_error = None;
                self.patch_status = None;
            }
            Err(e) => {
                self.single_error = Some(format!("Failed to load ROM: {e}"));
                self.single_rom = None;
            }
        }
    }

    fn export_rom_info_dialog(&mut self) {
        let Some(rom) = &self.single_rom else { return };
        let default_name =
            rom.path.file_name().map(|s| format!("{}_info.txt", s.to_string_lossy())).unwrap_or_else(|| "rom_info.txt".to_string());
        if let Some(out_path) = rfd::FileDialog::new().add_filter("Text file", &["txt"]).set_file_name(&default_name).save_file() {
            match std::fs::write(&out_path, rom.info_text()) {
                Ok(()) => {
                    self.single_error = None;
                    self.single_status = Some(format!("✅ ROM info exported to {}", out_path.display()));
                }
                Err(e) => self.single_error = Some(format!("Failed to export ROM info: {e}")),
            }
        }
    }

    fn dump_ipl3_dialog(&mut self) {
        let Some(rom) = &self.single_rom else { return };
        let Some(ipl3) = rom.ipl3_bytes() else {
            self.patch_error = Some("ROM is too small to contain an IPL3 region.".to_string());
            return;
        };
        let default_dir = crate::bootcode::ensure_bootcodes_dir().unwrap_or_else(|_| crate::bootcode::bootcodes_dir());
        let default_name =
            rom.path.file_stem().map(|s| format!("{}_ipl3.bin", s.to_string_lossy())).unwrap_or_else(|| "ipl3_dump.bin".to_string());
        if let Some(out_path) = rfd::FileDialog::new().set_directory(&default_dir).set_file_name(&default_name).save_file() {
            match std::fs::write(&out_path, &ipl3) {
                Ok(()) => {
                    self.patch_error = None;
                    self.patch_status = Some(format!("✅ IPL3 dumped to {}", out_path.display()));
                    self.refresh_bootcode_list();
                }
                Err(e) => self.patch_error = Some(format!("Failed to write IPL3 dump: {e}")),
            }
        }
    }

    fn refresh_bootcode_list(&mut self) {
        self.bootcode_list = crate::bootcode::list_bootcodes();
        if let Some(selected) = &self.selected_bootcode {
            if !self.bootcode_list.contains(selected) {
                self.selected_bootcode = None;
            }
        }
    }

    fn patch_selected_bootcode(&mut self) {
        let (Some(rom), Some(bootcode_path)) = (&self.single_rom, self.selected_bootcode.clone()) else {
            return;
        };
        let result = crate::bootcode::load_bootcode_file(&bootcode_path)
            .and_then(|ipl3| rom.with_patched_ipl3(&ipl3, self.fix_crc_on_patch, self.dat.as_deref()));
        match result {
            Ok(patched) => {
                self.patch_error = None;
                self.patch_status = Some(format!(
                    "✅ Patched with {} — preview below, choose \"Save patched ROM As…\" to write it out",
                    bootcode_path.display()
                ));
                self.patched_rom = Some(patched);
            }
            Err(e) => {
                self.patch_error = Some(format!("Failed to patch IPL3: {e}"));
                self.patched_rom = None;
            }
        }
    }

    fn save_patched_rom_dialog(&mut self) {
        let Some(patched) = &self.patched_rom else { return };
        let default_name = patched
            .path
            .file_stem()
            .map(|s| format!("{}_patched.{}", s.to_string_lossy(), self.single_target_format.extension()))
            .unwrap_or_else(|| format!("patched.{}", self.single_target_format.extension()));
        if let Some(out_path) = rfd::FileDialog::new().set_file_name(&default_name).save_file() {
            if let Err(e) = patched.convert_to_file(self.single_target_format, &out_path) {
                self.patch_error = Some(format!("Failed to save patched ROM: {e}"));
            } else {
                self.patch_error = None;
                self.patch_status = Some(format!("✅ Patched ROM saved to {}", out_path.display()));
            }
        }
    }

    fn open_disk_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("64DD Disk Images", crate::dd_disk::DISK_EXTENSIONS)
            .add_filter("All files", &["*"])
            .pick_file()
        {
            match DdDiskInfo::load(&path) {
                Ok(info) => {
                    self.disk_error = None;
                    self.disk_status = None;
                    self.disk_info = Some(info);
                }
                Err(e) => {
                    self.disk_error = Some(format!("Failed to load disk image: {e}"));
                    self.disk_info = None;
                }
            }
        }
    }

    fn export_disk_info_dialog(&mut self) {
        let Some(disk) = &self.disk_info else { return };
        let default_name =
            disk.path.file_name().map(|s| format!("{}_info.txt", s.to_string_lossy())).unwrap_or_else(|| "disk_info.txt".to_string());
        if let Some(out_path) = rfd::FileDialog::new().add_filter("Text file", &["txt"]).set_file_name(&default_name).save_file() {
            match std::fs::write(&out_path, disk.info_text()) {
                Ok(()) => {
                    self.disk_error = None;
                    self.disk_status = Some(format!("✅ Disk info exported to {}", out_path.display()));
                }
                Err(e) => self.disk_error = Some(format!("Failed to export disk info: {e}")),
            }
        }
    }

    fn save_converted_disk_dialog(&mut self) {
        let Some(disk) = &self.disk_info else { return };
        let default_name = disk
            .path
            .file_stem()
            .map(|s| format!("{}.{}", s.to_string_lossy(), self.disk_target_format.extension()))
            .unwrap_or_else(|| format!("disk.{}", self.disk_target_format.extension()));
        if let Some(out_path) = rfd::FileDialog::new().set_file_name(&default_name).save_file() {
            match disk.convert_to_file(self.disk_target_format, &out_path) {
                Ok(()) => self.disk_status = Some(format!("✅ Saved {} to {}", self.disk_target_format.label(), out_path.display())),
                Err(e) => self.disk_error = Some(format!("Failed to save converted disk image: {e}")),
            }
        }
    }

    fn extract_mfs_entry(&mut self, entry: MfsEntry) {
        let Some(disk) = &self.disk_info else { return };
        let Some(bytes) = disk.extract_mfs_file(&entry) else {
            self.disk_status = Some(format!("❌ Could not extract {}", entry.name));
            return;
        };
        if let Some(out_path) = rfd::FileDialog::new().set_file_name(&entry.name).save_file() {
            match std::fs::write(&out_path, &bytes) {
                Ok(()) => self.disk_status = Some(format!("✅ Extracted {} ({} bytes) to {}", entry.name, bytes.len(), out_path.display())),
                Err(e) => self.disk_status = Some(format!("❌ Failed to write {}: {e}", out_path.display())),
            }
        }
    }

    fn poll_batch(&mut self) {
        let Some(job) = &mut self.batch_job else {
            return;
        };
        while let Ok(event) = job.receiver.try_recv() {
            match event {
                BatchEvent::Started { .. } => {}
                BatchEvent::FileDone { path, result, .. } => match result {
                    Ok(out) => self.batch_log.push(format!("✅ {} -> {}", path.display(), out.display())),
                    Err(e) => {
                        self.batch_error_count += 1;
                        self.batch_log.push(format!("❌ {}: {}", path.display(), e));
                    }
                },
                BatchEvent::Finished => {}
            }
        }
    }
}

impl eframe::App for Turtle64App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_batch();
        if self.batch_job.is_some() {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("🐢 Turtle64").size(26.0).strong());
                ui.label(egui::RichText::new("N64 ROM toolkit").italics().weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let dat_label = match &self.dat {
                        Some(db) => format!("📀 DAT: {} ({} entries)", db.name, db.entry_count),
                        None => "📀 No DAT loaded".to_string(),
                    };
                    ui.label(dat_label);
                    if ui.button("Load No-Intro DAT…").clicked() {
                        self.load_dat_dialog();
                    }
                });
            });
            if let Some(err) = &self.dat_error {
                ui.colored_label(egui::Color32::LIGHT_RED, err);
            }
            ui.add_space(4.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Single, "🔍 Single ROM");
                ui.selectable_value(&mut self.tab, Tab::Batch, "📦 Batch");
                ui.selectable_value(&mut self.tab, Tab::Disk, "💽 64DD Disk");
                ui.selectable_value(&mut self.tab, Tab::About, "ℹ About");
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Single => self.ui_single(ui),
            Tab::Batch => self.ui_batch(ui),
            Tab::Disk => self.ui_disk(ui),
            Tab::About => ui_about(ui),
        });
    }
}

fn apply_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    let accent = egui::Color32::from_rgb(0x3D, 0xB8, 0x6A); // turtle green
    visuals.selection.bg_fill = accent;
    visuals.hyperlink_color = egui::Color32::from_rgb(0x6C, 0xD4, 0xA0);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x2E, 0x40, 0x3A);
    visuals.widgets.active.bg_fill = accent.linear_multiply(0.7);
    visuals.window_rounding = egui::Rounding::same(8.0);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}

fn ui_about(ui: &mut egui::Ui) {
    ui.heading("Turtle64");
    ui.label("Inspired by the excellent ROM64 and romjudge projects — convert, inspect, checksum and verify N64 ROMs.");
    ui.add_space(8.0);
    ui.label("Features:");
    ui.label("• Detects ROM byte order (big-endian / byte-swapped / little-endian) from file contents, never file extension");
    ui.label("• Converts between .z64 / .v64 / .n64, single file or whole folders");
    ui.label("• Parses the full N64 ROM header, including the Advanced Homebrew ROM Header");
    ui.label("• Calculates legacy IPL3 CRC1/CRC2 (with CIC boot-chip detection) and compares against the header");
    ui.label("• Calculates CRC32 / MD5 / SHA-1 for modern ROM databases");
    ui.label("• Verifies ROMs against a loaded No-Intro DAT file (good dump / bad dump / not found)");
    ui.label("• Dumps a ROM's IPL3 boot code for inspection, or patches in any dumped IPL3 from the \"bootcodes\" folder");
    ui.label("• Full N64DD (64DD disk drive) support: disk info, hashing, CIC identification, MFS filesystem browsing/extraction, and conversion between .d64 / .ndd / MAME disk image formats");
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    ui.label("With thanks to:");
    ui.label("• mroach/ROM64 and jkbenaim/romjudge — the tools that inspired Turtle64's cartridge ROM feature set");
    ui.label("• LuigiBlood's 64dd wiki and leo64dd_python — invaluable public documentation of 64DD disk image formats and CICs");
    ui.label("• jkbenaim/leotools — reference for 64DD disk-info fields and MFS filesystem layout");
    ui.label("• Happy-yappH/ddconvert and LuigiBlood/ddconvert_back — reference for MAME physical disk layout conversion");
    ui.weak("No source code from any of the above was copied into Turtle64 — their public documentation and algorithms were independently reimplemented in Rust.");
}

mod batch_tab;
mod disk_tab;
mod single_tab;
