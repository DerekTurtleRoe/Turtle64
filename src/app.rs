//! Turtle64 egui application: UI glue tying together ROM loading, header
//! display, hashing, DAT verification, single-file conversion, and batch
//! conversion with progress reporting.

use crate::batch::{BatchEvent, BatchJob};
use crate::dat::{DatCollection, DatKind};
use crate::dd_disk::{DdDiskInfo, DiskFormat};
use crate::dd_mfs::MfsEntry;
use crate::rom::RomInfo;
use crate::rom_format::RomFormat;
use eframe::egui;
use std::path::{Path, PathBuf};

/// Appends `suffix` to a path's full file name (name + extension), e.g.
/// `game.z64` + `_info.txt` -> `game.z64_info.txt`, preserving the parent
/// directory. Used so an auto-generated info report sits right next to the
/// file it describes without a second save dialog.
fn append_to_file_name(path: &Path, suffix: &str) -> PathBuf {
    let name = path.file_name().map(|s| format!("{}{suffix}", s.to_string_lossy())).unwrap_or_else(|| format!("output{suffix}"));
    path.with_file_name(name)
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Single,
    Batch,
    Disk,
    About,
}

/// What the Batch tab's "Action" selector does to each input ROM. Mirrors
/// `batch::BatchMode`, but kept separate since it drives UI state (e.g.
/// whether the target-format picker is shown) independently of the target
/// format itself.
#[derive(PartialEq, Clone, Copy)]
enum BatchAction {
    Convert,
    ExportInfo,
    ConvertAndExportInfo,
}

pub struct Turtle64App {
    tab: Tab,

    // DAT database (shared, immutable once loaded)
    dat: DatCollection,
    dat_error: Option<String>,
    dat_status: Option<String>,

    // Single ROM tab
    single_rom: Option<RomInfo>,
    single_error: Option<String>,
    single_status: Option<String>,
    single_target_format: RomFormat,
    single_use_native_hashes: bool,
    single_export_info_after_convert: bool,

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
    batch_action: BatchAction,
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
    disk_export_info_after_convert: bool,
}

impl Default for Turtle64App {
    fn default() -> Self {
        Self {
            tab: Tab::Single,
            dat: DatCollection::default(),
            dat_error: None,
            dat_status: None,
            single_rom: None,
            single_error: None,
            single_status: None,
            single_target_format: RomFormat::BigEndian,
            single_use_native_hashes: false,
            single_export_info_after_convert: false,
            bootcode_list: {
                let _ = crate::bootcode::ensure_bootcodes_dir();
                crate::bootcode::list_bootcodes()
            },
            selected_bootcode: None,
            fix_crc_on_patch: true,
            patched_rom: None,
            patch_error: None,
            patch_status: None,
            batch_inputs: Vec::new(),
            batch_target_format: RomFormat::BigEndian,
            batch_action: BatchAction::Convert,
            batch_output_dir: None,
            batch_same_as_source: true,
            batch_job: None,
            batch_log: Vec::new(),
            batch_error_count: 0,
            disk_info: None,
            disk_error: None,
            disk_target_format: DiskFormat::Ndd,
            disk_status: None,
            disk_export_info_after_convert: false,
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
            let results = self.dat.load_files(&[path]);
            self.apply_dat_load_results(results);
        }
    }

    /// Lets the user multi-select several (or all 8) No-Intro N64 DAT files
    /// at once, so they don't have to load them one at a time and switch
    /// between "which DAT is currently active" — each file is parsed and
    /// automatically routed into its matching [`DatKind`] slot.
    fn load_all_dats_dialog(&mut self) {
        let paths = rfd::FileDialog::new().add_filter("No-Intro DAT", &["dat", "xml"]).pick_files();
        if let Some(paths) = paths {
            let results = self.dat.load_files(&paths);
            self.apply_dat_load_results(results);
        }
    }

    fn apply_dat_load_results(&mut self, results: Vec<(PathBuf, Result<crate::dat::DatKind, String>)>) {
        let mut loaded = Vec::new();
        let mut failed = Vec::new();
        for (path, result) in results {
            match result {
                Ok(kind) => loaded.push(kind.label().to_string()),
                Err(e) => failed.push(format!("{}: {e}", path.display())),
            }
        }
        if !loaded.is_empty() {
            self.dat_status = Some(format!("✅ Loaded: {}", loaded.join(", ")));
        }
        self.dat_error = if failed.is_empty() { None } else { Some(failed.join("\n")) };
        // Loading a DAT can change verification results for an already-open
        // ROM/disk, so re-run against the newly loaded DAT set immediately.
        self.reload_single_rom();
    }

    /// Re-reads every currently loaded DAT from its original file path (no
    /// network access — see `DatCollection::recheck_all`), for the manual
    /// "Check for DAT updates" button: if the user has since downloaded a
    /// newer DAT to the same path, this picks up the new version/date/entry
    /// count without re-browsing for the file.
    fn recheck_dats(&mut self) {
        if self.dat.is_empty() {
            self.dat_status = None;
            self.dat_error = Some("No DAT files loaded yet — use \"Load DAT…\" or \"Load all DATs…\" first.".to_string());
            return;
        }
        let results = self.dat.recheck_all();
        let mut failed = Vec::new();
        for (kind, result) in &results {
            if let Err(e) = result {
                failed.push(format!("{}: {e}", kind.label()));
            }
        }
        self.dat_status = Some(format!("🔄 Re-checked {} loaded DAT file(s) from disk.", results.len()));
        self.dat_error = if failed.is_empty() { None } else { Some(failed.join("\n")) };
        self.reload_single_rom();
    }

    fn open_rom_dialog(&mut self) {
        if let Some(path) =
            rfd::FileDialog::new().add_filter("N64 ROMs", &["z64", "n64", "v64", "rom", "bin"]).add_filter("All files", &["*"]).pick_file()
        {
            self.load_single_rom(path);
        }
    }

    fn load_single_rom(&mut self, path: PathBuf) {
        match RomInfo::load(&path, Some(&self.dat), self.single_use_native_hashes) {
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

    /// Re-runs `load_single_rom` against the already-open ROM's path, used
    /// when the native-hash checkbox is toggled so the displayed info
    /// reflects the new setting immediately.
    fn reload_single_rom(&mut self) {
        if let Some(path) = self.single_rom.as_ref().map(|r| r.path.clone()) {
            self.load_single_rom(path);
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
        let _ = crate::bootcode::ensure_bootcodes_dir();
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
            .and_then(|ipl3| rom.with_patched_ipl3(&ipl3, self.fix_crc_on_patch, Some(&self.dat)));
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
            let target = self.disk_target_format;
            match disk.convert_to_file(target, &out_path) {
                Ok(()) => {
                    self.disk_status = Some(format!("✅ Saved {} to {}", target.label(), out_path.display()));
                    self.disk_error = None;
                    if self.disk_export_info_after_convert {
                        let info_out_path = append_to_file_name(&out_path, "_info.txt");
                        let report = disk.conversion_info_text(target, &out_path);
                        match std::fs::write(&info_out_path, report) {
                            Ok(()) => {
                                self.disk_status = Some(format!(
                                    "✅ Saved {} to {}; info exported to {}",
                                    target.label(),
                                    out_path.display(),
                                    info_out_path.display()
                                ));
                            }
                            Err(e) => self.disk_error = Some(format!("Conversion succeeded, but info export failed: {e}")),
                        }
                    }
                }
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
                    let loaded = self.dat.loaded_kinds();
                    ui.label(format!("📀 No-Intro DATs: {}/{} loaded", loaded.len(), DatKind::ALL.len()));
                    if ui
                        .button("Check for DAT updates")
                        .on_hover_text(
                            "Re-reads every loaded DAT from its file on disk (no network access — \
                         No-Intro's site prohibits automated/bot downloads). Use this after \
                         manually downloading a newer DAT to the same file path.",
                        )
                        .clicked()
                    {
                        self.recheck_dats();
                    }
                    if ui
                        .button("Load all DATs…")
                        .on_hover_text("Multi-select several (or all 8) No-Intro N64 DAT files at once.")
                        .clicked()
                    {
                        self.load_all_dats_dialog();
                    }
                    if ui.button("Load DAT…").clicked() {
                        self.load_dat_dialog();
                    }
                });
            });
            egui::CollapsingHeader::new("📀 Loaded No-Intro DAT files").default_open(false).show(ui, |ui| {
                egui::Grid::new("dat_versions_grid").striped(true).num_columns(4).show(ui, |ui| {
                    ui.strong("Kind");
                    ui.strong("DAT name");
                    ui.strong("Version / date");
                    ui.strong("Entries");
                    ui.end_row();
                    for kind in DatKind::ALL {
                        ui.label(kind.label());
                        match self.dat.get(kind) {
                            Some(loaded) => {
                                ui.label(&loaded.db.name);
                                let version = loaded.db.version.as_deref().or(loaded.db.date.as_deref()).unwrap_or("unknown");
                                ui.label(version);
                                ui.label(loaded.db.entry_count.to_string());
                            }
                            None => {
                                ui.weak("not loaded");
                                ui.weak("—");
                                ui.weak("—");
                            }
                        }
                        ui.end_row();
                    }
                });
            });
            if let Some(status) = &self.dat_status {
                ui.colored_label(egui::Color32::LIGHT_GREEN, status);
            }
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
    ui.label("• Verifies ROMs against up to 8 loaded No-Intro DAT files at once (N64 BigEndian/ByteSwapped, 64DD, Mario no Photopie SmartMedia, iQue CDN/Decrypted, Aleck64 BigEndian/ByteSwapped) — load one, multi-select several at once, or re-check already-loaded DATs from disk for updates (no automated downloading: No-Intro's site prohibits bot access, so this never touches the network)");
    ui.label("• Dumps a ROM's IPL3 boot code for inspection, or patches in any dumped IPL3 from the \"bootcodes\" folder — bundled with ready-to-use dumps of all 8 libdragon open-source IPL3 revisions (r1-r8), which Turtle64 also fingerprints and identifies by name during CIC detection");
    ui.label("• Full N64DD (64DD disk drive) support: disk info, hashing, CIC identification, MFS filesystem browsing/extraction, and conversion between .d64 / .ndd / MAME disk image formats");
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    ui.label("With thanks to:");
    ui.label("• mroach/ROM64 and jkbenaim/romjudge — the tools that inspired Turtle64's cartridge ROM feature set");
    ui.label("• LuigiBlood's 64dd wiki and leo64dd_python — invaluable public documentation of 64DD disk image formats and CICs");
    ui.label("• jkbenaim/leotools — reference for 64DD disk-info fields and MFS filesystem layout");
    ui.label("• Happy-yappH/ddconvert and LuigiBlood/ddconvert_back — reference for MAME physical disk layout conversion");
    ui.label("• DragonMinded/libdragon — its open-source IPL3 (public domain/Unlicense) is bundled directly in Turtle64 for IPL3 dumping/patching, and its published revision checksums were used to fingerprint each release for CIC identification");
    ui.weak("No source code from any of the above was copied into Turtle64 — their public documentation and algorithms were independently reimplemented in Rust. The libdragon IPL3 binaries are the one exception: they are redistributed as-is (unmodified, public domain) for convenience.");
}

mod batch_tab;
mod disk_tab;
mod single_tab;
