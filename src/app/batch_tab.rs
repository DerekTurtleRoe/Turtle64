//! "Batch" tab: pick files/folders, then either convert everything to a
//! target format or export each ROM's info to a text report, all on
//! background threads with a live progress bar and log.

use super::{BatchAction, Turtle64App};
use crate::batch::{self, BatchMode};
use crate::rom_format::RomFormat;
use eframe::egui;
use std::sync::atomic::Ordering;

impl Turtle64App {
    pub(super) fn ui_batch(&mut self, ui: &mut egui::Ui) {
        let running = self.batch_job.is_some();

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                if ui.button("📄 Add Files…").clicked() {
                    if let Some(paths) = rfd::FileDialog::new().add_filter("N64 ROMs", &["z64", "n64", "v64", "rom", "bin"]).pick_files() {
                        self.batch_inputs.extend(paths);
                    }
                }
                if ui.button("📁 Add Folder…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.batch_inputs.push(path);
                    }
                }
                if ui.button("🗑 Clear list").clicked() {
                    self.batch_inputs.clear();
                }
            });
        });

        ui.label(format!("{} input(s) selected (files and/or folders)", self.batch_inputs.len()));
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
            for p in &self.batch_inputs {
                ui.label(p.display().to_string());
            }
        });

        ui.add_space(8.0);
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Action:");
            ui.selectable_value(&mut self.batch_action, BatchAction::Convert, "🔄 Convert format");
            ui.selectable_value(&mut self.batch_action, BatchAction::ExportInfo, "📝 Export info to text");
            ui.selectable_value(&mut self.batch_action, BatchAction::ConvertAndExportInfo, "🔄📝 Convert & export info");
        });

        match self.batch_action {
            BatchAction::ExportInfo => {
                ui.weak("Writes a <name>.<ext>_info.txt report (header, checksums, hashes, No-Intro verification) for each ROM.");
            }
            BatchAction::Convert | BatchAction::ConvertAndExportInfo => {
                ui.horizontal(|ui| {
                    ui.label("Target format:");
                    egui::ComboBox::from_id_salt("batch_target_format").selected_text(self.batch_target_format.label()).show_ui(ui, |ui| {
                        for fmt in RomFormat::all_targets() {
                            ui.selectable_value(&mut self.batch_target_format, fmt, fmt.label());
                        }
                    });
                });
                if self.batch_action == BatchAction::ConvertAndExportInfo {
                    ui.weak("Converts each ROM, then also writes a <converted name>_info.txt report next to it.");
                }
            }
        }

        ui.checkbox(&mut self.batch_same_as_source, "Write output next to each source file");
        if !self.batch_same_as_source {
            ui.horizontal(|ui| {
                if ui.button("Choose output folder…").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        self.batch_output_dir = Some(dir);
                    }
                }
                if let Some(dir) = &self.batch_output_dir {
                    ui.label(dir.display().to_string());
                } else {
                    ui.weak("(none selected)");
                }
            });
        }

        ui.add_space(8.0);
        ui.add_enabled_ui(!running && !self.batch_inputs.is_empty(), |ui| {
            let button_label = match self.batch_action {
                BatchAction::ExportInfo => "▶ Start Batch Info Export",
                BatchAction::Convert => "▶ Start Batch Conversion",
                BatchAction::ConvertAndExportInfo => "▶ Start Batch Conversion + Info Export",
            };
            if ui.button(egui::RichText::new(button_label).strong()).clicked() {
                self.batch_log.clear();
                self.batch_error_count = 0;
                let files = batch::collect_rom_files(&self.batch_inputs);
                let output_dir = if self.batch_same_as_source { None } else { self.batch_output_dir.clone() };
                let mode = match self.batch_action {
                    BatchAction::ExportInfo => BatchMode::ExportInfo,
                    BatchAction::Convert => BatchMode::Convert(self.batch_target_format),
                    BatchAction::ConvertAndExportInfo => BatchMode::ConvertAndExportInfo(self.batch_target_format),
                };
                let job = batch::spawn_batch(files, mode, output_dir, Some(std::sync::Arc::new(self.dat.clone())));
                self.batch_job = Some(job);
            }
        });

        ui.add_space(8.0);

        let mut clear_job = false;
        if let Some(job) = &self.batch_job {
            let completed = job.completed.load(Ordering::SeqCst);
            let total = job.total.max(1);
            let fraction = completed as f32 / total as f32;
            let elapsed = job.started_at.elapsed().as_secs_f32();
            let eta = if completed > 0 {
                let per_item = elapsed / completed as f32;
                let remaining = (total - completed) as f32 * per_item;
                format!(" — ETA {:.0}s", remaining.max(0.0))
            } else {
                String::new()
            };
            ui.add(egui::ProgressBar::new(fraction).text(format!("{completed} / {total}{eta}")).animate(true));
            if completed >= job.total {
                let verb = match self.batch_action {
                    BatchAction::ExportInfo => "processed",
                    BatchAction::Convert | BatchAction::ConvertAndExportInfo => "converted",
                };
                ui.colored_label(
                    egui::Color32::LIGHT_GREEN,
                    format!("✅ Batch complete: {} {verb}, {} failed", job.total - self.batch_error_count, self.batch_error_count),
                );
                clear_job = true;
            }
        }
        if clear_job {
            self.batch_job = None;
        }

        ui.separator();
        ui.label("Log:");
        egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for line in &self.batch_log {
                ui.label(line);
            }
        });
    }
}
