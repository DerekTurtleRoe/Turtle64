//! Batch conversion engine: scans files/folders, converts each ROM to a
//! target format and/or exports its info to a text report, on a background
//! thread pool, and reports progress back to the GUI thread over a channel.

use crate::dat::DatCollection;
use crate::rom::{self, RomInfo};
use crate::rom_format::RomFormat;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// What a batch job does to each input ROM.
#[derive(Debug, Clone, Copy)]
pub enum BatchMode {
    /// Convert each ROM to `RomFormat` and write the converted ROM.
    Convert(RomFormat),
    /// Parse each ROM and write a `<name>.<ext>_info.txt` report instead of
    /// converting it (the source extension is kept in the report's name so
    /// same-named ROMs of different formats don't overwrite each other).
    ExportInfo,
    /// Convert each ROM to `RomFormat` *and* write a
    /// `<converted name>_info.txt` report alongside the converted output.
    ConvertAndExportInfo(RomFormat),
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields retained for future UI (per-file index/log) use
pub enum BatchEvent {
    Started { total: usize },
    FileDone { index: usize, path: PathBuf, result: Result<PathBuf, String> },
    Finished,
}

pub struct BatchJob {
    pub receiver: Receiver<BatchEvent>,
    pub total: usize,
    pub completed: Arc<AtomicUsize>,
    pub started_at: Instant,
    #[allow(dead_code)]
    pub results: Vec<(PathBuf, Result<PathBuf, String>)>,
}

/// Recursively collects candidate ROM files from a mix of file and folder
/// paths.
pub fn collect_rom_files(inputs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for input in inputs {
        if input.is_dir() {
            for entry in walkdir::WalkDir::new(input).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() && rom::is_probably_rom(entry.path()) {
                    out.push(entry.path().to_path_buf());
                }
            }
        } else if input.is_file() {
            out.push(input.clone());
        }
    }
    out
}

/// Spawns a small thread pool to process every input file according to
/// `mode` (convert to a target format, or export an info text report),
/// writing outputs into `output_dir` (or alongside the source file when
/// `output_dir` is `None`), and returns a handle for polling progress.
pub fn spawn_batch(files: Vec<PathBuf>, mode: BatchMode, output_dir: Option<PathBuf>, dat: Option<Arc<DatCollection>>) -> BatchJob {
    let (tx, rx): (Sender<BatchEvent>, Receiver<BatchEvent>) = std::sync::mpsc::channel();
    let total = files.len();
    let completed = Arc::new(AtomicUsize::new(0));

    let _ = tx.send(BatchEvent::Started { total });

    let queue = Arc::new(Mutex::new(files.into_iter().enumerate().collect::<Vec<(usize, PathBuf)>>()));

    let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8);

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let completed = Arc::clone(&completed);
        let output_dir = output_dir.clone();
        let dat = dat.clone();

        std::thread::spawn(move || loop {
            let item = {
                let mut q = queue.lock().unwrap();
                q.pop()
            };
            let Some((index, path)) = item else { break };

            let result = process_one(&path, mode, output_dir.as_deref(), dat.as_deref());
            completed.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(BatchEvent::FileDone { index, path, result });
        });
    }

    // Sentinel thread: waits for all workers to logically finish by
    // dropping the last sender once queue is drained. We detect completion
    // in the GUI by comparing completed count to total instead of relying
    // on channel closure, so no extra thread is required here.
    drop(tx);

    BatchJob { receiver: rx, total, completed, started_at: Instant::now(), results: Vec::new() }
}

fn process_one(path: &Path, mode: BatchMode, output_dir: Option<&Path>, dat: Option<&DatCollection>) -> Result<PathBuf, String> {
    // Batch mode never needs native-order hashes; it's a single-ROM
    // "checking ROM info" option only.
    let info = RomInfo::load(path, dat, false).map_err(|e| format!("read/parse failed: {e}"))?;
    let file_stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "rom".to_string());

    match mode {
        BatchMode::Convert(target) => {
            let out_name = format!("{file_stem}.{}", target.extension());
            let out_path = match output_dir {
                Some(dir) => dir.join(out_name),
                None => path.with_file_name(out_name),
            };
            info.convert_to_file(target, &out_path).map_err(|e| format!("write failed: {e}"))?;
            Ok(out_path)
        }
        BatchMode::ExportInfo => {
            // Include the source file's own extension in the report name
            // (e.g. "game.z64_info.txt" vs "game.v64_info.txt") so that
            // same-named ROMs of different formats in one folder don't
            // overwrite each other's info reports.
            let file_name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| file_stem.clone());
            let out_name = format!("{file_name}_info.txt");
            let out_path = match output_dir {
                Some(dir) => dir.join(out_name),
                None => path.with_file_name(out_name),
            };
            std::fs::write(&out_path, info.info_text()).map_err(|e| format!("write failed: {e}"))?;
            Ok(out_path)
        }
        BatchMode::ConvertAndExportInfo(target) => {
            let out_name = format!("{file_stem}.{}", target.extension());
            let out_path = match output_dir {
                Some(dir) => dir.join(&out_name),
                None => path.with_file_name(&out_name),
            };
            info.convert_to_file(target, &out_path).map_err(|e| format!("write failed: {e}"))?;

            // The converted output's own name (with its new extension)
            // already disambiguates same-named ROMs of different formats.
            let info_out_name = format!("{out_name}_info.txt");
            let info_out_path = match output_dir {
                Some(dir) => dir.join(info_out_name),
                None => path.with_file_name(info_out_name),
            };
            let report = info.conversion_info_text(target, &out_path);
            std::fs::write(&info_out_path, report).map_err(|e| format!("info export failed: {e}"))?;
            Ok(out_path)
        }
    }
}
