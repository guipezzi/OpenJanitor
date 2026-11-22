//! A traversal that never leaves the folder it was asked to walk.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::attrs::{EntryClass, classify_metadata};
use crate::deny::DenyList;
use crate::snapshot::FileSnapshot;

/// How many unreadable paths to keep as examples in a report.
const MAX_SAMPLES: usize = 10;

/// What a walk saw and skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WalkStats {
    pub files: u64,
    pub directories: u64,
    pub skipped_reparse_points: u64,
    pub skipped_cloud_files: u64,
    pub skipped_protected: u64,
    pub unreadable: u64,
    /// The first few paths that couldn't be read.
    pub unreadable_samples: Vec<PathBuf>,
}

impl WalkStats {
    fn note_unreadable(&mut self, path: &Path) {
        self.unreadable += 1;
        if self.unreadable_samples.len() < MAX_SAMPLES {
            self.unreadable_samples.push(path.to_path_buf());
        }
    }

    /// Adds another walk's numbers to this one.
    pub fn merge(&mut self, other: WalkStats) {
        self.files += other.files;
        self.directories += other.directories;
        self.skipped_reparse_points += other.skipped_reparse_points;
        self.skipped_cloud_files += other.skipped_cloud_files;
        self.skipped_protected += other.skipped_protected;
        self.unreadable += other.unreadable;
        for sample in other.unreadable_samples {
            if self.unreadable_samples.len() < MAX_SAMPLES {
                self.unreadable_samples.push(sample);
            }
        }
    }
}

/// Lets another thread stop a running walk, for example when the user
/// cancels a scan. Clones share the same flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks every walk using this token to stop as soon as possible.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Walks `root` and calls `on_file` for every regular file the deny list
/// allows.
///
/// - Reparse points (junctions, symlinks, mount points) are never entered.
/// - Cloud placeholders are skipped entirely.
/// - Folders the deny list fully protects are skipped without being read.
/// - Only metadata is read; file contents are never opened.
/// - Once `cancel` is cancelled, the walk stops before the next folder or
///   file and returns what it saw so far.
pub fn walk_files(
    root: &Path,
    deny: &DenyList,
    cancel: &CancelToken,
    mut on_file: impl FnMut(FileSnapshot),
) -> WalkStats {
    let mut stats = WalkStats::default();

    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(_) => {
            stats.note_unreadable(root);
            return stats;
        }
    };
    match classify_metadata(&metadata) {
        EntryClass::Directory => {}
        EntryClass::File => {
            visit_file(root, &metadata, deny, &mut stats, &mut on_file);
            return stats;
        }
        EntryClass::ReparsePoint => {
            stats.skipped_reparse_points += 1;
            return stats;
        }
        EntryClass::CloudPlaceholder => {
            stats.skipped_cloud_files += 1;
            return stats;
        }
    }

    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if cancel.is_cancelled() {
            break;
        }
        if deny.denies_subtree(&dir) {
            stats.skipped_protected += 1;
            continue;
        }
        stats.directories += 1;
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                stats.note_unreadable(&dir);
                continue;
            }
        };
        for entry in entries {
            if cancel.is_cancelled() {
                break;
            }
            let Ok(entry) = entry else {
                stats.note_unreadable(&dir);
                continue;
            };
            let path = entry.path();
            // On Windows, DirEntry::metadata describes the entry itself and
            // never follows a reparse point.
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    stats.note_unreadable(&path);
                    continue;
                }
            };
            match classify_metadata(&metadata) {
                EntryClass::Directory => pending.push(path),
                EntryClass::File => visit_file(&path, &metadata, deny, &mut stats, &mut on_file),
                EntryClass::ReparsePoint => stats.skipped_reparse_points += 1,
                EntryClass::CloudPlaceholder => stats.skipped_cloud_files += 1,
            }
        }
    }
    stats
}

fn visit_file(
    path: &Path,
    metadata: &fs::Metadata,
    deny: &DenyList,
    stats: &mut WalkStats,
    on_file: &mut impl FnMut(FileSnapshot),
) {
    if deny.check(path).is_err() {
        stats.skipped_protected += 1;
        return;
    }
    match FileSnapshot::capture(path, metadata) {
        Ok(snapshot) => {
            stats.files += 1;
            on_file(snapshot);
        }
        Err(_) => stats.note_unreadable(path),
    }
}
