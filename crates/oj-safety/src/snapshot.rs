//! What a file looked like when it was scanned.

use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use oj_windows::FileId;

/// A file as it was at scan time. Before acting on it, the executor checks
/// that it still looks exactly like this (PLANNING.md §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub path: PathBuf,
    /// Logical size in bytes.
    pub len: u64,
    /// Bytes allocated on disk.
    pub allocated: u64,
    /// Number of hard links.
    pub links: u32,
    pub modified: SystemTime,
    /// Which file object this is. A different file put at the same path
    /// has a different ID.
    pub file_id: FileId,
}

impl FileSnapshot {
    /// Captures a snapshot. `metadata` must come from a call that doesn't
    /// follow reparse points.
    pub fn capture(path: &Path, metadata: &Metadata) -> io::Result<Self> {
        let info = oj_windows::disk_info(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            len: metadata.len(),
            allocated: info.allocated,
            links: info.links,
            modified: metadata.modified()?,
            file_id: info.file_id,
        })
    }

    /// Bytes actually freed by deleting this file. A file with other hard
    /// links frees nothing, because the data is still referenced.
    pub fn reclaimable(&self) -> u64 {
        if self.links <= 1 { self.allocated } else { 0 }
    }
}
