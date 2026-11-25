//! The audit log (PLANNING.md §4.8): every action of every cleanup, one
//! JSON object per line, appended to `history.jsonl`. It never leaves the
//! machine.
//!
//! Each line has a `type`:
//!
//! - `file`: one file a cleanup acted on, or tried to, with the result. A
//!   Recycle Bin gets one too, with its folder as `path` and its `items`.
//! - `folder`: a folder removed because the cleanup left it empty.
//! - `cleanup`: the totals, written last.
//! - `quarantine`: a quarantined file restored (`restore`), deleted for
//!   good on request (`delete`) or because its time was up (`expired`), or
//!   a file moved into quarantine because a restore replaced it
//!   (`replace`).
//! - `quarantine_totals`: the totals of one restore or delete, written
//!   last.
//!
//! Lines of one cleanup share its `cleanup` number, and lines of one
//! quarantine action share its `action_id` (both: when it started, in
//! milliseconds since the Unix epoch). `mode` says whether it was a dry
//! run. Times are in seconds since the Unix epoch.
//!
//! Totals lines are kept forever; the per-file lines are trimmed after
//! [`crate::history_view::DETAIL_DAYS`] days (D30).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use oj_safety::{Mode, Outcome};
use serde::{Deserialize, Serialize};

use crate::clean::{Action, CleanReport};
use crate::quarantine::QuarantineReport;
use crate::scan::{Finding, Target};

/// The line format written by this version, in each line's `v`.
pub const FORMAT_VERSION: u32 = 1;

/// The log file, open for appending.
#[derive(Debug)]
pub struct History {
    file: File,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Line<'a> {
    File {
        v: u32,
        cleanup: u64,
        at: u64,
        mode: Mode,
        rule_id: &'a str,
        path: &'a Path,
        size: u64,
        /// For a Recycle Bin: the items in it.
        #[serde(skip_serializing_if = "Option::is_none")]
        items: Option<u64>,
        action: Action,
        #[serde(flatten)]
        outcome: &'a Outcome,
    },
    Folder {
        v: u32,
        cleanup: u64,
        at: u64,
        mode: Mode,
        path: &'a Path,
    },
    Cleanup {
        v: u32,
        cleanup: u64,
        started_at: u64,
        finished_at: u64,
        #[serde(flatten)]
        report: &'a CleanReport,
    },
    Quarantine {
        v: u32,
        action_id: u64,
        at: u64,
        mode: Mode,
        action: QuarantineAction,
        quarantine_batch: &'a str,
        quarantine_item: u32,
        /// Where the file came from.
        path: &'a Path,
        size: u64,
        #[serde(flatten)]
        outcome: &'a Outcome,
    },
    QuarantineTotals {
        v: u32,
        action_id: u64,
        action: QuarantineAction,
        started_at: u64,
        finished_at: u64,
        #[serde(flatten)]
        report: &'a QuarantineReport,
    },
}

/// What happened to a quarantined file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineAction {
    /// Moved back where it came from.
    Restore,
    /// The file at a restore destination, moved into quarantine (D23).
    Replace,
    /// Deleted for good because the user asked.
    Delete,
    /// Deleted for good because its time in quarantine was up.
    Expired,
}

/// One quarantined file, for a history line.
pub(crate) struct HeldFile<'a> {
    pub batch: &'a str,
    pub item: u32,
    pub path: &'a Path,
    pub size: u64,
}

impl History {
    /// Opens the log for appending, creating it and its folder if needed.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, error: None })
    }

    /// The first write that failed, if any. A failed write doesn't stop the
    /// cleanup; the summary says the history is incomplete.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(crate) fn file_action(
        &mut self,
        cleanup: u64,
        mode: Mode,
        finding: &Finding,
        action: Action,
        outcome: &Outcome,
    ) {
        self.write(&Line::File {
            v: FORMAT_VERSION,
            cleanup,
            at: now(),
            mode,
            rule_id: &finding.rule_id,
            path: &finding.path,
            size: finding.size_on_disk,
            items: match &finding.target {
                Target::RecycleBin { contents, .. } => Some(contents.items),
                Target::File(_) => None,
            },
            action,
            outcome,
        });
    }

    pub(crate) fn folder_removed(&mut self, cleanup: u64, mode: Mode, path: &Path) {
        self.write(&Line::Folder {
            v: FORMAT_VERSION,
            cleanup,
            at: now(),
            mode,
            path,
        });
    }

    pub(crate) fn cleanup(
        &mut self,
        cleanup: u64,
        started_at: u64,
        finished_at: u64,
        report: &CleanReport,
    ) {
        self.write(&Line::Cleanup {
            v: FORMAT_VERSION,
            cleanup,
            started_at,
            finished_at,
            report,
        });
    }

    pub(crate) fn quarantine(
        &mut self,
        action_id: u64,
        mode: Mode,
        action: QuarantineAction,
        file: &HeldFile,
        outcome: &Outcome,
    ) {
        self.write(&Line::Quarantine {
            v: FORMAT_VERSION,
            action_id,
            at: now(),
            mode,
            action,
            quarantine_batch: file.batch,
            quarantine_item: file.item,
            path: file.path,
            size: file.size,
            outcome,
        });
    }

    pub(crate) fn quarantine_totals(
        &mut self,
        action_id: u64,
        action: QuarantineAction,
        started_at: u64,
        report: &QuarantineReport,
    ) {
        self.write(&Line::QuarantineTotals {
            v: FORMAT_VERSION,
            action_id,
            action,
            started_at,
            finished_at: now(),
            report,
        });
    }

    fn write(&mut self, line: &Line) {
        let result = serde_json::to_vec(line)
            .map_err(|e| e.to_string())
            .and_then(|mut bytes| {
                bytes.push(b'\n');
                // The whole line in one write, so a crash leaves whole lines.
                self.file.write_all(&bytes).map_err(|e| e.to_string())
            });
        if let Err(error) = result {
            self.error.get_or_insert(error);
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
