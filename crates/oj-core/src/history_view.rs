//! Reading the history back for the History screen (PLANNING.md §7.4), and
//! trimming its per-file lines after [`DETAIL_DAYS`] days (D30).
//!
//! Each cleanup, restore, and delete becomes one entry, built from its
//! totals line. One whose totals line is missing (the app stopped partway)
//! is still shown, with numbers counted from its file lines. Lines that
//! can't be read are counted and skipped; they're never removed.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::Mode;
use oj_safety::persist::write_atomic;
use serde::{Deserialize, Serialize};

use crate::clean::Tally;
use crate::history::QuarantineAction;

/// How long per-file lines are kept (D30). Totals lines are kept forever.
pub const DETAIL_DAYS: u64 = 90;

/// Numbers each [`HistoryView`] built in this process.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// What an entry was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Cleanup,
    /// Files restored from quarantine.
    Restore,
    /// Quarantined files deleted for good on request.
    Delete,
    /// Quarantined files deleted for good because their time was up.
    Expired,
}

/// One cleanup, restore, or delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryEntry {
    /// Its number in this view; asking for its files quotes it.
    pub id: u32,
    pub kind: EntryKind,
    /// When it started, in seconds since the Unix epoch.
    pub at: u64,
    pub mode: Mode,
    /// Files deleted, restored, or (for a cleanup) deleted and quarantined.
    pub files: u64,
    /// Space freed for good.
    pub freed: u64,
    /// A cleanup's files moved to quarantine.
    pub quarantined: Tally,
    /// Files left alone.
    pub skipped: u64,
    /// A cleanup the user stopped.
    pub cancelled: bool,
    /// Its totals line is missing (the app stopped partway); the numbers
    /// come from its file lines.
    pub interrupted: bool,
    /// How many file lines are still kept for it (0 once trimmed).
    pub details: u64,
}

/// What happened to one file (or folder, or Recycle Bin) in an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryFile {
    pub path: String,
    pub size: u64,
    /// For a Recycle Bin: the items in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<u64>,
    /// `deleted`, `would_delete`, `quarantined`, `would_quarantine`,
    /// `restored`, `would_restore`, `skipped`, `replaced` (moved aside by a
    /// restore), or `folder_removed`.
    pub result: String,
    /// Why it was skipped ([`oj_safety::SkipReason::key`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One page of an entry's files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryFilePage {
    pub items: Vec<HistoryFile>,
    pub total: usize,
}

/// Everything freed for good, not counting dry runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct HistoryTotals {
    pub freed: u64,
    pub cleanups: u64,
    /// The first real cleanup, in seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// The history, read for the History screen. Entries are newest first.
#[derive(Debug)]
pub struct HistoryView {
    id: u64,
    entries: Vec<HistoryEntry>,
    files: Vec<Vec<HistoryFile>>,
    totals: HistoryTotals,
    unreadable_lines: u64,
}

// What's read from each line. Fields the screen doesn't need are ignored,
// and missing ones take defaults, so older and newer lines still read.

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Line {
    File(FileLine),
    Folder(FolderLine),
    Cleanup(CleanupLine),
    Quarantine(QuarantineLine),
    QuarantineTotals(TotalsLine),
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct FileLine {
    cleanup: u64,
    mode: Mode,
    path: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    items: Option<u64>,
    result: String,
    #[serde(default)]
    freed: u64,
    #[serde(default)]
    reason: Option<Reason>,
}

#[derive(Deserialize)]
struct FolderLine {
    cleanup: u64,
    path: String,
}

#[derive(Deserialize)]
struct CleanupLine {
    cleanup: u64,
    mode: Mode,
    #[serde(default)]
    cancelled: bool,
    #[serde(default)]
    deleted: Tally,
    #[serde(default)]
    recycle_bins: Vec<BinLine>,
    #[serde(default)]
    quarantined: Vec<Tally>,
    #[serde(default)]
    skipped: Vec<SkipLine>,
}

#[derive(Deserialize)]
struct BinLine {
    items: u64,
    size: u64,
}

#[derive(Deserialize)]
struct QuarantineLine {
    /// Missing in lines written before quarantine actions had ids.
    #[serde(default)]
    action_id: Option<u64>,
    at: u64,
    mode: Mode,
    action: QuarantineAction,
    path: String,
    #[serde(default)]
    size: u64,
    result: String,
    #[serde(default)]
    freed: u64,
    #[serde(default)]
    reason: Option<Reason>,
}

#[derive(Deserialize)]
struct TotalsLine {
    action_id: u64,
    action: QuarantineAction,
    mode: Mode,
    #[serde(default)]
    done: Tally,
    #[serde(default)]
    skipped: Vec<SkipLine>,
}

#[derive(Deserialize)]
struct SkipLine {
    files: u64,
}

#[derive(Deserialize)]
struct Reason {
    kind: String,
}

/// One cleanup or quarantine action as it's read: its totals line (as an
/// entry) if there is one, and its file lines.
#[derive(Default)]
struct Group {
    totals: Option<HistoryEntry>,
    files: Vec<HistoryFile>,
    /// Counted from the file lines, for when there's no totals line.
    counted: Option<HistoryEntry>,
}

impl HistoryView {
    /// Reads the history file. A missing file is an empty history.
    pub fn load(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Self::from_text(&text)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::from_text("")),
            Err(e) => Err(e),
        }
    }

    /// Reads history lines.
    pub fn from_text(text: &str) -> Self {
        let mut cleanups: BTreeMap<u64, Group> = BTreeMap::new();
        // Keyed by action id; old lines without one use their second.
        let mut actions: BTreeMap<(u64, u8), Group> = BTreeMap::new();
        let mut unreadable_lines = 0;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(line) = serde_json::from_str::<Line>(line) else {
                unreadable_lines += 1;
                continue;
            };
            match line {
                Line::Cleanup(line) => {
                    let group = cleanups.entry(line.cleanup).or_default();
                    group.totals = Some(cleanup_entry(&line));
                }
                Line::File(line) => {
                    let group = cleanups.entry(line.cleanup).or_default();
                    let counted = group
                        .counted
                        .get_or_insert_with(|| blank(EntryKind::Cleanup, line.cleanup, line.mode));
                    let files = line.items.unwrap_or(1);
                    count(counted, &line.result, line.freed, line.size, files);
                    group.files.push(HistoryFile {
                        path: line.path,
                        size: line.size,
                        items: line.items,
                        reason: line.reason.map(|r| r.kind),
                        result: line.result,
                    });
                }
                Line::Folder(line) => {
                    cleanups
                        .entry(line.cleanup)
                        .or_default()
                        .files
                        .push(HistoryFile {
                            path: line.path,
                            size: 0,
                            items: None,
                            result: "folder_removed".into(),
                            reason: None,
                        });
                }
                Line::QuarantineTotals(line) => {
                    let group = actions
                        .entry((line.action_id, totals_slot(line.action)))
                        .or_default();
                    let mut entry = blank(kind_of(line.action), line.action_id, line.mode);
                    entry.files = line.done.files;
                    if entry.kind != EntryKind::Restore {
                        entry.freed = line.done.size;
                    }
                    entry.skipped = line.skipped.iter().map(|s| s.files).sum();
                    group.totals = Some(entry);
                }
                Line::Quarantine(line) => {
                    let id = line.action_id.unwrap_or(line.at * 1000);
                    let group = actions.entry((id, totals_slot(line.action))).or_default();
                    let replaced = line.action == QuarantineAction::Replace;
                    if !replaced {
                        let counted = group
                            .counted
                            .get_or_insert_with(|| blank(kind_of(line.action), id, line.mode));
                        count(counted, &line.result, line.freed, line.size, 1);
                    }
                    group.files.push(HistoryFile {
                        path: line.path,
                        size: line.size,
                        items: None,
                        reason: line.reason.map(|r| r.kind),
                        result: if replaced {
                            "replaced".into()
                        } else {
                            line.result
                        },
                    });
                }
                Line::Other => {}
            }
        }

        let mut groups: Vec<(HistoryEntry, Vec<HistoryFile>)> = cleanups
            .into_values()
            .chain(actions.into_values())
            .filter_map(|group| {
                let mut entry = match (group.totals, group.counted) {
                    (Some(totals), _) => totals,
                    (None, Some(mut counted)) => {
                        counted.interrupted = true;
                        counted
                    }
                    (None, None) => return None,
                };
                entry.details = group.files.len() as u64;
                Some((entry, group.files))
            })
            .collect();
        groups.sort_by_key(|(entry, _)| std::cmp::Reverse(entry.at));

        let mut totals = HistoryTotals::default();
        let mut entries = Vec::with_capacity(groups.len());
        let mut files = Vec::with_capacity(groups.len());
        for (index, (mut entry, group_files)) in groups.into_iter().enumerate() {
            entry.id = index as u32;
            if entry.mode == Mode::Live {
                totals.freed += entry.freed;
                if entry.kind == EntryKind::Cleanup {
                    totals.cleanups += 1;
                    totals.since = Some(totals.since.map_or(entry.at, |s| s.min(entry.at)));
                }
            }
            entries.push(entry);
            files.push(group_files);
        }
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            entries,
            files,
            totals,
            unreadable_lines,
        }
    }

    /// Tells this view apart from any other, so requests for an entry's
    /// files can't mix up entry numbers.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Newest first.
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    pub fn totals(&self) -> HistoryTotals {
        self.totals
    }

    /// Lines that couldn't be read (damaged, or from a newer version).
    pub fn unreadable_lines(&self) -> u64 {
        self.unreadable_lines
    }

    /// Up to `limit` of entry `id`'s files, starting at `offset`, in the
    /// order they happened.
    pub fn files(&self, id: u32, offset: usize, limit: usize) -> Option<HistoryFilePage> {
        let files = self.files.get(id as usize)?;
        Some(HistoryFilePage {
            items: files.iter().skip(offset).take(limit).cloned().collect(),
            total: files.len(),
        })
    }
}

fn kind_of(action: QuarantineAction) -> EntryKind {
    match action {
        QuarantineAction::Restore | QuarantineAction::Replace => EntryKind::Restore,
        QuarantineAction::Delete => EntryKind::Delete,
        QuarantineAction::Expired => EntryKind::Expired,
    }
}

/// Keeps actions apart that started in the same millisecond (or, for old
/// lines, the same second) but aren't the same kind.
fn totals_slot(action: QuarantineAction) -> u8 {
    match kind_of(action) {
        EntryKind::Cleanup | EntryKind::Restore => 0,
        EntryKind::Delete => 1,
        EntryKind::Expired => 2,
    }
}

fn blank(kind: EntryKind, started_ms: u64, mode: Mode) -> HistoryEntry {
    HistoryEntry {
        id: 0,
        kind,
        at: started_ms / 1000,
        mode,
        files: 0,
        freed: 0,
        quarantined: Tally::default(),
        skipped: 0,
        cancelled: false,
        interrupted: false,
        details: 0,
    }
}

fn cleanup_entry(line: &CleanupLine) -> HistoryEntry {
    let mut entry = blank(EntryKind::Cleanup, line.cleanup, line.mode);
    for group in &line.quarantined {
        entry.quarantined.files += group.files;
        entry.quarantined.size += group.size;
    }
    // A Recycle Bin's items count as its files.
    let bins: Tally = line
        .recycle_bins
        .iter()
        .fold(Tally::default(), |sum, bin| Tally {
            files: sum.files + bin.items,
            size: sum.size + bin.size,
        });
    entry.files = line.deleted.files + bins.files + entry.quarantined.files;
    entry.freed = line.deleted.size + bins.size;
    entry.skipped = line.skipped.iter().map(|s| s.files).sum();
    entry.cancelled = line.cancelled;
    entry
}

/// Adds one file line's result to numbers counted without a totals line.
/// `files` is 1, or a Recycle Bin's items.
fn count(entry: &mut HistoryEntry, result: &str, freed: u64, size: u64, files: u64) {
    match result {
        "deleted" | "would_delete" => {
            entry.files += files;
            entry.freed += freed;
        }
        "quarantined" | "would_quarantine" => {
            entry.files += 1;
            entry.quarantined.files += 1;
            entry.quarantined.size += size;
        }
        "restored" | "would_restore" => entry.files += 1,
        "skipped" => entry.skipped += 1,
        _ => {}
    }
}

/// Drops per-file lines whose cleanup or action started more than `keep`
/// before `now`, and keeps everything else: totals lines, recent lines,
/// and lines it can't read. Rewrites the file atomically, and only when
/// something goes. Returns how many lines went.
pub fn trim_history(path: &Path, now: SystemTime, keep: Duration) -> io::Result<u64> {
    #[derive(Deserialize)]
    struct Age {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        cleanup: Option<u64>,
        #[serde(default)]
        action_id: Option<u64>,
        #[serde(default)]
        at: Option<u64>,
    }

    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let cutoff = now
        .checked_sub(keep)
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let old = |line: &str| -> bool {
        let Ok(age) = serde_json::from_str::<Age>(line) else {
            return false;
        };
        let started = match age.kind.as_str() {
            "file" | "folder" => age.cleanup.map(|ms| ms / 1000),
            "quarantine" => age.action_id.map(|ms| ms / 1000).or(age.at),
            _ => return false,
        };
        started.is_some_and(|started| started < cutoff)
    };

    let mut kept = String::with_capacity(text.len());
    let mut dropped = 0;
    for line in text.lines() {
        if !line.trim().is_empty() && old(line) {
            dropped += 1;
        } else if !line.trim().is_empty() {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if dropped > 0 {
        write_atomic(path, kept.as_bytes())?;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = 86_400_000;

    fn file(cleanup: u64, result: &str) -> String {
        format!(
            r#"{{"type":"file","v":1,"cleanup":{cleanup},"at":{},"mode":"live","rule_id":"r","path":"C:\\T\\a.tmp","size":10,"action":{{"kind":"delete"}},"result":"{result}","freed":10}}"#,
            cleanup / 1000
        )
    }

    fn totals(cleanup: u64, mode: &str) -> String {
        format!(
            r#"{{"type":"cleanup","v":1,"cleanup":{cleanup},"started_at":{},"finished_at":{},"mode":"{mode}","cancelled":false,"deleted":{{"files":2,"size":20}},"quarantined":[{{"days":7,"expires_at":1,"files":1,"size":5}}],"skipped":[{{"reason":"in_use","files":3}}],"not_started":0,"folders_removed":0,"needs_admin":{{"files":0,"size":0}},"apps_open":[]}}"#,
            cleanup / 1000,
            cleanup / 1000
        )
    }

    #[test]
    fn entries_come_from_totals_newest_first() {
        let older = 1_000 * DAY_MS;
        let newer = older + DAY_MS;
        let text = [
            file(older, "deleted"),
            totals(older, "live"),
            file(newer, "would_delete"),
            totals(newer, "dry_run"),
        ]
        .join("\n");
        let view = HistoryView::from_text(&text);

        let entries = view.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].at, newer / 1000);
        assert_eq!(entries[0].mode, Mode::DryRun);
        let real = &entries[1];
        assert_eq!(real.kind, EntryKind::Cleanup);
        assert_eq!((real.files, real.freed, real.skipped), (3, 20, 3));
        assert_eq!(real.quarantined, Tally { files: 1, size: 5 });
        assert_eq!(real.details, 1);
        assert!(!real.interrupted);

        let totals = view.totals();
        assert_eq!(totals.freed, 20, "dry runs don't count");
        assert_eq!(totals.cleanups, 1);
        assert_eq!(totals.since, Some(older / 1000));
        assert_eq!(view.files(1, 0, 10).unwrap().items[0].result, "deleted");
        assert!(view.files(9, 0, 10).is_none());
    }

    #[test]
    fn a_cleanup_without_totals_is_counted_from_its_files() {
        let start = 1_000 * DAY_MS;
        let text = [file(start, "deleted"), file(start, "skipped")].join("\n");
        let view = HistoryView::from_text(&text);
        let entry = &view.entries()[0];
        assert!(entry.interrupted);
        assert_eq!((entry.files, entry.freed, entry.skipped), (1, 10, 1));
    }

    #[test]
    fn unreadable_and_unknown_lines_are_counted_or_ignored() {
        let text = format!(
            "not json\n{}\n{{\"type\":\"from_the_future\",\"v\":9}}\n",
            totals(5_000, "live")
        );
        let view = HistoryView::from_text(&text);
        assert_eq!(view.entries().len(), 1);
        assert_eq!(view.unreadable_lines(), 1);
    }

    #[test]
    fn trimming_keeps_totals_and_recent_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        let now = UNIX_EPOCH + Duration::from_millis(1_000 * DAY_MS);
        let old = 1_000 * DAY_MS - 100 * DAY_MS;
        let recent = 1_000 * DAY_MS - 10 * DAY_MS;
        let old_quarantine = format!(
            r#"{{"type":"quarantine","v":1,"action_id":{old},"at":0,"mode":"live","action":"delete","path":"x","size":1,"result":"deleted","freed":1}}"#
        );
        let text = [
            file(old, "deleted"),
            totals(old, "live"),
            old_quarantine,
            file(recent, "deleted"),
            totals(recent, "live"),
            "garbage".to_string(),
        ]
        .join("\n");
        fs::write(&path, &text).unwrap();
        let keep = Duration::from_secs(DETAIL_DAYS * 86_400);

        assert_eq!(trim_history(&path, now, keep).unwrap(), 2);

        let trimmed = fs::read_to_string(&path).unwrap();
        let view = HistoryView::from_text(&trimmed);
        assert_eq!(view.entries().len(), 2, "both cleanups keep their totals");
        assert_eq!(view.entries()[1].details, 0, "the old one lost its files");
        assert_eq!(view.entries()[0].details, 1);
        assert_eq!(view.unreadable_lines(), 1, "garbage is kept, not removed");
        assert_eq!(
            trim_history(&path, now, keep).unwrap(),
            0,
            "nothing more to trim"
        );
        let missing = dir.path().join("none.jsonl");
        assert_eq!(trim_history(&missing, now, keep).unwrap(), 0);
    }
}
