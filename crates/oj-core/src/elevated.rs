//! Cleaning files that need administrator rights, through the elevated
//! helper (PLANNING.md §4.6 and D34).
//!
//! The app sends the helper one [`ElevatedRequest`]: the files of the plan
//! that need administrator rights, as the scan saw them. The helper trusts
//! none of it. [`Checker`] makes sure each file is one its rule would have
//! found (a bundled rule that needs administrator rights and only looks in
//! machine-wide folders, inside that rule's locations as the helper itself
//! finds them, matching its patterns, old enough, and not protected); then
//! the executor checks it's still the same file. So even a forged request
//! can only clean what OpenJanitor's own rules would.
//!
//! The helper answers with one [`HelperMessage`] per line; the app writes
//! the history.
//!
//! It can also scan the admin rules with administrator rights ("Check
//! with admin rights", D35): [`scan_elevated`] in the helper, and
//! [`merge_elevated`] in the app to put what it found into the results.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{
    CancelToken, DenyList, Entry, Executor, FileSnapshot, NormPath, Outcome, ProtectedList,
    SkipReason, WindowsRecycleBin,
};
use oj_windows::FileId;
use serde::{Deserialize, Serialize};

use crate::age::DEFAULT_MIN_AGE;
use crate::clean::{note_folders, remove_empty_folders};
use crate::rule::{CompiledRule, Level, RuleSet};
use crate::scan::{
    Finding, RuleReport, ScanOptions, ScanProgress, ScanReport, Scanner, Target, relative_path,
};
use crate::vars::{Vars, expand};

/// The request format this version speaks, in each request's `version`.
pub const PROTOCOL_VERSION: u32 = 2;

/// The only variables an elevated rule's locations may use: machine-wide
/// folders. Never a user's profile, which may not even be the helper's.
const MACHINE_VARS: &[&str] = &[
    "%WINDIR%",
    "%SYSTEMROOT%",
    "%PROGRAMDATA%",
    "%PROGRAMFILES%",
    "%PROGRAMFILES(X86)%",
];

/// One file the helper is asked to delete, as the scan saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevatedItem {
    pub rule_id: String,
    /// The rule location it was found in.
    pub root: PathBuf,
    pub path: PathBuf,
    pub len: u64,
    pub allocated: u64,
    pub links: u32,
    /// Modified time: seconds and nanoseconds since the Unix epoch.
    pub modified_secs: u64,
    pub modified_nanos: u32,
    /// [`FileId`] in its text form.
    pub file_id: String,
}

impl ElevatedItem {
    /// The item for a file finding; `None` for a Recycle Bin.
    pub fn from_finding(finding: &Finding) -> Option<Self> {
        let Target::File(snapshot) = &finding.target else {
            return None;
        };
        let since = snapshot
            .modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Some(Self {
            rule_id: finding.rule_id.clone(),
            root: finding.root.clone(),
            path: snapshot.path.clone(),
            len: snapshot.len,
            allocated: snapshot.allocated,
            links: snapshot.links,
            modified_secs: since.as_secs(),
            modified_nanos: since.subsec_nanos(),
            file_id: snapshot.file_id.to_string(),
        })
    }

    fn modified(&self) -> Option<SystemTime> {
        let since = Duration::new(self.modified_secs, self.modified_nanos);
        UNIX_EPOCH.checked_add(since)
    }

    /// The file as the scan saw it, if the item is well formed.
    pub fn snapshot(&self) -> Option<FileSnapshot> {
        Some(FileSnapshot {
            path: self.path.clone(),
            len: self.len,
            allocated: self.allocated,
            links: self.links,
            modified: self.modified()?,
            file_id: self.file_id.parse::<FileId>().ok()?,
        })
    }
}

/// What the app asks the helper, as the first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Delete these files: a cleanup's admin-only part (D34).
    Clean(ElevatedRequest),
    /// Scan the admin rules with administrator rights (D35).
    Scan(ScanRequest),
}

/// A scan of the admin rules, with administrator rights. Only reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub version: u32,
    pub level: Level,
    /// The drive letters the results cover; locations elsewhere are left
    /// alone.
    pub drives: Vec<char>,
    /// The user's minimum age in seconds (each rule uses the longer of this
    /// and its own).
    pub min_age_floor_secs: u64,
    /// The user's Protected list.
    pub protected: Vec<Entry>,
}

/// A file the helper's scan found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedFile {
    pub item: ElevatedItem,
    pub size_on_disk: u64,
    pub evidence: Vec<String>,
}

/// Everything the helper is asked to do, sent as the first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevatedRequest {
    pub version: u32,
    /// Dry run if either this or the helper's own build says so.
    pub mode: oj_safety::Mode,
    /// The user's minimum age in seconds. Each rule uses the longer of this
    /// and its own, so it can only make the helper more careful.
    pub min_age_floor_secs: u64,
    /// The user's Protected list. It can only leave files alone.
    pub protected: Vec<Entry>,
    pub items: Vec<ElevatedItem>,
}

/// What the app may send after the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppMessage {
    /// Stop after the file it's on.
    Cancel,
}

/// What the helper says, one line at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperMessage {
    /// What happened to item `index` of the request.
    Outcome { index: usize, outcome: Outcome },
    /// A folder removed because the cleanup left it empty.
    FolderRemoved { path: PathBuf },
    /// Where the helper's scan is.
    ScanProgress { progress: ScanProgress },
    /// What the helper's scan found: the admin rules' reports, and their
    /// files. Not sent when the scan was stopped.
    Scanned {
        rules: Vec<RuleReport>,
        files: Vec<ScannedFile>,
    },
    /// Everything that could be done is done.
    Done,
    /// The request was refused as a whole, such as one from a newer app.
    Refused { message: String },
}

/// The checks the helper makes on each item before the executor's own.
pub struct Checker<'a> {
    rules: &'a RuleSet,
    vars: &'a dyn Vars,
    protected: &'a ProtectedList,
    min_age_floor: Duration,
    now: SystemTime,
}

impl<'a> Checker<'a> {
    pub fn new(
        rules: &'a RuleSet,
        vars: &'a dyn Vars,
        protected: &'a ProtectedList,
        min_age_floor: Duration,
        now: SystemTime,
    ) -> Self {
        Self {
            rules,
            vars,
            protected,
            min_age_floor,
            now,
        }
    }

    /// The snapshot to revalidate and act on, if `item` is one its rule
    /// would have found.
    pub fn check(&self, item: &ElevatedItem) -> Result<FileSnapshot, SkipReason> {
        let outside = SkipReason::OutsideRule;
        let compiled = self
            .rules
            .iter()
            .find(|compiled| compiled.rule.id == item.rule_id)
            .filter(|compiled| elevated_rule(compiled))
            .ok_or(outside.clone())?;

        // The location, as the helper finds it, never as the app says.
        let root = compiled
            .rule
            .paths
            .iter()
            .filter_map(|template| expand(template, self.vars).ok())
            .find(|root| same_path(root, &item.root))
            .ok_or(outside.clone())?;
        let inside = match (NormPath::new(&item.path), NormPath::new(&root)) {
            (Ok(path), Ok(location)) => path.starts_with(&location),
            _ => false,
        };
        if !inside {
            return Err(outside);
        }
        let relative = relative_path(&root, &item.path).ok_or(outside.clone())?;
        if !compiled.matches(&relative) {
            return Err(outside);
        }

        if self.protected.protects_rule(&compiled.rule.id) || self.protected.covers(&item.path) {
            return Err(SkipReason::Protected);
        }

        let min_age = compiled
            .min_age
            .unwrap_or(DEFAULT_MIN_AGE)
            .max(self.min_age_floor);
        let modified = item.modified().ok_or(outside.clone())?;
        let old_enough = self
            .now
            .duration_since(modified)
            .is_ok_and(|age| age >= min_age);
        if !old_enough {
            return Err(outside);
        }

        // Its path was checked above to lie inside the location the helper
        // found.
        item.snapshot().ok_or(outside)
    }
}

/// A rule the helper may act for: file-based, needing administrator
/// rights, and looking only in machine-wide folders.
pub fn elevated_rule(compiled: &CompiledRule) -> bool {
    let rule = &compiled.rule;
    rule.needs_admin
        && rule.builtin.is_none()
        && !rule.paths.is_empty()
        && rule.paths.iter().all(|template| {
            MACHINE_VARS
                .iter()
                .any(|var| template.to_ascii_uppercase().starts_with(var))
        })
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (NormPath::new(a), NormPath::new(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Runs a checked request: what the helper does once it's connected.
/// Deletes each item that passes the checks, then the folders that left
/// empty, telling `send` along the way. Stops before the next item once
/// `cancel` is cancelled.
pub fn serve(
    request: &ElevatedRequest,
    checker: &Checker,
    executor: &Executor,
    cancel: &CancelToken,
    send: &mut dyn FnMut(HelperMessage),
) {
    if request.version != PROTOCOL_VERSION {
        send(HelperMessage::Refused {
            message: format!(
                "the app speaks version {} of the helper's language, not {PROTOCOL_VERSION}",
                request.version
            ),
        });
        return;
    }
    let mut emptied: HashMap<PathBuf, &Path> = HashMap::new();
    for (index, item) in request.items.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        let outcome = match checker.check(item) {
            Ok(snapshot) => executor.delete_file(&snapshot),
            Err(reason) => Outcome::Skipped { reason },
        };
        if matches!(outcome, Outcome::Deleted { .. }) {
            note_folders(&mut emptied, &item.path, &item.root);
        }
        send(HelperMessage::Outcome { index, outcome });
    }
    remove_empty_folders(executor, emptied, &mut |folder| {
        send(HelperMessage::FolderRemoved {
            path: folder.to_path_buf(),
        });
    });
    send(HelperMessage::Done);
}

/// Runs a scan request: what the helper does for "Check with admin
/// rights" (D35). Scans only the rules it may act for, with the same
/// read-only scanner as the app, and reports what it found.
pub fn scan_elevated(
    request: &ScanRequest,
    rules: &RuleSet,
    vars: &dyn Vars,
    deny: &DenyList,
    cancel: &CancelToken,
    send: &mut dyn FnMut(HelperMessage),
) {
    if request.version != PROTOCOL_VERSION {
        send(HelperMessage::Refused {
            message: format!(
                "the app speaks version {} of the helper's language, not {PROTOCOL_VERSION}",
                request.version
            ),
        });
        return;
    }
    let protected = match ProtectedList::from_entries(request.protected.clone()) {
        Ok(protected) => protected,
        Err(e) => {
            send(HelperMessage::Refused {
                message: format!("the Protected list couldn't be read: {e}"),
            });
            return;
        }
    };
    let admin = rules.filtered(elevated_rule);
    // No admin rule is a builtin, so the Recycle Bin is never read here.
    let scanner = Scanner {
        rules: &admin,
        vars,
        deny,
        protected: &protected,
        recycle_bin: &WindowsRecycleBin,
    };
    let mut options = ScanOptions::new(request.level);
    options.min_age_floor = Some(Duration::from_secs(request.min_age_floor_secs));
    options.drives = Some(request.drives.clone());
    let report = scanner.scan_with(&options, cancel, &mut |progress| {
        send(HelperMessage::ScanProgress {
            progress: progress.clone(),
        });
    });
    if !report.cancelled {
        let files = report
            .findings
            .iter()
            .filter_map(|finding| {
                Some(ScannedFile {
                    item: ElevatedItem::from_finding(finding)?,
                    size_on_disk: finding.size_on_disk,
                    evidence: finding.evidence.clone(),
                })
            })
            .collect();
        send(HelperMessage::Scanned {
            rules: report.rules,
            files,
        });
    }
    send(HelperMessage::Done);
}

/// `report` with the admin rules' parts replaced by what the helper's scan
/// found (D35). Reports and files for any other rule are ignored, and the
/// findings are numbered again.
pub fn merge_elevated(
    report: &ScanReport,
    elevated: Vec<RuleReport>,
    files: Vec<ScannedFile>,
) -> ScanReport {
    let replaced: Vec<RuleReport> = elevated
        .into_iter()
        .filter(|new| {
            report
                .rules
                .iter()
                .any(|old| old.rule_id == new.rule_id && old.needs_admin)
        })
        .collect();
    let is_replaced = |rule_id: &str| replaced.iter().any(|rule| rule.rule_id == rule_id);

    let rules: Vec<RuleReport> = report
        .rules
        .iter()
        .map(|old| {
            replaced
                .iter()
                .find(|new| new.rule_id == old.rule_id)
                .cloned()
                .unwrap_or_else(|| old.clone())
        })
        .collect();
    let mut findings: Vec<Finding> = report
        .findings
        .iter()
        .filter(|finding| !is_replaced(&finding.rule_id))
        .cloned()
        .collect();
    for file in files {
        let Some(rule) = rules
            .iter()
            .find(|rule| rule.rule_id == file.item.rule_id && is_replaced(&rule.rule_id))
        else {
            continue;
        };
        let Some(snapshot) = file.item.snapshot() else {
            continue;
        };
        findings.push(Finding {
            id: 0,
            rule_id: rule.rule_id.clone(),
            category: rule.category.clone(),
            risk: rule.risk,
            path: snapshot.path.clone(),
            root: file.item.root.clone(),
            size_on_disk: file.size_on_disk,
            file_count: 1,
            last_modified: file.item.modified_secs,
            needs_admin: true,
            evidence: file.evidence,
            target: Target::File(snapshot),
        });
    }
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.id = index as u64 + 1;
    }
    ScanReport {
        level: report.level,
        findings_total: findings.len() as u64,
        size_on_disk_total: findings.iter().map(|f| f.size_on_disk).sum(),
        rules,
        findings,
        cancelled: false,
        drives: report.drives.clone(),
    }
}

/// Why the elevated part of a cleanup didn't run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElevatedError {
    /// The user said no to Windows' prompt.
    #[error("administrator permission was declined")]
    Declined,
    #[error("{0}")]
    Failed(String),
}

/// Runs the elevated part of a cleanup: in the app, by starting the helper
/// with a UAC prompt; in tests, in-process.
pub trait Elevator {
    /// Asks for `items` to be deleted with administrator rights, passing
    /// each [`HelperMessage`] to `on_message` as it comes. Returns once the
    /// helper is done. `cancel` asks it to stop after the file it's on.
    fn run(
        &mut self,
        items: &[ElevatedItem],
        cancel: &CancelToken,
        on_message: &mut dyn FnMut(HelperMessage),
    ) -> Result<(), ElevatedError>;
}
