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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{
    CancelToken, Entry, Executor, FileSnapshot, NormPath, Outcome, ProtectedList, SkipReason,
};
use oj_windows::FileId;
use serde::{Deserialize, Serialize};

use crate::age::DEFAULT_MIN_AGE;
use crate::clean::{note_folders, remove_empty_folders};
use crate::rule::{CompiledRule, RuleSet};
use crate::scan::{Finding, Target, relative_path};
use crate::vars::{Vars, expand};

/// The request format this version speaks, in [`ElevatedRequest::version`].
pub const PROTOCOL_VERSION: u32 = 1;

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

        let file_id: FileId = item.file_id.parse().map_err(|_| outside.clone())?;
        Ok(FileSnapshot {
            // Checked above to lie inside the location the helper found.
            path: item.path.clone(),
            len: item.len,
            allocated: item.allocated,
            links: item.links,
            modified,
            file_id,
        })
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
