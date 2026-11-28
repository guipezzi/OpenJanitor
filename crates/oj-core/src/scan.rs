//! Running rules against the filesystem and the Recycle Bin. Read-only.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{
    BinContents, CancelToken, DenyList, FileSnapshot, NormPath, ProtectedList, RecycleBin,
    WalkStats, walk_files,
};
use serde::{Deserialize, Serialize};

use crate::age::{DEFAULT_MIN_AGE, describe};
use crate::rule::{App, CompiledRule, Level, RECYCLE_BIN, Risk, RuleSet};
use crate::vars::{Vars, expand};

/// How to run a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub level: Level,
    /// No rule uses a shorter minimum age than this (the user's setting,
    /// D31). Rules that wait longer keep their own.
    pub min_age_floor: Option<Duration>,
    /// Replaces every rule's minimum age, floor included. For the CLI's
    /// `--min-age` only.
    pub min_age_override: Option<Duration>,
    /// The drive letters to scan (D33): locations on other drives are left
    /// alone, and the Recycle Bin is read on each of these. `None` scans
    /// every location, and the Recycle Bin of the system drive.
    pub drives: Option<Vec<char>>,
    /// "Now", for age calculations. Tests can pin it.
    pub now: SystemTime,
}

impl ScanOptions {
    pub fn new(level: Level) -> Self {
        Self {
            level,
            min_age_floor: None,
            min_age_override: None,
            drives: None,
            now: SystemTime::now(),
        }
    }

    /// Whether `path` is on a drive this scan covers.
    fn covers(&self, path: &Path) -> bool {
        self.drives.as_ref().is_none_or(|drives| {
            drive_letter(path)
                .is_some_and(|drive| drives.iter().any(|d| d.eq_ignore_ascii_case(&drive)))
        })
    }
}

/// What a finding is, and what it looked like at scan time, for
/// revalidation.
#[derive(Debug, Clone)]
pub enum Target {
    File(FileSnapshot),
    /// A drive's whole Recycle Bin, emptied through the Windows shell.
    RecycleBin {
        drive: char,
        contents: BinContents,
    },
}

/// One file a rule suggests cleaning, or one drive's Recycle Bin.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: u64,
    pub rule_id: String,
    pub category: String,
    pub risk: Risk,
    /// For a Recycle Bin, its folder (`C:\$Recycle.Bin`), for display only.
    pub path: PathBuf,
    /// The rule location the file was found under.
    pub root: PathBuf,
    /// Bytes freed by deleting it (0 for files with other hard links). For
    /// a Recycle Bin, the size Windows reports.
    pub size_on_disk: u64,
    /// 1 for a file; for a Recycle Bin, the items in it.
    pub file_count: u64,
    /// Seconds since the Unix epoch. 0 for a Recycle Bin.
    pub last_modified: u64,
    pub needs_admin: bool,
    /// Human-readable reasons, shown in the details panel.
    pub evidence: Vec<String>,
    #[serde(skip)]
    pub target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Scanned,
    /// The app the rule is for isn't installed.
    NotDetected,
    /// None of the rule's locations exist on this machine.
    NoLocations,
    /// Its locations are on drives that aren't selected (D33).
    NotSelected,
    /// The user protected the whole rule.
    Protected,
}

/// What one rule found. It reads back from JSON too: the elevated helper's
/// scan reports this way (D35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleReport {
    pub rule_id: String,
    pub name: String,
    /// What the rule cleans, in plain language, for the details panel.
    pub description: String,
    pub category: String,
    pub level: Level,
    pub risk: Risk,
    /// Whether "Select recommended" may pick it (only if it's also low
    /// risk).
    pub recommended: bool,
    pub needs_admin: bool,
    /// The built-in action it runs, such as `recycle-bin`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtin: Option<String>,
    /// The program whose files these are. While it runs, they're left out
    /// of cleanups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<App>,
    pub status: RuleStatus,
    pub roots: Vec<PathBuf>,
    pub findings: u64,
    pub size_on_disk: u64,
    /// Matching files newer than the minimum age.
    pub skipped_recent: u64,
    /// Matching files another rule already reported.
    pub skipped_duplicates: u64,
    /// Matching files the user protected.
    pub skipped_user_protected: u64,
    pub walk: WalkStats,
    pub warnings: Vec<String>,
}

/// The result of a scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub level: Level,
    pub findings_total: u64,
    pub size_on_disk_total: u64,
    pub rules: Vec<RuleReport>,
    pub findings: Vec<Finding>,
    /// The scan was cancelled, so the report is incomplete.
    pub cancelled: bool,
    /// The drives it covered ([`ScanOptions::drives`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drives: Option<Vec<char>>,
}

/// Where a running scan is, for progress displays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Position of the rule being scanned, counting from 0.
    pub rule_index: usize,
    pub rule_count: usize,
    pub rule_id: String,
    pub rule_name: String,
    /// Files looked at so far, in all rules.
    pub files_checked: u64,
    /// Files found so far, and the space they take.
    pub findings: u64,
    pub size_on_disk: u64,
}

/// A scan reports progress when each rule starts and then every this many
/// files.
const PROGRESS_EVERY: u64 = 256;

/// Runs rules. Never modifies anything.
pub struct Scanner<'a> {
    pub rules: &'a RuleSet,
    pub vars: &'a dyn Vars,
    pub deny: &'a DenyList,
    /// The user's Protected list: protected rules and files are left out.
    pub protected: &'a ProtectedList,
    /// Read for the Recycle Bin rule; never emptied here.
    pub recycle_bin: &'a dyn RecycleBin,
}

impl Scanner<'_> {
    pub fn scan(&self, options: &ScanOptions) -> ScanReport {
        self.scan_with(options, &CancelToken::new(), &mut |_| {})
    }

    /// Like [`scan`](Self::scan), but calls `on_progress` along the way and
    /// stops early once `cancel` is cancelled. The report of a cancelled
    /// scan is incomplete and has `cancelled` set.
    pub fn scan_with(
        &self,
        options: &ScanOptions,
        cancel: &CancelToken,
        on_progress: &mut dyn FnMut(&ScanProgress),
    ) -> ScanReport {
        let selected: Vec<&CompiledRule> = self
            .rules
            .iter()
            .filter(|compiled| options.level.includes(compiled.rule.level))
            .collect();
        let mut state = State {
            seen: HashSet::new(),
            findings: Vec::new(),
            files_checked: 0,
            size_on_disk: 0,
        };
        let mut rules = Vec::with_capacity(selected.len());
        for (index, compiled) in selected.iter().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            let mut progress = Progress {
                rule_index: index,
                rule_count: selected.len(),
                compiled,
                on_progress: &mut *on_progress,
            };
            rules.push(self.scan_rule(compiled, options, &mut state, cancel, &mut progress));
        }
        ScanReport {
            level: options.level,
            findings_total: state.findings.len() as u64,
            size_on_disk_total: state.size_on_disk,
            rules,
            findings: state.findings,
            cancelled: cancel.is_cancelled(),
            drives: options.drives.clone(),
        }
    }

    fn scan_rule(
        &self,
        compiled: &CompiledRule,
        options: &ScanOptions,
        state: &mut State,
        cancel: &CancelToken,
        progress: &mut Progress,
    ) -> RuleReport {
        progress.report(state);
        let rule = &compiled.rule;
        let mut report = RuleReport {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            category: rule.category.clone(),
            level: rule.level,
            risk: rule.risk,
            recommended: rule.recommended,
            needs_admin: rule.needs_admin,
            builtin: rule.builtin.clone(),
            app: rule.app.clone(),
            status: RuleStatus::Scanned,
            roots: Vec::new(),
            findings: 0,
            size_on_disk: 0,
            skipped_recent: 0,
            skipped_duplicates: 0,
            skipped_user_protected: 0,
            walk: WalkStats::default(),
            warnings: Vec::new(),
        };

        if self.protected.protects_rule(&rule.id) {
            report.status = RuleStatus::Protected;
            return report;
        }
        if let Some(builtin) = &rule.builtin {
            match builtin.as_str() {
                RECYCLE_BIN => self.scan_recycle_bin(compiled, options, &mut report, state),
                // Rules can only name known builtins.
                other => report
                    .warnings
                    .push(format!("unknown builtin action {other:?}")),
            }
            return report;
        }
        if let Some(detect) = &rule.detect {
            let detected = expand(detect, self.vars).is_ok_and(|path| path.exists());
            if !detected {
                report.status = RuleStatus::NotDetected;
                return report;
            }
        }

        let mut root_keys = HashSet::new();
        let mut elsewhere = false;
        for template in &rule.paths {
            match expand(template, self.vars) {
                // Checked first, so a drive that isn't selected isn't even
                // looked at.
                Ok(root) if !options.covers(&root) => {
                    elsewhere = true;
                    report.warnings.push(format!(
                        "{} is on a drive that isn't selected",
                        root.display()
                    ));
                }
                Ok(root) if root.exists() => {
                    if root_keys.insert(path_key(&root)) {
                        report.roots.push(root);
                    }
                }
                Ok(root) => report
                    .warnings
                    .push(format!("{} doesn't exist on this machine", root.display())),
                Err(error) => report.warnings.push(error.to_string()),
            }
        }
        if report.roots.is_empty() {
            report.status = if elsewhere {
                RuleStatus::NotSelected
            } else {
                RuleStatus::NoLocations
            };
            return report;
        }

        let min_age = options.min_age_override.unwrap_or_else(|| {
            let own = compiled.min_age.unwrap_or(DEFAULT_MIN_AGE);
            options.min_age_floor.map_or(own, |floor| own.max(floor))
        });

        for root in report.roots.clone() {
            let stats = walk_files(&root, self.deny, cancel, |snapshot| {
                state.files_checked += 1;
                if state.files_checked.is_multiple_of(PROGRESS_EVERY) {
                    progress.report(state);
                }
                let Some(relative) = relative_path(&root, &snapshot.path) else {
                    return;
                };
                if !compiled.matches(&relative) {
                    return;
                }
                if !self.protected.is_empty() && self.protected.covers(&snapshot.path) {
                    report.skipped_user_protected += 1;
                    return;
                }
                // A modified time in the future counts as "just modified".
                let age = options.now.duration_since(snapshot.modified).ok();
                let Some(age) = age.filter(|age| *age >= min_age) else {
                    report.skipped_recent += 1;
                    return;
                };
                if !state.seen.insert(path_key(&snapshot.path)) {
                    report.skipped_duplicates += 1;
                    return;
                }
                let finding = make_finding(
                    state.findings.len() as u64 + 1,
                    compiled,
                    &root,
                    age,
                    snapshot,
                );
                report.findings += 1;
                report.size_on_disk += finding.size_on_disk;
                state.size_on_disk += finding.size_on_disk;
                state.findings.push(finding);
            });
            report.walk.merge(stats);
        }
        report
    }

    /// The signed-in user's Recycle Bin on each selected drive (or the
    /// system drive), one finding per drive that holds anything. The
    /// minimum age doesn't apply: it's emptied as a whole (D32).
    fn scan_recycle_bin(
        &self,
        compiled: &CompiledRule,
        options: &ScanOptions,
        report: &mut RuleReport,
        state: &mut State,
    ) {
        let drives = match &options.drives {
            Some(drives) => drives.clone(),
            None => {
                let system = self.vars.get("SYSTEMDRIVE");
                let Some(drive) = system.as_deref().and_then(drive_letter) else {
                    report.status = RuleStatus::NoLocations;
                    report
                        .warnings
                        .push("%SYSTEMDRIVE% isn't a drive on this machine".into());
                    return;
                };
                vec![drive]
            }
        };
        for drive in drives {
            self.scan_one_recycle_bin(compiled, drive.to_ascii_uppercase(), report, state);
        }
    }

    fn scan_one_recycle_bin(
        &self,
        compiled: &CompiledRule,
        drive: char,
        report: &mut RuleReport,
        state: &mut State,
    ) {
        let folder = PathBuf::from(format!("{drive}:\\$Recycle.Bin"));
        report.roots.push(folder.clone());
        let contents = match self.recycle_bin.contents(drive) {
            Ok(contents) if contents.items > 0 => contents,
            Ok(_) => return,
            Err(error) => {
                report.warnings.push(format!(
                    "Couldn't read the Recycle Bin on {drive}: ({error})"
                ));
                return;
            }
        };
        let rule = &compiled.rule;
        let finding = Finding {
            id: state.findings.len() as u64 + 1,
            rule_id: rule.id.clone(),
            category: rule.category.clone(),
            risk: rule.risk,
            path: folder.clone(),
            root: folder,
            size_on_disk: contents.size,
            file_count: contents.items,
            last_modified: 0,
            needs_admin: rule.needs_admin,
            evidence: vec![
                format!(
                    "Windows counts {} items in the Recycle Bin on drive {drive}:",
                    contents.items
                ),
                "Its size is the one Windows reports for the deleted files, which can differ a little from the space they take on disk".into(),
            ],
            target: Target::RecycleBin { drive, contents },
        };
        report.findings += 1;
        report.size_on_disk += finding.size_on_disk;
        state.size_on_disk += finding.size_on_disk;
        state.findings.push(finding);
    }
}

/// The drive a path is on: `C:` (or `C:\…`) → `'C'`. `None` for anything
/// else, such as a network path.
pub(crate) fn drive_letter(path: &Path) -> Option<char> {
    let mut chars = path.to_str()?.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

struct State {
    seen: HashSet<String>,
    findings: Vec<Finding>,
    files_checked: u64,
    size_on_disk: u64,
}

/// Sends progress for the rule being scanned.
struct Progress<'a> {
    rule_index: usize,
    rule_count: usize,
    compiled: &'a CompiledRule,
    on_progress: &'a mut dyn FnMut(&ScanProgress),
}

impl Progress<'_> {
    fn report(&mut self, state: &State) {
        (self.on_progress)(&ScanProgress {
            rule_index: self.rule_index,
            rule_count: self.rule_count,
            rule_id: self.compiled.rule.id.clone(),
            rule_name: self.compiled.rule.name.clone(),
            files_checked: state.files_checked,
            findings: state.findings.len() as u64,
            size_on_disk: state.size_on_disk,
        });
    }
}

fn make_finding(
    id: u64,
    compiled: &CompiledRule,
    root: &Path,
    age: Duration,
    snapshot: FileSnapshot,
) -> Finding {
    let rule = &compiled.rule;
    let mut evidence = vec![
        format!("Found in {} by rule {}", root.display(), rule.id),
        format!("Last modified {} ago", describe(age)),
    ];
    if snapshot.links > 1 {
        evidence.push(format!(
            "Has {} hard links, so deleting it frees no space",
            snapshot.links
        ));
    }
    Finding {
        id,
        rule_id: rule.id.clone(),
        category: rule.category.clone(),
        risk: rule.risk,
        path: snapshot.path.clone(),
        root: root.to_path_buf(),
        size_on_disk: snapshot.reclaimable(),
        file_count: 1,
        last_modified: snapshot
            .modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        needs_admin: rule.needs_admin,
        evidence,
        target: Target::File(snapshot),
    }
}

/// `root\a\b.txt` → `"a/b.txt"`, for glob matching.
/// When the rule's location is a single file (like `%WINDIR%\MEMORY.DMP`),
/// it's the file's own name.
pub(crate) fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return path.file_name()?.to_str().map(str::to_owned);
    }
    let parts = relative
        .components()
        .map(|c| c.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()?;
    Some(parts.join("/"))
}

/// A case-insensitive key for deduplicating paths.
fn path_key(path: &Path) -> String {
    NormPath::new(path)
        .map(|p| p.to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_lowercase())
}
