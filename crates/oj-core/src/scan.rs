//! Running rules against the filesystem. Read-only.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{CancelToken, DenyList, FileSnapshot, NormPath, WalkStats, walk_files};
use serde::Serialize;

use crate::age::{DEFAULT_MIN_AGE, describe};
use crate::rule::{CompiledRule, Level, Risk, RuleSet};
use crate::vars::{Vars, expand};

/// How to run a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub level: Level,
    /// Overrides every rule's minimum age (the user's setting).
    pub min_age_override: Option<Duration>,
    /// "Now", for age calculations. Tests can pin it.
    pub now: SystemTime,
}

impl ScanOptions {
    pub fn new(level: Level) -> Self {
        Self {
            level,
            min_age_override: None,
            now: SystemTime::now(),
        }
    }
}

/// One file a rule suggests cleaning.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: u64,
    pub rule_id: String,
    pub category: String,
    pub risk: Risk,
    pub path: PathBuf,
    /// The rule location the file was found under.
    pub root: PathBuf,
    /// Bytes freed by deleting it (0 for files with other hard links).
    pub size_on_disk: u64,
    pub file_count: u64,
    /// Seconds since the Unix epoch.
    pub last_modified: u64,
    pub needs_admin: bool,
    /// Human-readable reasons, shown in the details panel.
    pub evidence: Vec<String>,
    /// What the file looked like at scan time, for revalidation.
    #[serde(skip)]
    pub snapshot: FileSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Scanned,
    /// The app the rule is for isn't installed.
    NotDetected,
    /// None of the rule's locations exist on this machine.
    NoLocations,
}

/// What one rule found.
#[derive(Debug, Clone, Serialize)]
pub struct RuleReport {
    pub rule_id: String,
    pub name: String,
    /// What the rule cleans, in plain language, for the details panel.
    pub description: String,
    pub category: String,
    pub level: Level,
    pub risk: Risk,
    pub needs_admin: bool,
    pub status: RuleStatus,
    pub roots: Vec<PathBuf>,
    pub findings: u64,
    pub size_on_disk: u64,
    /// Matching files newer than the minimum age.
    pub skipped_recent: u64,
    /// Matching files another rule already reported.
    pub skipped_duplicates: u64,
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
}

/// Where a running scan is, for progress displays.
#[derive(Debug, Clone, Serialize)]
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
            needs_admin: rule.needs_admin,
            status: RuleStatus::Scanned,
            roots: Vec::new(),
            findings: 0,
            size_on_disk: 0,
            skipped_recent: 0,
            skipped_duplicates: 0,
            walk: WalkStats::default(),
            warnings: Vec::new(),
        };

        if let Some(detect) = &rule.detect {
            let detected = expand(detect, self.vars).is_ok_and(|path| path.exists());
            if !detected {
                report.status = RuleStatus::NotDetected;
                return report;
            }
        }

        let mut root_keys = HashSet::new();
        for template in &rule.paths {
            match expand(template, self.vars) {
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
            report.status = RuleStatus::NoLocations;
            return report;
        }

        let min_age = options
            .min_age_override
            .or(compiled.min_age)
            .unwrap_or(DEFAULT_MIN_AGE);

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
        snapshot,
    }
}

/// `root\a\b.txt` → `"a/b.txt"`, for glob matching.
fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
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
