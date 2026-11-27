//! Cleaning (PLANNING.md §4.4 and §4.5): turning a selection into a plan,
//! and running exactly that plan.
//!
//! A plan is fixed once it's built, and the confirmation shows it. Running
//! it never adds a file: each one is checked again right before it's
//! touched, and anything that changed since the scan is skipped. So the
//! list the user confirmed can only get shorter. A Recycle Bin is emptied
//! as a whole, and only if it still holds what the scan saw (D32).
//!
//! Every file operation goes through the [`Executor`] in `oj-safety`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{Batch, CancelToken, Executor, Mode, Outcome, SkipReason, Store};
use serde::{Deserialize, Serialize};

use crate::elevated::{ElevatedError, ElevatedItem, Elevator, HelperMessage};
use crate::history::History;
use crate::results::{NodeId, ScanResults};
use crate::rule::Risk;
use crate::running::RunningPrograms;
use crate::scan::{Finding, Target};

const DAY: u64 = 24 * 60 * 60;

/// What a cleanup does with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Deleted for good.
    Delete,
    /// Moved to quarantine, where it can be restored for `days` days.
    Quarantine { days: u32 },
}

/// What happens to each risk level (PLANNING.md §4.5). `default()` is the
/// built-in policy; [`Settings::policy`](crate::Settings::policy) builds
/// the user's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub low: Action,
    pub medium: Action,
    pub review: Action,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            low: Action::Delete,
            medium: Action::Quarantine { days: 7 },
            review: Action::Quarantine { days: 30 },
        }
    }
}

impl Policy {
    pub fn action(&self, risk: Risk) -> Action {
        match risk {
            Risk::Low => self.low,
            Risk::Medium => self.medium,
            Risk::Review => self.review,
        }
    }
}

/// A number of files and the space they take on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub files: u64,
    pub size: u64,
}

impl Tally {
    pub(crate) fn add(&mut self, size: u64) {
        self.files += 1;
        self.size += size;
    }
}

/// Files that go to quarantine for the same number of days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct QuarantineGroup {
    pub days: u32,
    pub files: u64,
    pub size: u64,
}

/// One drive's Recycle Bin, in totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BinTally {
    /// Its drive letter, such as `C`.
    pub drive: char,
    /// Items in it. A deleted folder counts as one, whatever is inside.
    pub items: u64,
    pub size: u64,
}

/// A Recycle Bin a cleanup left alone, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BinSkip {
    pub drive: char,
    /// [`oj_safety::SkipReason::key`], such as `changed`.
    pub reason: &'static str,
}

/// Selected files left out because their app is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenApp {
    /// The app's name, such as "Google Chrome".
    pub name: String,
    pub files: u64,
    pub size: u64,
}

/// A plan in totals: what the confirmation shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanSummary {
    /// Files deleted for good.
    pub delete: Tally,
    /// Recycle Bins emptied for good, each as a whole (D32).
    pub recycle_bins: Vec<BinTally>,
    /// Moved to quarantine, shortest stay first.
    pub quarantine: Vec<QuarantineGroup>,
    /// Files deleted for good by the elevated helper, after one UAC prompt
    /// (D34).
    pub elevated: Tally,
    /// Selected, but left out: they need administrator rights and would go
    /// to quarantine, and the quarantine for system files comes later.
    pub needs_admin: Tally,
    /// Selected, but left out: their app is open (PLANNING.md §6.1).
    /// Biggest first.
    pub apps_open: Vec<OpenApp>,
    /// Selected, but left out: "Always use the quarantine" is on, and a
    /// Recycle Bin can't go to quarantine (D32).
    pub recycle_bins_kept: Vec<BinTally>,
}

impl PlanSummary {
    /// Files the plan will act on, not counting Recycle Bins.
    pub fn files(&self) -> u64 {
        self.delete.files
            + self.elevated.files
            + self.quarantine.iter().map(|g| g.files).sum::<u64>()
    }
}

/// Exactly which files a cleanup will touch, and how.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The [`ScanResults::id`] it was built from.
    results: u64,
    /// Indices into the results' findings, in tree order.
    items: Vec<(usize, Action)>,
    /// Findings the elevated helper deletes, in tree order.
    elevated: Vec<usize>,
    summary: PlanSummary,
}

impl Plan {
    /// The plan for a selection (see [`ScanResults::selected`]). Files that
    /// need administrator rights go to the elevated helper when the policy
    /// deletes them, and are left out (and counted) when it would
    /// quarantine them. Files of apps that are `running` are left out too.
    pub fn build(
        results: &ScanResults,
        choices: &HashMap<NodeId, bool>,
        policy: &Policy,
        running: &RunningPrograms,
    ) -> Self {
        let findings = &results.report().findings;
        let open = open_apps(results, running);
        let mut items = Vec::new();
        let mut elevated = Vec::new();
        let mut summary = PlanSummary::default();
        let mut groups: BTreeMap<u32, Tally> = BTreeMap::new();
        let mut apps: BTreeMap<&str, Tally> = BTreeMap::new();
        for index in results.selected(choices) {
            let finding = &findings[index];
            if finding.needs_admin {
                let file = matches!(finding.target, Target::File(_));
                if file && policy.action(finding.risk) == Action::Delete {
                    summary.elevated.add(finding.size_on_disk);
                    elevated.push(index);
                } else {
                    summary.needs_admin.add(finding.size_on_disk);
                }
                continue;
            }
            if let Some(&app) = open.get(finding.rule_id.as_str()) {
                apps.entry(app).or_default().add(finding.size_on_disk);
                continue;
            }
            let action = policy.action(finding.risk);
            if let Target::RecycleBin { drive, contents } = finding.target {
                let bin = BinTally {
                    drive,
                    items: contents.items,
                    size: contents.size,
                };
                match action {
                    Action::Delete => {
                        summary.recycle_bins.push(bin);
                        items.push((index, action));
                    }
                    // Whoever asked for the quarantine asked for nothing to
                    // be deleted directly.
                    Action::Quarantine { .. } => summary.recycle_bins_kept.push(bin),
                }
                continue;
            }
            match action {
                Action::Delete => summary.delete.add(finding.size_on_disk),
                Action::Quarantine { days } => {
                    groups.entry(days).or_default().add(finding.size_on_disk)
                }
            }
            items.push((index, action));
        }
        summary.quarantine = groups
            .into_iter()
            .map(|(days, tally)| QuarantineGroup {
                days,
                files: tally.files,
                size: tally.size,
            })
            .collect();
        summary.apps_open = apps
            .into_iter()
            .map(|(name, tally)| OpenApp {
                name: name.to_owned(),
                files: tally.files,
                size: tally.size,
            })
            .collect();
        summary.apps_open.sort_by_key(|app| Reverse(app.size));
        Self {
            results: results.id(),
            items,
            elevated,
            summary,
        }
    }

    pub fn summary(&self) -> &PlanSummary {
        &self.summary
    }

    /// Files (and Recycle Bins) the plan will act on.
    pub fn len(&self) -> usize {
        self.items.len() + self.elevated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a running cleanup is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanProgress {
    /// Files (and Recycle Bins) handled so far, out of `total`.
    pub done: u64,
    pub total: u64,
    /// Space freed so far, Recycle Bins included.
    pub freed: u64,
    /// Waiting for the user to answer Windows' administrator prompt.
    pub admin_prompt: bool,
}

/// Files now in quarantine for the same number of days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct QuarantinedGroup {
    pub days: u32,
    /// When they may be deleted for good, in seconds since the Unix epoch.
    pub expires_at: u64,
    pub files: u64,
    pub size: u64,
}

/// Files left alone for one reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkipCount {
    /// [`oj_safety::SkipReason::key`].
    pub reason: &'static str,
    pub files: u64,
}

/// What a cleanup did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanReport {
    pub mode: Mode,
    /// Stopped before the end. The `not_started` files weren't touched.
    pub cancelled: bool,
    /// Files deleted for good (in dry-run mode: would have been), and the
    /// space that freed.
    pub deleted: Tally,
    /// Recycle Bins emptied (in dry-run mode: would have been). Their space
    /// is freed too, but isn't in `deleted`.
    pub recycle_bins: Vec<BinTally>,
    /// Recycle Bins left alone, such as one that changed since the scan.
    pub recycle_bins_skipped: Vec<BinSkip>,
    /// Moved to quarantine, shortest stay first. Their space comes back
    /// when they're deleted for good.
    pub quarantined: Vec<QuarantinedGroup>,
    /// The quarantine batch they went to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<String>,
    /// Files left alone, most common reason first.
    pub skipped: Vec<SkipCount>,
    pub not_started: u64,
    /// Folders removed because the cleanup left them empty.
    pub folders_removed: u64,
    /// Selected files left out because they need administrator rights.
    pub needs_admin: Tally,
    /// Selected files left out because their app was open.
    pub apps_open: Vec<OpenApp>,
    /// Selected Recycle Bins left out because "Always use the quarantine"
    /// is on.
    pub recycle_bins_kept: Vec<BinTally>,
    /// The history couldn't be written in full.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_error: Option<String>,
}

/// Runs cleanup plans.
pub struct Cleaner<'a> {
    pub executor: &'a Executor<'a>,
    /// Where quarantined files go.
    pub store: &'a Store,
    pub history: &'a mut History,
    /// What's running as the cleanup starts. Files of an app opened since
    /// the plan was made are skipped.
    pub running: &'a RunningPrograms,
    /// Deletes the files that need administrator rights. Without one, they
    /// are left alone.
    pub elevator: Option<&'a mut dyn Elevator>,
}

impl Cleaner<'_> {
    /// Runs `plan`, file by file, then removes the folders it left empty.
    /// The files that need administrator rights go first, so Windows asks
    /// for permission right after the confirmation (D34). Once `cancel` is
    /// cancelled, it stops before the next file.
    ///
    /// # Panics
    ///
    /// If `plan` wasn't built from `results`.
    pub fn run(
        &mut self,
        results: &ScanResults,
        plan: &Plan,
        now: SystemTime,
        cancel: &CancelToken,
        on_progress: &mut dyn FnMut(&CleanProgress),
    ) -> CleanReport {
        assert_eq!(
            plan.results,
            results.id(),
            "a plan only runs against the results it was built from"
        );
        let findings = &results.report().findings;
        let opened = open_apps(results, self.running);
        let mode = self.executor.mode();
        let cleanup = unix_millis(now);
        let mut batch = self.store.new_batch(now);
        let mut deleted = Tally::default();
        let mut freed = 0;
        let mut recycle_bins = Vec::new();
        let mut recycle_bins_skipped = Vec::new();
        let mut quarantined: BTreeMap<u32, Tally> = BTreeMap::new();
        let mut skipped: BTreeMap<&'static str, u64> = BTreeMap::new();
        // Folders that held a removed file, with the rule location above them.
        let mut emptied: HashMap<PathBuf, &Path> = HashMap::new();

        let total = plan.len() as u64;
        let mut done = 0;
        let mut folders_removed = 0;

        if !plan.elevated.is_empty() && !cancel.is_cancelled() {
            let elevated: Vec<&Finding> = plan.elevated.iter().map(|&i| &findings[i]).collect();
            let items: Vec<ElevatedItem> = elevated
                .iter()
                .filter_map(|finding| ElevatedItem::from_finding(finding))
                .collect();
            on_progress(&CleanProgress {
                done,
                total,
                freed,
                admin_prompt: true,
            });
            let mut answered = vec![false; elevated.len()];
            let mut refused = None;
            let history = &mut *self.history;
            let mut on_message = |message: HelperMessage| match message {
                HelperMessage::Outcome { index, outcome } => {
                    // Anything the helper says about other items is ignored.
                    let Some(&finding) = elevated.get(index) else {
                        return;
                    };
                    if std::mem::replace(&mut answered[index], true) {
                        return;
                    }
                    match &outcome {
                        Outcome::Deleted { freed: size } | Outcome::WouldDelete { freed: size } => {
                            freed += size;
                            deleted.files += 1;
                            deleted.size += size;
                        }
                        Outcome::Skipped { reason } => {
                            *skipped.entry(reason.key()).or_default() += 1
                        }
                        _ => {}
                    }
                    history.file_action(cleanup, mode, finding, Action::Delete, &outcome);
                    done += 1;
                    on_progress(&CleanProgress {
                        done,
                        total,
                        freed,
                        admin_prompt: false,
                    });
                }
                HelperMessage::FolderRemoved { path } => {
                    folders_removed += 1;
                    history.folder_removed(cleanup, mode, &path);
                }
                HelperMessage::Refused { message } => refused = Some(message),
                HelperMessage::Done => {}
            };
            let result = match self.elevator.as_deref_mut() {
                Some(elevator) => elevator.run(&items, cancel, &mut on_message),
                None => Err(ElevatedError::Failed(
                    "this cleanup can't ask for administrator rights".into(),
                )),
            };
            let reason = match (result, refused) {
                (Err(ElevatedError::Declined), _) => Some(SkipReason::AdminDeclined),
                (Err(ElevatedError::Failed(message)), _) | (Ok(()), Some(message)) => {
                    Some(SkipReason::Failed(message))
                }
                // Unanswered after a clean finish: stopped by the user.
                (Ok(()), None) => None,
            };
            if let Some(reason) = reason {
                for (index, &finding) in elevated.iter().enumerate() {
                    if answered[index] {
                        continue;
                    }
                    let outcome = Outcome::Skipped {
                        reason: reason.clone(),
                    };
                    *skipped.entry(reason.key()).or_default() += 1;
                    self.history
                        .file_action(cleanup, mode, finding, Action::Delete, &outcome);
                    done += 1;
                }
                on_progress(&CleanProgress {
                    done,
                    total,
                    freed,
                    admin_prompt: false,
                });
            }
        }

        for &(index, action) in &plan.items {
            if cancel.is_cancelled() {
                break;
            }
            let finding = &findings[index];
            let outcome = if opened.contains_key(finding.rule_id.as_str()) {
                Outcome::Skipped {
                    reason: SkipReason::AppRunning,
                }
            } else {
                self.act(&mut batch, finding, action, now)
            };
            match (&finding.target, &outcome, action) {
                (
                    Target::RecycleBin { drive, contents },
                    Outcome::Deleted { freed: size } | Outcome::WouldDelete { freed: size },
                    _,
                ) => {
                    freed += size;
                    recycle_bins.push(BinTally {
                        drive: *drive,
                        items: contents.items,
                        size: *size,
                    });
                }
                (Target::RecycleBin { drive, .. }, Outcome::Skipped { reason }, _) => {
                    recycle_bins_skipped.push(BinSkip {
                        drive: *drive,
                        reason: reason.key(),
                    });
                }
                (Target::RecycleBin { .. }, _, _) => {}
                (_, Outcome::Deleted { freed: size } | Outcome::WouldDelete { freed: size }, _) => {
                    freed += size;
                    deleted.files += 1;
                    deleted.size += size;
                }
                (
                    _,
                    Outcome::Quarantined { .. } | Outcome::WouldQuarantine,
                    Action::Quarantine { days },
                ) => quarantined
                    .entry(days)
                    .or_default()
                    .add(finding.size_on_disk),
                (_, Outcome::Skipped { reason }, _) => {
                    *skipped.entry(reason.key()).or_default() += 1
                }
                _ => {}
            }
            let removed = matches!(
                outcome,
                Outcome::Deleted { .. } | Outcome::Quarantined { .. }
            );
            if removed && matches!(finding.target, Target::File(_)) {
                note_folders(&mut emptied, &finding.path, &finding.root);
            }
            self.history
                .file_action(cleanup, mode, finding, action, &outcome);
            done += 1;
            on_progress(&CleanProgress {
                done,
                total,
                freed,
                admin_prompt: false,
            });
        }

        let history = &mut *self.history;
        folders_removed += remove_empty_folders(self.executor, emptied, &mut |folder| {
            history.folder_removed(cleanup, mode, folder);
        });
        let mut skipped: Vec<SkipCount> = skipped
            .into_iter()
            .map(|(reason, files)| SkipCount { reason, files })
            .collect();
        skipped.sort_by_key(|count| Reverse(count.files));
        let mut report = CleanReport {
            mode,
            cancelled: done < total,
            deleted,
            recycle_bins,
            recycle_bins_skipped,
            quarantined: quarantined
                .into_iter()
                .map(|(days, tally)| QuarantinedGroup {
                    days,
                    expires_at: unix_secs(now) + u64::from(days) * DAY,
                    files: tally.files,
                    size: tally.size,
                })
                .collect(),
            batch: (!batch.manifest().items.is_empty()).then(|| batch.name().to_owned()),
            skipped,
            not_started: total - done,
            folders_removed,
            needs_admin: plan.summary.needs_admin,
            apps_open: plan.summary.apps_open.clone(),
            recycle_bins_kept: plan.summary.recycle_bins_kept.clone(),
            history_error: None,
        };
        self.history.cleanup(
            cleanup,
            unix_secs(now),
            unix_secs(SystemTime::now()),
            &report,
        );
        report.history_error = self.history.error().map(str::to_owned);
        report
    }

    /// Deletes, quarantines, or empties one plan item, through the executor.
    fn act(
        &self,
        batch: &mut Batch,
        finding: &Finding,
        action: Action,
        now: SystemTime,
    ) -> Outcome {
        match (&finding.target, action) {
            (Target::File(snapshot), Action::Delete) => self.executor.delete_file(snapshot),
            (Target::File(snapshot), Action::Quarantine { days }) => self.executor.quarantine_file(
                self.store,
                batch,
                snapshot,
                &finding.rule_id,
                Duration::from_secs(u64::from(days) * DAY),
                now,
            ),
            (Target::RecycleBin { drive, contents }, Action::Delete) => {
                self.executor.empty_recycle_bin(*drive, *contents)
            }
            // Plans never ask for this.
            (Target::RecycleBin { .. }, Action::Quarantine { .. }) => Outcome::Skipped {
                reason: SkipReason::Failed("a Recycle Bin can't be moved to quarantine".into()),
            },
        }
    }
}

/// Removes the emptied folders, deepest first, so a folder whose only
/// content was emptied folders goes too. Calls `on_removed` for each, and
/// returns how many went.
pub(crate) fn remove_empty_folders(
    executor: &Executor,
    emptied: HashMap<PathBuf, &Path>,
    on_removed: &mut dyn FnMut(&Path),
) -> u64 {
    let mut folders: Vec<(PathBuf, &Path)> = emptied.into_iter().collect();
    folders.sort_by(|(a, _), (b, _)| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    let mut removed = 0;
    for (folder, location) in folders {
        if let Outcome::Deleted { .. } = executor.remove_empty_folder(&folder, location) {
            removed += 1;
            on_removed(&folder);
        }
    }
    removed
}

/// The rules whose app is running, with the app's name.
fn open_apps<'r>(results: &'r ScanResults, running: &RunningPrograms) -> HashMap<&'r str, &'r str> {
    results
        .report()
        .rules
        .iter()
        .filter_map(|rule| {
            let app = rule.app.as_ref().filter(|app| running.is_running(app))?;
            Some((rule.rule_id.as_str(), app.name.as_str()))
        })
        .collect()
}

/// Adds every folder between `file` and its rule location `root` (which
/// itself is never removed).
pub(crate) fn note_folders<'a>(
    emptied: &mut HashMap<PathBuf, &'a Path>,
    file: &Path,
    root: &'a Path,
) {
    let mut folder = file.parent();
    while let Some(dir) = folder {
        if dir == root || !dir.starts_with(root) || emptied.contains_key(dir) {
            // An already noted folder has its parents noted too.
            break;
        }
        emptied.insert(dir.to_path_buf(), root);
        folder = dir.parent();
    }
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_deletes_low_risk_and_quarantines_the_rest() {
        let policy = Policy::default();
        assert_eq!(policy.action(Risk::Low), Action::Delete);
        assert_eq!(policy.action(Risk::Medium), Action::Quarantine { days: 7 });
        assert_eq!(policy.action(Risk::Review), Action::Quarantine { days: 30 });
    }

    #[test]
    fn folders_between_a_file_and_its_location_are_noted() {
        let root = Path::new(r"C:\Temp");
        let mut emptied = HashMap::new();
        note_folders(&mut emptied, Path::new(r"C:\Temp\a\b\file.tmp"), root);
        note_folders(&mut emptied, Path::new(r"C:\Temp\a\c.tmp"), root);
        note_folders(&mut emptied, Path::new(r"C:\Temp\top.tmp"), root);
        let mut noted: Vec<&Path> = emptied.keys().map(PathBuf::as_path).collect();
        noted.sort();
        assert_eq!(noted, [Path::new(r"C:\Temp\a"), Path::new(r"C:\Temp\a\b")]);

        // A location that is itself a file has no folders below it.
        let mut emptied = HashMap::new();
        let dump = Path::new(r"C:\Windows\MEMORY.DMP");
        note_folders(&mut emptied, dump, dump);
        assert!(emptied.is_empty());
    }
}
