//! Cleaning (PLANNING.md §4.4 and §4.5): turning a selection into a plan,
//! and running exactly that plan.
//!
//! A plan is fixed once it's built, and the confirmation shows it. Running
//! it never adds a file: each one is checked again right before it's
//! touched, and anything that changed since the scan is skipped. So the
//! list the user confirmed can only get shorter.
//!
//! Every file operation goes through the [`Executor`] in `oj-safety`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{CancelToken, Executor, Mode, Outcome, SkipReason, Store};
use serde::Serialize;

use crate::history::History;
use crate::results::{NodeId, ScanResults};
use crate::rule::Risk;
use crate::running::RunningPrograms;

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

/// What happens to each risk level (PLANNING.md §4.5). These are the
/// defaults; Settings will change them.
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
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
    /// Deleted for good.
    pub delete: Tally,
    /// Moved to quarantine, shortest stay first.
    pub quarantine: Vec<QuarantineGroup>,
    /// Selected, but left out: cleaning them needs administrator rights,
    /// which arrive with the elevated helper.
    pub needs_admin: Tally,
    /// Selected, but left out: their app is open (PLANNING.md §6.1).
    /// Biggest first.
    pub apps_open: Vec<OpenApp>,
}

impl PlanSummary {
    /// Files the plan will act on.
    pub fn files(&self) -> u64 {
        self.delete.files + self.quarantine.iter().map(|g| g.files).sum::<u64>()
    }
}

/// Exactly which files a cleanup will touch, and how.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The [`ScanResults::id`] it was built from.
    results: u64,
    /// Indices into the results' findings, in tree order.
    items: Vec<(usize, Action)>,
    summary: PlanSummary,
}

impl Plan {
    /// The plan for a selection (see [`ScanResults::selected`]). Files that
    /// need administrator rights, and files of apps that are `running`, are
    /// left out and only counted.
    pub fn build(
        results: &ScanResults,
        choices: &HashMap<NodeId, bool>,
        policy: &Policy,
        running: &RunningPrograms,
    ) -> Self {
        let findings = &results.report().findings;
        let open = open_apps(results, running);
        let mut items = Vec::new();
        let mut summary = PlanSummary::default();
        let mut groups: BTreeMap<u32, Tally> = BTreeMap::new();
        let mut apps: BTreeMap<&str, Tally> = BTreeMap::new();
        for index in results.selected(choices) {
            let finding = &findings[index];
            if finding.needs_admin {
                summary.needs_admin.add(finding.size_on_disk);
                continue;
            }
            if let Some(&app) = open.get(finding.rule_id.as_str()) {
                apps.entry(app).or_default().add(finding.size_on_disk);
                continue;
            }
            let action = policy.action(finding.risk);
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
            summary,
        }
    }

    pub fn summary(&self) -> &PlanSummary {
        &self.summary
    }

    /// Files the plan will act on.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Where a running cleanup is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanProgress {
    /// Files handled so far, out of `total`.
    pub done: u64,
    pub total: u64,
    /// Space freed so far.
    pub freed: u64,
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
    /// Deleted for good (in dry-run mode: would have been), and the space
    /// that freed.
    pub deleted: Tally,
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
}

impl Cleaner<'_> {
    /// Runs `plan`, file by file, then removes the folders it left empty.
    /// Once `cancel` is cancelled, it stops before the next file.
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
        let mut quarantined: BTreeMap<u32, Tally> = BTreeMap::new();
        let mut skipped: BTreeMap<&'static str, u64> = BTreeMap::new();
        // Folders that held a removed file, with the rule location above them.
        let mut emptied: HashMap<PathBuf, &Path> = HashMap::new();

        let total = plan.items.len() as u64;
        let mut done = 0;
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
                match action {
                    Action::Delete => self.executor.delete_file(&finding.snapshot),
                    Action::Quarantine { days } => self.executor.quarantine_file(
                        self.store,
                        &mut batch,
                        &finding.snapshot,
                        &finding.rule_id,
                        Duration::from_secs(u64::from(days) * DAY),
                        now,
                    ),
                }
            };
            match (&outcome, action) {
                (Outcome::Deleted { freed } | Outcome::WouldDelete { freed }, _) => {
                    deleted.files += 1;
                    deleted.size += freed;
                }
                (
                    Outcome::Quarantined { .. } | Outcome::WouldQuarantine,
                    Action::Quarantine { days },
                ) => quarantined
                    .entry(days)
                    .or_default()
                    .add(finding.size_on_disk),
                (Outcome::Skipped { reason }, _) => *skipped.entry(reason.key()).or_default() += 1,
                _ => {}
            }
            if matches!(
                outcome,
                Outcome::Deleted { .. } | Outcome::Quarantined { .. }
            ) {
                note_folders(&mut emptied, &finding.path, &finding.root);
            }
            self.history
                .file_action(cleanup, mode, finding, action, &outcome);
            done += 1;
            on_progress(&CleanProgress {
                done,
                total,
                freed: deleted.size,
            });
        }

        let folders_removed = self.remove_emptied(emptied, cleanup, mode);
        let mut skipped: Vec<SkipCount> = skipped
            .into_iter()
            .map(|(reason, files)| SkipCount { reason, files })
            .collect();
        skipped.sort_by_key(|count| Reverse(count.files));
        let mut report = CleanReport {
            mode,
            cancelled: done < total,
            deleted,
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

    /// Removes the emptied folders, deepest first, so a folder whose only
    /// content was emptied folders goes too. Returns how many went.
    fn remove_emptied(
        &mut self,
        emptied: HashMap<PathBuf, &Path>,
        cleanup: u64,
        mode: Mode,
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
            if let Outcome::Deleted { .. } = self.executor.remove_empty_folder(&folder, location) {
                removed += 1;
                self.history.folder_removed(cleanup, mode, &folder);
            }
        }
        removed
    }
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
fn note_folders<'a>(emptied: &mut HashMap<PathBuf, &'a Path>, file: &Path, root: &'a Path) {
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
