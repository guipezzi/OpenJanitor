//! What the app remembers between commands: the results of the last scan,
//! the cleanup plan made from them, the quarantine as last shown, and the
//! operation that's running, if any.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_core::{
    CancelToken, ChildPage, DETAIL_DAYS, HistoryEntry, HistoryFilePage, HistoryTotals, HistoryView,
    ItemRef, Level, NodeId, NodeKind, NodeView, Plan, PlanSummary, Policy, QuarantineReport,
    QuarantineSummary, QuarantineView, RuleReport, RunningPrograms, ScanReport, ScanResults,
};
use oj_safety::{Entry, EntryKind, Mode, ProtectedList};
use serde::Serialize;

/// The most children one request can fetch.
pub const MAX_PAGE: usize = 500;

/// Results older than this get a "scan again" suggestion before cleaning.
pub const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// What the UI gets after a completed scan.
#[derive(Debug, Serialize)]
pub struct ScanOverview {
    /// Identifies these results. Requests for more of the tree quote it,
    /// so they can't mix up two scans.
    pub scan_id: u64,
    pub level: Level,
    pub findings_total: u64,
    pub size_on_disk_total: u64,
    pub rules: Vec<RuleReport>,
    /// Categories, biggest first, each with its rules.
    pub categories: Vec<NodeView>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScanOutcome {
    Completed { overview: ScanOverview },
    Cancelled,
}

/// What the confirmation shows: a cleanup plan in totals.
#[derive(Debug, Serialize)]
pub struct PlanView {
    /// Running the cleanup quotes it, so exactly this plan runs.
    pub plan_id: u64,
    pub mode: Mode,
    #[serde(flatten)]
    pub summary: PlanSummary,
    /// When the scan finished, in seconds since the Unix epoch.
    pub scanned_at: u64,
    /// The results are old enough that scanning again first is worth it.
    pub stale: bool,
}

/// What the Quarantine screen gets.
#[derive(Debug, Serialize)]
pub struct QuarantineOverview {
    /// Identifies this view; actions quote it, so they can't mix up node
    /// ids from an older one.
    pub view_id: u64,
    pub mode: Mode,
    #[serde(flatten)]
    pub summary: QuarantineSummary,
    /// Batches, newest first, each with its folders.
    pub batches: Vec<NodeView>,
    /// Expired files deleted when the app started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<ExpiredNote>,
}

/// What the History screen gets.
#[derive(Debug, Serialize)]
pub struct HistoryOverview {
    /// Requests for an entry's files quote it.
    pub view_id: u64,
    /// Newest first.
    pub entries: Vec<HistoryEntry>,
    pub totals: HistoryTotals,
    pub unreadable_lines: u64,
    /// How long per-file details are kept.
    pub detail_days: u64,
}

/// What deleting expired files at startup did.
#[derive(Debug, Clone, Serialize)]
pub struct ExpiredNote {
    /// Seconds since the Unix epoch.
    pub at: u64,
    #[serde(flatten)]
    pub report: QuarantineReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Scan,
    Clean,
    Quarantine,
}

#[derive(Debug)]
struct Running {
    operation: Operation,
    cancel: CancelToken,
}

#[derive(Debug)]
struct Session {
    id: u64,
    results: ScanResults,
    scanned_at: SystemTime,
    /// The latest plan made from these results, with its id.
    plan: Option<(u64, Plan)>,
}

#[derive(Debug, Default)]
pub struct AppState {
    last_scan_id: AtomicU64,
    last_plan_id: AtomicU64,
    /// One scan, cleanup, or quarantine action at a time.
    running: Mutex<Option<Running>>,
    session: Mutex<Option<Session>>,
    /// The quarantine as the Quarantine screen last loaded it.
    quarantine: Mutex<Option<QuarantineView>>,
    expired: Mutex<Option<ExpiredNote>>,
    /// The history as the History screen last loaded it.
    history: Mutex<Option<HistoryView>>,
    /// Held while reading, changing, and saving the Protected list, so two
    /// changes can't overwrite each other.
    protected_file: Mutex<()>,
}

/// A panic while a lock was held leaves plain data behind, so carry on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn overview(id: u64, results: &ScanResults) -> ScanOverview {
    let report = results.report();
    ScanOverview {
        scan_id: id,
        level: report.level,
        findings_total: report.findings_total,
        size_on_disk_total: report.size_on_disk_total,
        rules: report.rules.clone(),
        categories: results.categories(),
    }
}

impl AppState {
    /// Starts a scan: forgets the previous results and returns the token
    /// that cancels this one. Fails if a scan or a cleanup is running.
    pub fn begin_scan(&self) -> Result<CancelToken, String> {
        let mut running = lock(&self.running);
        if let Some(busy) = running.as_ref() {
            return Err(busy_message(busy.operation));
        }
        *lock(&self.session) = None;
        let cancel = CancelToken::new();
        *running = Some(Running {
            operation: Operation::Scan,
            cancel: cancel.clone(),
        });
        Ok(cancel)
    }

    /// Asks the running scan, if any, to stop.
    pub fn cancel_scan(&self) {
        self.cancel(Operation::Scan);
    }

    /// Records how a scan ended. Call it exactly once after each
    /// [`begin_scan`](Self::begin_scan).
    pub fn finish_scan(&self, result: Result<ScanReport, String>) -> Result<ScanOutcome, String> {
        let outcome = match result {
            Ok(report) if report.cancelled => Ok(ScanOutcome::Cancelled),
            Ok(report) => {
                let id = self.last_scan_id.fetch_add(1, Ordering::Relaxed) + 1;
                let results = ScanResults::new(report);
                let overview = overview(id, &results);
                *lock(&self.session) = Some(Session {
                    id,
                    results,
                    scanned_at: SystemTime::now(),
                    plan: None,
                });
                Ok(ScanOutcome::Completed { overview })
            }
            Err(error) => Err(error),
        };
        self.finish(Operation::Scan);
        outcome
    }

    /// Makes the cleanup plan for a selection of scan `scan_id`'s results
    /// and keeps it, replacing any earlier plan. Only this plan can run.
    pub fn plan_clean(
        &self,
        scan_id: u64,
        choices: &HashMap<NodeId, bool>,
        policy: &Policy,
        running: &RunningPrograms,
        mode: Mode,
        now: SystemTime,
    ) -> Result<PlanView, String> {
        let mut session = lock(&self.session);
        let session = session
            .as_mut()
            .filter(|session| session.id == scan_id)
            .ok_or(OUT_OF_DATE)?;
        let plan = Plan::build(&session.results, choices, policy, running);
        let plan_id = self.last_plan_id.fetch_add(1, Ordering::Relaxed) + 1;
        let view = PlanView {
            plan_id,
            mode,
            summary: plan.summary().clone(),
            scanned_at: unix_secs(session.scanned_at),
            stale: now
                .duration_since(session.scanned_at)
                .is_ok_and(|age| age > STALE_AFTER),
        };
        session.plan = Some((plan_id, plan));
        Ok(view)
    }

    /// Starts cleanup `plan_id`. The results it came from are handed over
    /// and forgotten here, since cleaning makes them out of date. Fails if
    /// the plan was replaced, if its results are gone, or if a scan or a
    /// cleanup is running.
    pub fn begin_clean(&self, plan_id: u64) -> Result<(ScanResults, Plan, CancelToken), String> {
        let mut running = lock(&self.running);
        if let Some(busy) = running.as_ref() {
            return Err(busy_message(busy.operation));
        }
        let mut session = lock(&self.session);
        let current = session
            .as_ref()
            .and_then(|s| s.plan.as_ref())
            .is_some_and(|(id, _)| *id == plan_id);
        if !current {
            return Err("This cleanup is out of date. Review it again.".into());
        }
        let session = session.take().expect("checked above");
        let (_, plan) = session.plan.expect("checked above");
        let results = session.results;
        let cancel = CancelToken::new();
        *running = Some(Running {
            operation: Operation::Clean,
            cancel: cancel.clone(),
        });
        Ok((results, plan, cancel))
    }

    /// Asks the running cleanup, if any, to stop after the current file.
    pub fn cancel_clean(&self) {
        self.cancel(Operation::Clean);
    }

    /// Records that the cleanup ended. Call it once after each successful
    /// [`begin_clean`](Self::begin_clean).
    pub fn finish_clean(&self) {
        self.finish(Operation::Clean);
    }

    /// Keeps a freshly loaded quarantine view, replacing the last one, and
    /// returns what the Quarantine screen shows.
    pub fn show_quarantine(&self, view: QuarantineView, mode: Mode) -> QuarantineOverview {
        let overview = QuarantineOverview {
            view_id: view.id(),
            mode,
            summary: view.summary().clone(),
            batches: view.batches(),
            expired: lock(&self.expired).clone(),
        };
        *lock(&self.quarantine) = Some(view);
        overview
    }

    /// One page of a node's children from quarantine view `view_id`.
    pub fn quarantine_children(
        &self,
        view_id: u64,
        node: NodeId,
        offset: usize,
        limit: usize,
    ) -> Result<ChildPage, String> {
        self.with_quarantine(view_id, |view| {
            view.children(node, offset, limit.min(MAX_PAGE))
                .ok_or_else(|| no_item(node))
        })
    }

    /// The quarantined files a selection in view `view_id` covers.
    pub fn quarantine_items(
        &self,
        view_id: u64,
        choices: &HashMap<NodeId, bool>,
    ) -> Result<Vec<ItemRef>, String> {
        self.with_quarantine(view_id, |view| Ok(view.selected(choices)))
    }

    /// Starts a restore or a delete: the view it came from is out of date
    /// afterwards. Fails if anything else is running.
    pub fn begin_quarantine(&self) -> Result<(), String> {
        let mut running = lock(&self.running);
        if let Some(busy) = running.as_ref() {
            return Err(busy_message(busy.operation));
        }
        *lock(&self.quarantine) = None;
        *running = Some(Running {
            operation: Operation::Quarantine,
            cancel: CancelToken::new(),
        });
        Ok(())
    }

    /// Records that the restore or delete ended.
    pub fn finish_quarantine(&self) {
        self.finish(Operation::Quarantine);
    }

    /// Keeps a freshly read history, replacing the last one, and returns
    /// what the History screen shows.
    pub fn show_history(&self, view: HistoryView) -> HistoryOverview {
        let overview = HistoryOverview {
            view_id: view.id(),
            entries: view.entries().to_vec(),
            totals: view.totals(),
            unreadable_lines: view.unreadable_lines(),
            detail_days: DETAIL_DAYS,
        };
        *lock(&self.history) = Some(view);
        overview
    }

    /// One page of entry `entry`'s files from history view `view_id`.
    pub fn history_files(
        &self,
        view_id: u64,
        entry: u32,
        offset: usize,
        limit: usize,
    ) -> Result<HistoryFilePage, String> {
        let view = lock(&self.history);
        let view = view
            .as_ref()
            .filter(|view| view.id() == view_id)
            .ok_or("The history changed. Open it again.")?;
        view.files(entry, offset, limit.min(MAX_PAGE))
            .ok_or_else(|| format!("There's no entry {entry} in this history."))
    }

    /// Remembers what deleting expired files at startup did.
    pub fn set_expired(&self, note: ExpiredNote) {
        *lock(&self.expired) = Some(note);
    }

    fn with_quarantine<T>(
        &self,
        view_id: u64,
        f: impl FnOnce(&QuarantineView) -> Result<T, String>,
    ) -> Result<T, String> {
        let view = lock(&self.quarantine);
        let view = view
            .as_ref()
            .filter(|view| view.id() == view_id)
            .ok_or("The quarantine changed. Open it again.")?;
        f(view)
    }

    fn cancel(&self, operation: Operation) {
        if let Some(running) = lock(&self.running)
            .as_ref()
            .filter(|r| r.operation == operation)
        {
            running.cancel.cancel();
        }
    }

    /// Frees the slot, but only for the operation that holds it.
    fn finish(&self, operation: Operation) {
        let mut running = lock(&self.running);
        if running.as_ref().is_some_and(|r| r.operation == operation) {
            *running = None;
        }
    }

    /// One page of a node's children from the results of scan `scan_id`.
    pub fn children(
        &self,
        scan_id: u64,
        node: NodeId,
        offset: usize,
        limit: usize,
    ) -> Result<ChildPage, String> {
        self.with_results(scan_id, |results| {
            results
                .children(node, offset, limit.min(MAX_PAGE))
                .ok_or_else(|| no_item(node))
        })
    }

    /// The path of a location, folder, or file node from scan `scan_id`.
    pub fn node_path(&self, scan_id: u64, node: NodeId) -> Result<PathBuf, String> {
        self.with_results(scan_id, |results| {
            results
                .path(node)
                .map(Path::to_path_buf)
                .ok_or_else(|| no_item(node))
        })
    }

    /// What protecting node `node` of scan `scan_id` means: its rule, its
    /// folder, or its file. Whole categories can't be protected.
    pub fn protect_entry(&self, scan_id: u64, node: NodeId, now: u64) -> Result<Entry, String> {
        self.with_results(scan_id, |results| {
            let view = results.node(node).ok_or_else(|| no_item(node))?;
            let path = || {
                results
                    .path(node)
                    .map(|path| path.to_string_lossy().into_owned())
                    .ok_or_else(|| no_item(node))
            };
            let (kind, value, label) = match view.kind {
                NodeKind::Category => {
                    return Err(
                        "Protect a rule, folder, or file inside this category instead.".into(),
                    );
                }
                NodeKind::Rule => (
                    EntryKind::Rule,
                    view.rule_id.ok_or_else(|| no_item(node))?,
                    Some(view.name),
                ),
                NodeKind::Location | NodeKind::Folder => (EntryKind::Folder, path()?, None),
                NodeKind::File => (EntryKind::File, path()?, None),
                NodeKind::Batch => return Err(no_item(node)),
            };
            Ok(Entry {
                kind,
                value,
                label,
                added_at: now,
            })
        })
    }

    /// Hides what `protected` covers from the current results, keeping
    /// node ids. Returns the updated overview, if there are results.
    pub fn apply_protection(&self, protected: &ProtectedList) -> Option<ScanOverview> {
        let mut session = lock(&self.session);
        let session = session.as_mut()?;
        session.results.hide_protected(protected);
        Some(overview(session.id, &session.results))
    }

    /// Serializes changes to the Protected list file.
    pub fn protected_file(&self) -> MutexGuard<'_, ()> {
        lock(&self.protected_file)
    }

    fn with_results<T>(
        &self,
        scan_id: u64,
        f: impl FnOnce(&ScanResults) -> Result<T, String>,
    ) -> Result<T, String> {
        let session = lock(&self.session);
        let session = session
            .as_ref()
            .filter(|session| session.id == scan_id)
            .ok_or(OUT_OF_DATE)?;
        f(&session.results)
    }
}

const OUT_OF_DATE: &str = "These results are out of date. Scan again.";

fn busy_message(operation: Operation) -> String {
    match operation {
        Operation::Scan => "A scan is already running.",
        Operation::Clean => "A cleanup is running. Wait for it to finish.",
        Operation::Quarantine => "The quarantine is busy. Wait a moment and try again.",
    }
    .into()
}

fn no_item(node: NodeId) -> String {
    format!("There's no item {node} in these results.")
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(cancelled: bool) -> ScanReport {
        ScanReport {
            level: Level::Simple,
            findings_total: 0,
            size_on_disk_total: 0,
            rules: Vec::new(),
            findings: Vec::new(),
            cancelled,
        }
    }

    fn completed_id(outcome: Result<ScanOutcome, String>) -> u64 {
        match outcome {
            Ok(ScanOutcome::Completed { overview }) => overview.scan_id,
            other => panic!("expected a completed scan, got {other:?}"),
        }
    }

    #[test]
    fn only_one_scan_runs_at_a_time() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        assert!(state.begin_scan().is_err());
        state.finish_scan(Ok(report(false))).unwrap();
        assert!(state.begin_scan().is_ok());
    }

    #[test]
    fn cancelling_reaches_the_running_scan() {
        let state = AppState::default();
        let cancel = state.begin_scan().unwrap();
        state.cancel_scan();
        assert!(cancel.is_cancelled());
        assert!(matches!(
            state.finish_scan(Ok(report(true))),
            Ok(ScanOutcome::Cancelled)
        ));
        assert!(state.children(1, 0, 0, 10).is_err(), "nothing was kept");
    }

    #[test]
    fn children_need_the_current_scan_id() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        let first = completed_id(state.finish_scan(Ok(report(false))));
        let error = state.children(first, 0, 0, 10).unwrap_err();
        assert!(error.contains("no item"), "{error}");
        let error = state.node_path(first, 0).unwrap_err();
        assert!(error.contains("no item"), "{error}");

        state.begin_scan().unwrap();
        let out_of_date = state.children(first, 0, 0, 10).unwrap_err();
        assert!(out_of_date.contains("out of date"), "{out_of_date}");
        let out_of_date = state.node_path(first, 0).unwrap_err();
        assert!(out_of_date.contains("out of date"), "{out_of_date}");
        let second = completed_id(state.finish_scan(Ok(report(false))));
        assert_eq!(second, first + 1);
    }

    #[test]
    fn protection_needs_current_results() {
        let state = AppState::default();
        assert!(state.apply_protection(&ProtectedList::new()).is_none());
        let error = state.protect_entry(1, 0, 0).unwrap_err();
        assert!(error.contains("out of date"), "{error}");

        state.begin_scan().unwrap();
        let id = completed_id(state.finish_scan(Ok(report(false))));
        let overview = state.apply_protection(&ProtectedList::new()).unwrap();
        assert_eq!(overview.scan_id, id, "same scan, same ids");
        assert!(
            state
                .protect_entry(id, 0, 0)
                .unwrap_err()
                .contains("no item")
        );
    }

    fn plan(state: &AppState, scan_id: u64, now: SystemTime) -> Result<PlanView, String> {
        state.plan_clean(
            scan_id,
            &HashMap::new(),
            &Policy::default(),
            &RunningPrograms::default(),
            Mode::DryRun,
            now,
        )
    }

    #[test]
    fn a_plan_needs_the_current_results() {
        let state = AppState::default();
        assert!(
            plan(&state, 1, SystemTime::now())
                .unwrap_err()
                .contains("out of date")
        );

        state.begin_scan().unwrap();
        let id = completed_id(state.finish_scan(Ok(report(false))));
        let first = plan(&state, id, SystemTime::now()).unwrap();
        assert_eq!(first.mode, Mode::DryRun);
        assert!(!first.stale);
        let second = plan(&state, id, SystemTime::now()).unwrap();
        assert_ne!(first.plan_id, second.plan_id);

        let error = state.begin_clean(first.plan_id).unwrap_err();
        assert!(
            error.contains("Review it again"),
            "a newer plan replaced it"
        );
        assert!(state.begin_clean(second.plan_id).is_ok());
    }

    #[test]
    fn old_results_are_flagged() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        let id = completed_id(state.finish_scan(Ok(report(false))));
        let later = SystemTime::now() + STALE_AFTER + Duration::from_secs(1);
        assert!(plan(&state, id, later).unwrap().stale);
    }

    #[test]
    fn a_cleanup_takes_the_results_and_blocks_scans() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        let id = completed_id(state.finish_scan(Ok(report(false))));
        let view = plan(&state, id, SystemTime::now()).unwrap();

        let (_results, _plan, cancel) = state.begin_clean(view.plan_id).unwrap();
        assert!(state.begin_clean(view.plan_id).is_err(), "a plan runs once");
        assert!(
            state
                .begin_scan()
                .unwrap_err()
                .contains("cleanup is running")
        );
        assert!(
            state
                .children(id, 0, 0, 10)
                .unwrap_err()
                .contains("out of date")
        );

        state.cancel_scan();
        assert!(
            !cancel.is_cancelled(),
            "only a cleanup's own cancel reaches it"
        );
        state.cancel_clean();
        assert!(cancel.is_cancelled());

        state.finish_scan(Err("not mine".into())).unwrap_err();
        assert!(
            state.begin_scan().is_err(),
            "a scan can't free the cleanup's slot"
        );
        state.finish_clean();
        assert!(state.begin_scan().is_ok());
    }

    #[test]
    fn a_cleanup_waits_for_the_scan() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        let id = completed_id(state.finish_scan(Ok(report(false))));
        let view = plan(&state, id, SystemTime::now()).unwrap();
        state.begin_scan().unwrap();
        assert!(
            state
                .begin_clean(view.plan_id)
                .unwrap_err()
                .contains("scan is already running")
        );
        state.finish_clean();
        assert!(state.begin_scan().is_err(), "the scan still holds the slot");
    }

    /// A view of a quarantine folder that doesn't exist: empty.
    fn empty_quarantine() -> QuarantineView {
        let nowhere = std::env::temp_dir().join("openjanitor-tests-no-such-quarantine");
        QuarantineView::load(&oj_safety::Store::new(nowhere)).unwrap()
    }

    #[test]
    fn quarantine_actions_need_the_current_view() {
        let state = AppState::default();
        assert!(
            state
                .quarantine_items(1, &HashMap::new())
                .unwrap_err()
                .contains("Open it again")
        );
        let first = state.show_quarantine(empty_quarantine(), Mode::DryRun);
        assert!(first.batches.is_empty());
        assert_eq!(first.summary.held.files, 0);
        let second = state.show_quarantine(empty_quarantine(), Mode::DryRun);
        assert_ne!(first.view_id, second.view_id);

        assert!(
            state
                .quarantine_items(first.view_id, &HashMap::new())
                .is_err()
        );
        assert!(
            state
                .quarantine_items(second.view_id, &HashMap::new())
                .unwrap()
                .is_empty()
        );
        assert!(state.quarantine_children(second.view_id, 0, 0, 10).is_err());
    }

    #[test]
    fn a_quarantine_action_holds_the_slot_and_ends_the_view() {
        let state = AppState::default();
        let view = state.show_quarantine(empty_quarantine(), Mode::DryRun);

        state.begin_quarantine().unwrap();
        assert!(
            state
                .begin_scan()
                .unwrap_err()
                .contains("quarantine is busy")
        );
        assert!(state.begin_quarantine().is_err());
        assert!(
            state
                .quarantine_items(view.view_id, &HashMap::new())
                .is_err()
        );
        state.finish_clean();
        assert!(state.begin_scan().is_err(), "only its own finish frees it");
        state.finish_quarantine();
        assert!(state.begin_scan().is_ok());
        assert!(
            state
                .begin_quarantine()
                .unwrap_err()
                .contains("scan is already running")
        );
    }

    #[test]
    fn the_startup_note_shows_up_with_the_quarantine() {
        let state = AppState::default();
        state.set_expired(ExpiredNote {
            at: 42,
            report: QuarantineReport {
                mode: Mode::Live,
                done: oj_core::Tally {
                    files: 3,
                    size: 300,
                },
                skipped: Vec::new(),
                history_error: None,
            },
        });
        let overview = state.show_quarantine(empty_quarantine(), Mode::Live);
        assert_eq!(overview.expired.unwrap().report.done.files, 3);
    }

    #[test]
    fn history_files_need_the_current_view() {
        let state = AppState::default();
        assert!(
            state
                .history_files(1, 0, 0, 10)
                .unwrap_err()
                .contains("Open it again")
        );
        let text =
            r#"{"type":"cleanup","cleanup":1000,"mode":"live","deleted":{"files":1,"size":10}}"#;
        let first = state.show_history(HistoryView::from_text(text));
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.totals.freed, 10);
        assert_eq!(first.detail_days, DETAIL_DAYS);
        let second = state.show_history(HistoryView::from_text(text));

        assert!(state.history_files(first.view_id, 0, 0, 10).is_err());
        assert_eq!(
            state.history_files(second.view_id, 0, 0, 10).unwrap().total,
            0
        );
        assert!(
            state
                .history_files(second.view_id, 5, 0, 10)
                .unwrap_err()
                .contains("no entry 5")
        );
    }

    #[test]
    fn a_failed_scan_frees_the_slot() {
        let state = AppState::default();
        state.begin_scan().unwrap();
        assert_eq!(
            state.finish_scan(Err("no rules".into())).unwrap_err(),
            "no rules"
        );
        assert!(state.begin_scan().is_ok());
    }
}
