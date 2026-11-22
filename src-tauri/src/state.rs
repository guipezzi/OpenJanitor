//! What the app remembers between commands: the results of the last scan,
//! and the scan that's running, if any.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use oj_core::{
    CancelToken, ChildPage, Level, NodeId, NodeView, RuleReport, ScanReport, ScanResults,
};
use serde::Serialize;

/// The most children one request can fetch.
pub const MAX_PAGE: usize = 500;

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

#[derive(Debug)]
struct Session {
    id: u64,
    results: ScanResults,
}

#[derive(Debug, Default)]
pub struct AppState {
    last_scan_id: AtomicU64,
    running: Mutex<Option<CancelToken>>,
    session: Mutex<Option<Session>>,
}

/// A panic while a lock was held leaves plain data behind, so carry on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    /// Starts a scan: forgets the previous results and returns the token
    /// that cancels this one. Fails if a scan is already running.
    pub fn begin_scan(&self) -> Result<CancelToken, String> {
        let mut running = lock(&self.running);
        if running.is_some() {
            return Err("A scan is already running.".into());
        }
        *lock(&self.session) = None;
        let cancel = CancelToken::new();
        *running = Some(cancel.clone());
        Ok(cancel)
    }

    /// Asks the running scan, if any, to stop.
    pub fn cancel_scan(&self) {
        if let Some(cancel) = lock(&self.running).as_ref() {
            cancel.cancel();
        }
    }

    /// Records how a scan ended. Call it exactly once after each
    /// [`begin_scan`](Self::begin_scan).
    pub fn finish_scan(&self, result: Result<ScanReport, String>) -> Result<ScanOutcome, String> {
        let outcome = match result {
            Ok(report) if report.cancelled => Ok(ScanOutcome::Cancelled),
            Ok(report) => {
                let id = self.last_scan_id.fetch_add(1, Ordering::Relaxed) + 1;
                let results = ScanResults::new(report);
                let report = results.report();
                let overview = ScanOverview {
                    scan_id: id,
                    level: report.level,
                    findings_total: report.findings_total,
                    size_on_disk_total: report.size_on_disk_total,
                    rules: report.rules.clone(),
                    categories: results.categories(),
                };
                *lock(&self.session) = Some(Session { id, results });
                Ok(ScanOutcome::Completed { overview })
            }
            Err(error) => Err(error),
        };
        *lock(&self.running) = None;
        outcome
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

    fn with_results<T>(
        &self,
        scan_id: u64,
        f: impl FnOnce(&ScanResults) -> Result<T, String>,
    ) -> Result<T, String> {
        let session = lock(&self.session);
        let session = session
            .as_ref()
            .filter(|session| session.id == scan_id)
            .ok_or("These results are out of date. Scan again.")?;
        f(&session.results)
    }
}

fn no_item(node: NodeId) -> String {
    format!("There's no item {node} in these results.")
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
