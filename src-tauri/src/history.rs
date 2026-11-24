//! History screen commands (PLANNING.md §4.8 and §7.4). Reading only; the
//! history is written by cleanups and quarantine actions, and trimmed at
//! startup (D30).

use std::time::{Duration, SystemTime};

use oj_core::{DETAIL_DAYS, HistoryFilePage, HistoryView, trim_history};
use oj_safety::SystemPaths;
use tauri::{AppHandle, Manager, State};

use crate::state::{AppState, HistoryOverview};

/// Reads the history and keeps it for `history_files`. Changes nothing.
#[tauri::command]
pub async fn history_overview(app: AppHandle) -> Result<HistoryOverview, String> {
    // The file can hold tens of thousands of lines, so read it off the
    // UI's async runtime.
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let path = SystemPaths::discover()
            .map_err(|e| e.to_string())?
            .history_path();
        let view = HistoryView::load(&path)
            .map_err(|e| format!("Couldn't read the history ({}): {e}", path.display()))?;
        Ok(app.state::<AppState>().show_history(view))
    })
    .await;
    joined.unwrap_or_else(|error| Err(format!("Reading the history stopped unexpectedly: {error}")))
}

/// One page of an entry's files.
#[tauri::command]
pub fn history_files(
    state: State<'_, AppState>,
    view_id: u64,
    entry_id: u32,
    offset: usize,
    limit: usize,
) -> Result<HistoryFilePage, String> {
    state.history_files(view_id, entry_id, offset, limit)
}

/// Drops per-file lines older than [`DETAIL_DAYS`] days, keeping every
/// totals line (D30). Runs at startup, after expired quarantine files are
/// deleted, so their lines are written first.
pub fn trim_at_startup() {
    let path = match SystemPaths::discover() {
        Ok(system) => system.history_path(),
        Err(error) => {
            eprintln!("history not trimmed: {error}");
            return;
        }
    };
    let keep = Duration::from_secs(DETAIL_DAYS * 24 * 60 * 60);
    if let Err(error) = trim_history(&path, SystemTime::now(), keep) {
        eprintln!("history not trimmed: {error}");
    }
}
