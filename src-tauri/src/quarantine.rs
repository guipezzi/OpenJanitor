//! Quarantine screen commands (PLANNING.md §4.5 and §7.3).
//!
//! The screen loads a view of the personal quarantine and refers to files
//! by node id from that view, never by path. Restores and deletes go
//! through `oj-safety`, which checks each stored file again first, and
//! every one is written to the history.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use oj_core::{
    ChildPage, Conflicts, History, ItemRef, NodeId, QuarantineKeeper, QuarantineReport,
    QuarantineView, restore_conflicts,
};
use oj_safety::{DenyList, Executor, IfExists, Mode, Store, SystemPaths};
use tauri::{AppHandle, Manager, State};

use crate::state::{AppState, ExpiredNote, QuarantineOverview};

/// More choices than this can't come from someone clicking through a tree.
const MAX_CHOICES: usize = 100_000;

/// Reads the quarantine and keeps the view for the commands below.
/// Changes nothing.
#[tauri::command]
pub fn quarantine_overview(state: State<'_, AppState>) -> Result<QuarantineOverview, String> {
    let store = personal_store()?;
    let view = QuarantineView::load(&store).map_err(|e| {
        format!(
            "Couldn't read the quarantine ({}): {e}",
            store.root().display()
        )
    })?;
    Ok(state.show_quarantine(view, Mode::from_env()))
}

/// One page of a quarantine node's children.
#[tauri::command]
pub fn quarantine_children(
    state: State<'_, AppState>,
    view_id: u64,
    node_id: NodeId,
    offset: usize,
    limit: usize,
) -> Result<ChildPage, String> {
    state.quarantine_children(view_id, node_id, offset, limit)
}

/// Which selected files would land where something already is. Changes
/// nothing.
#[tauri::command]
pub fn quarantine_conflicts(
    state: State<'_, AppState>,
    view_id: u64,
    choices: Vec<(NodeId, bool)>,
) -> Result<Conflicts, String> {
    let items = state.quarantine_items(view_id, &to_map(choices)?)?;
    Ok(restore_conflicts(&personal_store()?, &items))
}

/// Moves the selected files back where they came from; `if_exists` says
/// what to do where something is there again.
#[tauri::command]
pub async fn restore_quarantined(
    app: AppHandle,
    view_id: u64,
    choices: Vec<(NodeId, bool)>,
    if_exists: IfExists,
) -> Result<QuarantineReport, String> {
    act(app, view_id, choices, move |keeper, items| {
        keeper.restore(items, if_exists, SystemTime::now())
    })
    .await
}

/// Deletes the selected files for good. "Empty quarantine now" selects
/// everything.
#[tauri::command]
pub async fn delete_quarantined(
    app: AppHandle,
    view_id: u64,
    choices: Vec<(NodeId, bool)>,
) -> Result<QuarantineReport, String> {
    act(app, view_id, choices, |keeper, items| keeper.delete(items)).await
}

/// Resolves the selection, then runs `action` off the UI's async runtime
/// while holding the one-operation-at-a-time slot.
async fn act(
    app: AppHandle,
    view_id: u64,
    choices: Vec<(NodeId, bool)>,
    action: impl FnOnce(&mut QuarantineKeeper, &[ItemRef]) -> QuarantineReport + Send + 'static,
) -> Result<QuarantineReport, String> {
    let choices = to_map(choices)?;
    let worker = app.clone();
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        let items = state.quarantine_items(view_id, &choices)?;
        let unchanged = "Nothing was changed.";
        let system = SystemPaths::discover().map_err(|e| format!("{e}. {unchanged}"))?;
        let deny = DenyList::new(&system).map_err(|e| format!("{e}. {unchanged}"))?;
        let mut history = History::open(&system.history_path())
            .map_err(|e| format!("Couldn't open the history file: {e}. {unchanged}"))?;
        let executor = Executor::new(Mode::from_env(), &deny);
        let store = Store::new(system.personal_quarantine());

        state.begin_quarantine()?;
        let report = action(
            &mut QuarantineKeeper {
                executor: &executor,
                store: &store,
                history: &mut history,
            },
            &items,
        );
        state.finish_quarantine();
        Ok(report)
    })
    .await;
    joined.unwrap_or_else(|error| {
        app.state::<AppState>().finish_quarantine();
        Err(format!(
            "The quarantine action stopped unexpectedly: {error}"
        ))
    })
}

/// Deletes files whose time in quarantine is up (PLANNING.md §4.5). Runs at
/// startup, after recovery and before the window can ask for anything.
/// Without a history file nothing is deleted, so every deletion is on
/// record.
pub fn delete_expired_at_startup(app: &AppHandle) {
    let run = || -> Result<Option<QuarantineReport>, String> {
        let system = SystemPaths::discover().map_err(|e| e.to_string())?;
        let store = Store::new(system.personal_quarantine());
        if store.batch_names().map_err(|e| e.to_string())?.is_empty() {
            // Nothing to do, and no reason to create the history file.
            return Ok(None);
        }
        let deny = DenyList::new(&system).map_err(|e| e.to_string())?;
        let mut history = History::open(&system.history_path()).map_err(|e| e.to_string())?;
        let executor = Executor::new(Mode::from_env(), &deny);
        QuarantineKeeper {
            executor: &executor,
            store: &store,
            history: &mut history,
        }
        .delete_expired(SystemTime::now())
        .map(Some)
        .map_err(|e| e.to_string())
    };
    match run() {
        Ok(Some(report)) if report.done.files > 0 || !report.skipped.is_empty() => {
            let at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            app.state::<AppState>()
                .set_expired(ExpiredNote { at, report });
        }
        Ok(_) => {}
        Err(error) => eprintln!("expired quarantine files left for later: {error}"),
    }
}

fn personal_store() -> Result<Store, String> {
    let system = SystemPaths::discover().map_err(|e| e.to_string())?;
    Ok(Store::new(system.personal_quarantine()))
}

fn to_map(choices: Vec<(NodeId, bool)>) -> Result<HashMap<NodeId, bool>, String> {
    if choices.len() > MAX_CHOICES {
        return Err("The selection is too large.".into());
    }
    Ok(choices.into_iter().collect())
}
