//! Cleaning commands (PLANNING.md §4.4, §4.5, and §7.1).
//!
//! The UI sends its selection as node ids from the last scan, never paths.
//! `plan_clean` turns it into a plan for the confirmation; `run_clean` runs
//! exactly that plan, by its id. Every file operation goes through
//! `oj-safety`, which checks each file again right before touching it.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use oj_core::{CleanProgress, CleanReport, Cleaner, History, NodeId, Policy};
use oj_safety::{DenyList, Executor, Mode, Store, SystemPaths};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use crate::state::{AppState, PlanView};

/// Progress goes to the UI at most this often.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// More choices than this can't come from someone clicking through a tree.
const MAX_CHOICES: usize = 100_000;

/// Builds the cleanup plan for a selection of scan `scan_id`'s results:
/// what will be deleted, what will be quarantined, and what's left out.
/// Changes nothing.
#[tauri::command]
pub fn plan_clean(
    state: State<'_, AppState>,
    scan_id: u64,
    choices: Vec<(NodeId, bool)>,
) -> Result<PlanView, String> {
    if choices.len() > MAX_CHOICES {
        return Err("The selection is too large.".into());
    }
    let choices: HashMap<NodeId, bool> = choices.into_iter().collect();
    state.plan_clean(
        scan_id,
        &choices,
        &Policy::default(),
        Mode::from_env(),
        SystemTime::now(),
    )
}

/// Runs cleanup plan `plan_id`, sending progress on `on_progress`.
/// Afterwards the scan results are gone: they're out of date.
#[tauri::command]
pub async fn run_clean(
    app: AppHandle,
    plan_id: u64,
    on_progress: Channel<CleanProgress>,
) -> Result<CleanReport, String> {
    let worker = app.clone();
    // Deleting files blocks, so keep it off the UI's async runtime.
    let joined =
        tauri::async_runtime::spawn_blocking(move || clean(&worker, plan_id, &on_progress)).await;
    joined.unwrap_or_else(|error| {
        app.state::<AppState>().finish_clean();
        Err(format!("The cleanup stopped unexpectedly: {error}"))
    })
}

/// Stops the running cleanup after the file it's on.
#[tauri::command]
pub fn cancel_clean(state: State<'_, AppState>) {
    state.cancel_clean();
}

fn clean(
    app: &AppHandle,
    plan_id: u64,
    channel: &Channel<CleanProgress>,
) -> Result<CleanReport, String> {
    // Everything that can fail comes before the plan is taken, so a
    // failure here leaves the results and the plan in place.
    let unchanged = "Nothing was cleaned.";
    let system = SystemPaths::discover().map_err(|e| format!("{e}. {unchanged}"))?;
    let deny = DenyList::new(&system).map_err(|e| format!("{e}. {unchanged}"))?;
    let protected = crate::protected::load(&system.protected_list_path())?;
    let mut history = History::open(&system.history_path())
        .map_err(|e| format!("Couldn't open the history file: {e}. {unchanged}"))?;
    let executor = Executor::new(Mode::from_env(), &deny).with_protected_list(protected);
    let store = Store::new(system.personal_quarantine());

    let state = app.state::<AppState>();
    let (results, plan, cancel) = state.begin_clean(plan_id)?;
    let mut last_sent: Option<Instant> = None;
    let mut on_progress = |progress: &CleanProgress| {
        let due = progress.done == progress.total
            || last_sent.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL);
        if due {
            // Progress is best effort: a closed window just stops listening.
            let _ = channel.send(progress.clone());
            last_sent = Some(Instant::now());
        }
    };
    let report = Cleaner {
        executor: &executor,
        store: &store,
        history: &mut history,
    }
    .run(
        &results,
        &plan,
        SystemTime::now(),
        &cancel,
        &mut on_progress,
    );
    state.finish_clean();
    Ok(report)
}

/// Puts the quarantine back in a consistent state after a crash or a power
/// cut, before anything else runs (PLANNING.md §4.5). It only edits
/// manifests; files stay where they are.
pub fn recover_quarantine() {
    let system = match SystemPaths::discover() {
        Ok(system) => system,
        Err(error) => {
            eprintln!("quarantine recovery skipped: {error}");
            return;
        }
    };
    match Store::new(system.personal_quarantine()).recover() {
        Ok(recovery) => {
            for (batch, item, state) in &recovery.fixed {
                eprintln!("quarantine recovery: {batch} item {item} is now {state:?}");
            }
            for (batch, error) in &recovery.unreadable {
                eprintln!("quarantine recovery: left {batch} alone: {error}");
            }
        }
        Err(error) => eprintln!("quarantine recovery failed: {error}"),
    }
}
