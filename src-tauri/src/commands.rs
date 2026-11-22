//! Commands the UI can call. Each one is a narrow, read-only entry point into
//! the core crates (PLANNING.md §5.2).

use std::fs;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use oj_core::{
    CancelToken, ChildPage, EnvVars, Level, NodeId, RuleSet, ScanOptions, ScanProgress, ScanReport,
    Scanner,
};
use oj_safety::{DenyList, SystemPaths};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use crate::state::{AppState, ScanOutcome};

/// Progress goes to the UI at most this often, and whenever a rule starts.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Runs a read-only scan of the bundled rules, sending progress on
/// `on_progress`. Never deletes or moves anything.
#[tauri::command]
pub async fn scan(
    app: AppHandle,
    level: Level,
    on_progress: Channel<ScanProgress>,
) -> Result<ScanOutcome, String> {
    let cancel = app.state::<AppState>().begin_scan()?;
    let worker = app.clone();
    // Walking folders blocks, so keep it off the UI's async runtime.
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let result = run_scan(level, &cancel, &on_progress);
        worker.state::<AppState>().finish_scan(result)
    })
    .await;
    joined.unwrap_or_else(|error| {
        app.state::<AppState>()
            .finish_scan(Err(format!("The scan stopped unexpectedly: {error}")))
    })
}

/// Stops the running scan, if any. The scan then returns `cancelled`.
#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.cancel_scan();
}

/// One page of a results tree node's children.
#[tauri::command]
pub fn scan_children(
    state: State<'_, AppState>,
    scan_id: u64,
    node_id: NodeId,
    offset: usize,
    limit: usize,
) -> Result<ChildPage, String> {
    state.children(scan_id, node_id, offset, limit)
}

/// Shows a location, folder, or file from the scan results in File
/// Explorer: folders open, files are highlighted in their folder. The path
/// comes from the results, never from the UI.
#[tauri::command]
pub fn reveal_in_explorer(
    state: State<'_, AppState>,
    scan_id: u64,
    node_id: NodeId,
) -> Result<(), String> {
    let path = state.node_path(scan_id, node_id)?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "This item no longer exists.".to_string())?;
    let windows = SystemPaths::discover().map_err(|e| e.to_string())?.windows;

    // Explorer treats commas as separators, so the path is always quoted.
    // Rust only quotes arguments with spaces, so pass it raw. Windows paths
    // can't contain quotes.
    let quoted = format!("\"{}\"", path.display());
    let argument = if metadata.is_dir() {
        quoted
    } else {
        format!("/select,{quoted}")
    };
    Command::new(windows.join("explorer.exe"))
        .raw_arg(argument)
        .spawn()
        .map_err(|e| format!("Couldn't open File Explorer: {e}"))?;
    Ok(())
}

fn run_scan(
    level: Level,
    cancel: &CancelToken,
    channel: &Channel<ScanProgress>,
) -> Result<ScanReport, String> {
    let rules = RuleSet::bundled().map_err(|e| e.to_string())?;
    let system = SystemPaths::discover().map_err(|e| e.to_string())?;
    let deny = DenyList::new(&system).map_err(|e| e.to_string())?;
    let protected = crate::protected::load(&system.protected_list_path())?;
    let scanner = Scanner {
        rules: &rules,
        vars: &EnvVars,
        deny: &deny,
        protected: &protected,
    };

    let mut last_sent: Option<(usize, Instant)> = None;
    let mut on_progress = |progress: &ScanProgress| {
        let due = last_sent.is_none_or(|(rule, at)| {
            rule != progress.rule_index || at.elapsed() >= PROGRESS_INTERVAL
        });
        if due {
            // Progress is best effort: a closed window just stops listening.
            let _ = channel.send(progress.clone());
            last_sent = Some((progress.rule_index, Instant::now()));
        }
    };
    Ok(scanner.scan_with(&ScanOptions::new(level), cancel, &mut on_progress))
}
