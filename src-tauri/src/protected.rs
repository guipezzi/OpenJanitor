//! Commands for the Protected list (PLANNING.md §7.2).
//!
//! The list lives in `protected.json` in OpenJanitor's data folder. Every
//! change reads it, changes it, saves it, and hides what it now covers
//! from the current results. If the file can't be read, nothing is
//! changed and the error is shown: a damaged list never counts as empty.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oj_safety::{Entry, EntryKind, ProtectedList, SystemPaths};
use serde::Serialize;
use tauri::{AppHandle, Manager, State, WebviewWindow};

use crate::state::{AppState, ScanOverview};

/// Imported files bigger than this aren't Protected lists.
const MAX_IMPORT_BYTES: u64 = 1024 * 1024;

/// The list after a change, and the results with newly protected items
/// hidden (if there are results).
#[derive(Debug, Serialize)]
pub struct ProtectedUpdate {
    entries: Vec<Entry>,
    overview: Option<ScanOverview>,
    /// How many entries the change added.
    added: usize,
}

pub fn list_path() -> Result<PathBuf, String> {
    Ok(SystemPaths::discover()
        .map_err(|e| e.to_string())?
        .protected_list_path())
}

/// Loads the list, or explains why it can't be used.
pub fn load(path: &Path) -> Result<ProtectedList, String> {
    ProtectedList::load(path).map_err(|e| {
        format!(
            "Your Protected list ({}) couldn't be read: {e}. Nothing was scanned or changed. Fix or remove that file and try again.",
            path.display()
        )
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the list, applies `change`, saves it if anything was added, and
/// hides what it covers from the current results.
fn update(
    state: &AppState,
    change: impl FnOnce(&mut ProtectedList) -> Result<usize, String>,
) -> Result<ProtectedUpdate, String> {
    let _guard = state.protected_file();
    let path = list_path()?;
    let mut list = load(&path)?;
    let added = change(&mut list)?;
    if added > 0 {
        list.save(&path)
            .map_err(|e| format!("Couldn't save your Protected list: {e}"))?;
    }
    Ok(ProtectedUpdate {
        entries: list.entries().to_vec(),
        overview: state.apply_protection(&list),
        added,
    })
}

#[tauri::command]
pub fn protected_entries(state: State<'_, AppState>) -> Result<Vec<Entry>, String> {
    let _guard = state.protected_file();
    Ok(load(&list_path()?)?.entries().to_vec())
}

/// Protects a result: its rule, its folder, or its file.
#[tauri::command]
pub fn protect_item(
    state: State<'_, AppState>,
    scan_id: u64,
    node_id: u32,
) -> Result<ProtectedUpdate, String> {
    let entry = state.protect_entry(scan_id, node_id, now())?;
    update(&state, |list| {
        list.add(entry).map(usize::from).map_err(|e| e.to_string())
    })
}

/// Protects every file whose name (`*.psd`) or full path (`D:\Projects\**`)
/// matches `pattern`.
#[tauri::command]
pub fn protect_pattern(
    state: State<'_, AppState>,
    pattern: String,
) -> Result<ProtectedUpdate, String> {
    let entry = Entry {
        kind: EntryKind::Pattern,
        value: pattern,
        label: None,
        added_at: now(),
    };
    update(&state, |list| {
        list.add(entry).map(usize::from).map_err(|e| e.to_string())
    })
}

/// Stops protecting an entry. Its items come back on the next scan.
#[tauri::command]
pub fn unprotect(
    state: State<'_, AppState>,
    kind: EntryKind,
    value: String,
) -> Result<Vec<Entry>, String> {
    let _guard = state.protected_file();
    let path = list_path()?;
    let mut list = load(&path)?;
    if list.remove(kind, &value) {
        list.save(&path)
            .map_err(|e| format!("Couldn't save your Protected list: {e}"))?;
    }
    Ok(list.entries().to_vec())
}

/// Saves a copy of the list where the user picks. `false` if they cancelled.
#[tauri::command]
pub async fn export_protected(app: AppHandle, window: WebviewWindow) -> Result<bool, String> {
    let json = {
        let state = app.state::<AppState>();
        let _guard = state.protected_file();
        load(&list_path()?)?.to_json()
    };
    let target = tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_title("Export Protected list")
            .set_file_name("openjanitor-protected.json")
            .add_filter("OpenJanitor Protected list", &["json"])
            .set_parent(&window)
            .save_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    let Some(target) = target else {
        return Ok(false);
    };
    // The save dialog already asked before replacing an existing file.
    fs::write(&target, json).map_err(|e| format!("Couldn't save {}: {e}", target.display()))?;
    Ok(true)
}

/// Adds the entries of a list file the user picks. Nothing is removed.
#[tauri::command]
pub async fn import_protected(
    app: AppHandle,
    window: WebviewWindow,
) -> Result<Option<ProtectedUpdate>, String> {
    let source = tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_title("Import Protected list")
            .add_filter("OpenJanitor Protected list", &["json"])
            .set_parent(&window)
            .pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    let Some(source) = source else {
        return Ok(None);
    };
    let size = fs::metadata(&source).map_err(|e| e.to_string())?.len();
    if size > MAX_IMPORT_BYTES {
        return Err(format!(
            "{} is too big to be a Protected list.",
            source.display()
        ));
    }
    let bytes =
        fs::read(&source).map_err(|e| format!("Couldn't read {}: {e}", source.display()))?;
    let imported = ProtectedList::from_json(&bytes).map_err(|e| {
        format!(
            "{} isn't a Protected list OpenJanitor can use: {e}",
            source.display()
        )
    })?;
    let state = app.state::<AppState>();
    update(&state, |list| Ok(list.merge(&imported))).map(Some)
}
