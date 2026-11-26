//! Commands for the drive selector (PLANNING.md §7.9 and D33).
//!
//! The choice is saved in the settings, by volume ID. Scans read it each
//! time, and a cleanup refuses results scanned with another choice.

use oj_core::Settings;
use oj_core::drives::{self, Drive};
use oj_safety::SystemPaths;
use serde::Serialize;
use tauri::State;

use crate::state::AppState;

/// More choices than this can't come from someone ticking drives.
const MAX_CHOICES: usize = 64;

/// What the drive selector shows.
#[derive(Debug, Serialize)]
pub struct DrivesOverview {
    /// By letter, with the selected ones marked.
    drives: Vec<Drive>,
}

/// The drives on this machine, with the user's choice marked.
fn current(settings: &Settings) -> Result<Vec<Drive>, String> {
    let system = SystemPaths::discover().map_err(|e| e.to_string())?;
    let letter = system
        .windows
        .to_str()
        .and_then(|path| path.chars().next())
        .filter(char::is_ascii_alphabetic)
        .ok_or("Couldn't tell which drive Windows is on.")?;
    let mut list = drives::detect(letter);
    drives::select(&mut list, &settings.drives);
    Ok(list)
}

/// The drive letters a scan covers: the user's choice, or the system drive.
pub fn selected_letters(settings: &Settings) -> Result<Vec<char>, String> {
    let letters = drives::selected_letters(&current(settings)?);
    if letters.is_empty() {
        return Err("Couldn't find a drive to scan.".into());
    }
    Ok(letters)
}

/// The drives, and which are selected.
#[tauri::command]
pub fn drives_overview(state: State<'_, AppState>) -> Result<DrivesOverview, String> {
    let _guard = state.settings_file();
    let settings = crate::settings::load()?;
    Ok(DrivesOverview {
        drives: current(&settings)?,
    })
}

/// Saves which drives to scan (`ids`: volume IDs of drives here). Drives
/// that aren't connected keep their choice. If the selection changes, the
/// current results are forgotten: they'd no longer match it.
#[tauri::command]
pub fn select_drives(
    state: State<'_, AppState>,
    ids: Vec<String>,
) -> Result<DrivesOverview, String> {
    if ids.len() > MAX_CHOICES {
        return Err("That's more drives than this computer has.".into());
    }
    let _guard = state.settings_file();
    let mut settings = crate::settings::load()?;
    let mut list = current(&settings)?;
    let before = drives::selected_letters(&list);
    settings.drives = drives::remember(&list, &settings.drives, &ids)?;
    drives::select(&mut list, &settings.drives);
    if drives::selected_letters(&list) != before {
        // Refused while a scan or cleanup runs, before anything is saved.
        state.forget_results()?;
    }
    crate::settings::save(&settings)?;
    Ok(DrivesOverview { drives: list })
}
