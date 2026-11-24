//! Commands for the Settings screen (PLANNING.md §7.4 and D31).
//!
//! The settings live in `settings.json` in OpenJanitor's data folder.
//! Scans and cleanups read the file each time. If it can't be read, they
//! refuse and say why: a damaged file never counts as the defaults, which
//! could be less careful than what the user chose.

use std::path::PathBuf;

use oj_core::settings::CHOICES;
use oj_core::{Settings, SettingsChoices, Theme};
use oj_safety::SystemPaths;
use serde::Serialize;
use tauri::{AppHandle, State};

use crate::state::AppState;

/// The settings for the Settings screen, or why they can't be read.
#[derive(Debug, Serialize)]
pub struct SettingsOverview {
    /// Missing when the file couldn't be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<Settings>,
    /// Why the file couldn't be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    choices: SettingsChoices,
    defaults: Settings,
}

fn path() -> Result<PathBuf, String> {
    Ok(SystemPaths::discover()
        .map_err(|e| e.to_string())?
        .settings_path())
}

fn read(path: &std::path::Path) -> Result<Settings, String> {
    Settings::load(path)
        .map_err(|e| format!("Your settings ({}) couldn't be read: {e}.", path.display()))
}

/// Loads the settings for a scan or cleanup. `refused` completes "Nothing
/// was …" when they can't be read.
pub fn load_for(refused: &str) -> Result<Settings, String> {
    read(&path()?).map_err(|error| {
        format!(
            "{error} Nothing was {refused}. Open Settings to restore the defaults, or fix that file."
        )
    })
}

/// The window's title bar follows the theme too. The UI themes itself.
fn apply_window_theme(app: &AppHandle, theme: Theme) {
    app.set_theme(match theme {
        Theme::System => None,
        Theme::Light => Some(tauri::Theme::Light),
        Theme::Dark => Some(tauri::Theme::Dark),
    });
}

/// Sets the window's theme before it shows. A damaged file leaves it
/// following Windows; scans and cleanups will say what's wrong.
pub fn apply_theme_at_startup(app: &AppHandle) {
    if let Ok(settings) = path().and_then(|path| read(&path)) {
        apply_window_theme(app, settings.theme);
    }
}

/// The settings, or why they can't be read. The window's theme follows
/// what's found: a damaged file puts it back to the system's, since an
/// earlier choice would otherwise still be forced on the window.
#[tauri::command]
pub fn settings_overview(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SettingsOverview, String> {
    let _guard = state.settings_file();
    let (settings, error) = match read(&path()?) {
        Ok(settings) => (Some(settings), None),
        Err(error) => (None, Some(error)),
    };
    apply_window_theme(
        &app,
        settings.map_or(Theme::System, |settings| settings.theme),
    );
    Ok(SettingsOverview {
        settings,
        error,
        choices: CHOICES,
        defaults: Settings::default(),
    })
}

/// Saves every setting at once. Values outside the choices are refused.
#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Settings, String> {
    let _guard = state.settings_file();
    settings
        .save(&path()?)
        .map_err(|e| format!("Couldn't save your settings: {e}"))?;
    apply_window_theme(&app, settings.theme);
    Ok(settings)
}

/// Puts every setting back to its default, replacing a damaged file too.
#[tauri::command]
pub fn reset_settings(app: AppHandle, state: State<'_, AppState>) -> Result<Settings, String> {
    save_settings(app, state, Settings::default())
}
