//! OpenJanitor desktop app (PLANNING.md §5).
//!
//! The window runs the React UI from `ui/`. The commands here scan, manage
//! the Protected list and the settings, and clean what the user confirmed. Nothing here
//! deletes or moves a file itself: that's `oj-safety`'s job.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod clean;
mod commands;
mod drives;
mod helper;
mod history;
mod protected;
mod quarantine;
mod settings;
mod state;

fn main() {
    tauri::Builder::default()
        .manage(state::AppState::default())
        .setup(|app| {
            // Before the window can ask for anything: put the quarantine
            // back in order, delete what has expired, then trim old
            // per-file history lines.
            clean::recover_quarantine();
            quarantine::delete_expired_at_startup(app.handle());
            history::trim_at_startup();
            settings::apply_theme_at_startup(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan,
            commands::cancel_scan,
            commands::scan_with_admin,
            commands::scan_children,
            commands::reveal_in_explorer,
            commands::open_recycle_bin,
            drives::drives_overview,
            drives::select_drives,
            protected::protected_entries,
            protected::protect_item,
            protected::protect_pattern,
            protected::unprotect,
            protected::export_protected,
            protected::import_protected,
            clean::plan_clean,
            clean::run_clean,
            clean::cancel_clean,
            quarantine::quarantine_overview,
            quarantine::quarantine_children,
            quarantine::quarantine_conflicts,
            quarantine::restore_quarantined,
            quarantine::delete_quarantined,
            history::history_overview,
            history::history_files,
            settings::settings_overview,
            settings::save_settings,
            settings::reset_settings,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start OpenJanitor");
}
