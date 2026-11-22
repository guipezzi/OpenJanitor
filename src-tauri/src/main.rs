//! OpenJanitor desktop app (PLANNING.md §5).
//!
//! The window runs the React UI from `ui/`. The commands here scan, manage
//! the Protected list, and clean what the user confirmed. Nothing here
//! deletes or moves a file itself: that's `oj-safety`'s job.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod clean;
mod commands;
mod protected;
mod state;

fn main() {
    tauri::Builder::default()
        .manage(state::AppState::default())
        .setup(|_app| {
            // Before the window can ask for anything.
            clean::recover_quarantine();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan,
            commands::cancel_scan,
            commands::scan_children,
            commands::reveal_in_explorer,
            protected::protected_entries,
            protected::protect_item,
            protected::protect_pattern,
            protected::unprotect,
            protected::export_protected,
            protected::import_protected,
            clean::plan_clean,
            clean::run_clean,
            clean::cancel_clean,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start OpenJanitor");
}
