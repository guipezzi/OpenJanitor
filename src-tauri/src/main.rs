//! OpenJanitor desktop app (PLANNING.md §5).
//!
//! The window runs the React UI from `ui/`. In phase 0 it can only run
//! read-only scans; nothing here deletes or moves files.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod commands;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![commands::scan])
        .run(tauri::generate_context!())
        .expect("failed to start OpenJanitor");
}
