//! Commands the UI can call. Each one is a narrow, read-only entry point into
//! the core crates (PLANNING.md §5.2).

use oj_core::{EnvVars, Level, RuleReport, RuleSet, ScanOptions, Scanner};
use oj_safety::{DenyList, SystemPaths};
use serde::Serialize;

/// What the UI shows after a scan: totals and one line per rule. Individual
/// findings stay on the Rust side until the results tree exists (phase 1).
#[derive(Debug, Serialize)]
pub struct ScanSummary {
    level: Level,
    findings_total: u64,
    size_on_disk_total: u64,
    rules: Vec<RuleReport>,
}

/// Runs a read-only scan of the bundled rules. Never deletes or moves anything.
#[tauri::command]
pub async fn scan(level: Level) -> Result<ScanSummary, String> {
    // Walking folders blocks, so keep it off the UI's async runtime.
    tauri::async_runtime::spawn_blocking(move || run_scan(level))
        .await
        .map_err(|e| format!("the scan stopped unexpectedly: {e}"))?
}

fn run_scan(level: Level) -> Result<ScanSummary, String> {
    let rules = RuleSet::bundled().map_err(|e| e.to_string())?;
    let system = SystemPaths::discover().map_err(|e| e.to_string())?;
    let deny = DenyList::new(&system).map_err(|e| e.to_string())?;
    let scanner = Scanner {
        rules: &rules,
        vars: &EnvVars,
        deny: &deny,
    };
    let report = scanner.scan(&ScanOptions::new(level));
    Ok(ScanSummary {
        level: report.level,
        findings_total: report.findings_total,
        size_on_disk_total: report.size_on_disk_total,
        rules: report.rules,
    })
}
