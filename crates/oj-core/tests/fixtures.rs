//! One fixture test per bundled rule (PLANNING.md §5.3): a fake folder
//! layout and the findings the rule should produce.

mod common;

use std::fs;

use common::{FakeMachine, junction, new_file, old_file};
use oj_core::{RuleSet, RuleStatus};

fn bundled() -> RuleSet {
    RuleSet::bundled().unwrap()
}

#[test]
fn user_temp_finds_old_files_only() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("old.tmp"));
    old_file(&temp.join(r"setup-1234\old.log"));
    new_file(&temp.join("fresh.tmp"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp"), temp.join(r"setup-1234\old.log")]
    );
    let report = m.scan(&bundled());
    let rule = report
        .rules
        .iter()
        .find(|r| r.rule_id == "windows.temp.user")
        .unwrap();
    assert_eq!(rule.skipped_recent, 1);
    assert!(rule.size_on_disk > 0);
}

#[test]
fn user_temp_never_follows_junctions() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    let elsewhere = m.root.join("elsewhere");
    old_file(&temp.join("old.tmp"));
    old_file(&elsewhere.join("important.docx"));
    junction(&temp.join("link"), &elsewhere);

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp")]
    );
}

#[test]
fn user_temp_never_reports_protected_files() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("old.tmp"));
    old_file(&temp.join(r".ssh\id_ed25519"));
    old_file(&temp.join(r"profile\Cookies"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp")]
    );
}

#[test]
fn hard_linked_files_count_as_freeing_nothing() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("a.bin"));
    fs::hard_link(temp.join("a.bin"), m.root.join("kept-copy.bin")).unwrap();

    let report = m.scan(&bundled());
    let finding = report
        .findings
        .iter()
        .find(|f| f.path == temp.join("a.bin"))
        .unwrap();
    assert_eq!(finding.size_on_disk, 0);
    assert!(finding.evidence.iter().any(|e| e.contains("hard links")));
}

#[test]
fn system_temp_finds_files_inside_windows_temp_only() {
    let m = FakeMachine::new();
    let windows = &m.system.windows;
    old_file(&windows.join(r"Temp\installer.log"));
    old_file(&windows.join(r"System32\kernel32.dll"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.system"),
        vec![windows.join(r"Temp\installer.log")]
    );
}

#[test]
fn crash_dumps_finds_dmp_files_only() {
    let m = FakeMachine::new();
    let dumps = m.system.local_app_data.join("CrashDumps");
    old_file(&dumps.join("app.exe.1234.dmp"));
    old_file(&dumps.join("notes.txt"));

    assert_eq!(
        m.found(&bundled(), "windows.crash-dumps.user"),
        vec![dumps.join("app.exe.1234.dmp")]
    );
}

#[test]
fn thumbnail_cache_finds_cache_databases_only() {
    let m = FakeMachine::new();
    let explorer = m.system.local_app_data.join(r"Microsoft\Windows\Explorer");
    old_file(&explorer.join("thumbcache_256.db"));
    old_file(&explorer.join("iconcache_32.db"));
    old_file(&explorer.join("ExplorerStartupLog.etl"));
    old_file(&explorer.join(r"sub\thumbcache_96.db"));

    assert_eq!(
        m.found(&bundled(), "windows.thumbnail-cache"),
        vec![
            explorer.join("iconcache_32.db"),
            explorer.join("thumbcache_256.db"),
        ]
    );
}

#[test]
fn missing_locations_are_reported_not_failed() {
    let m = FakeMachine::new();
    let report = m.scan(&bundled());
    for rule in &report.rules {
        assert_eq!(rule.status, RuleStatus::NoLocations, "{}", rule.rule_id);
        assert_eq!(rule.findings, 0);
    }
}
