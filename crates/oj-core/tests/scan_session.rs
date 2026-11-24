//! Progress, cancellation, and the results tree on a fake machine.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{FakeMachine, old_file, set_age};
use oj_core::{CancelToken, Level, NodeKind, RuleSet, ScanOptions, ScanProgress, ScanResults};

const DAY: u64 = 24 * 60 * 60;

fn bundled() -> RuleSet {
    RuleSet::bundled().unwrap()
}

/// A fake machine with old files in the user's temp folder.
fn machine_with_temp_files(count: usize) -> FakeMachine {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    for i in 0..count {
        old_file(&temp.join(format!(r"batch\file-{i}.tmp")));
    }
    m
}

#[test]
fn progress_names_each_rule_in_order() {
    let m = machine_with_temp_files(3);
    let rules = bundled();
    let mut seen: Vec<ScanProgress> = Vec::new();

    let report = m.scan_with(&rules, &CancelToken::new(), &mut |p| seen.push(p.clone()));

    assert!(!report.cancelled);
    // Every rule announces itself when it starts, in rule order.
    let mut order: Vec<&str> = Vec::new();
    for progress in &seen {
        if order.last() != Some(&progress.rule_id.as_str()) {
            order.push(&progress.rule_id);
        }
    }
    let expected: Vec<&str> = rules.iter().map(|r| r.rule.id.as_str()).collect();
    assert_eq!(order, expected);
    assert!(seen.iter().all(|p| p.rule_count == rules.len()));
}

#[test]
fn progress_counts_files_along_the_way() {
    let m = machine_with_temp_files(600);
    let mut seen: Vec<ScanProgress> = Vec::new();

    let report = m.scan_with(&bundled(), &CancelToken::new(), &mut |p| {
        seen.push(p.clone())
    });

    assert_eq!(report.findings_total, 600);
    let during_walk: Vec<u64> = seen
        .iter()
        .filter(|p| p.rule_id == "windows.temp.user")
        .map(|p| p.files_checked)
        .collect();
    assert!(
        during_walk.len() >= 3,
        "a start event plus one every 256 files, got {during_walk:?}"
    );
    assert!(during_walk.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn a_cancelled_scan_stops_and_says_so() {
    let m = machine_with_temp_files(600);
    let cancel = CancelToken::new();

    let report = m.scan_with(&bundled(), &cancel, &mut |p| {
        if p.files_checked >= 256 {
            cancel.cancel();
        }
    });

    assert!(report.cancelled);
    assert!(
        report.findings_total < 600,
        "stopped early: {}",
        report.findings_total
    );
}

#[test]
fn a_scan_cancelled_before_it_starts_finds_nothing() {
    let m = machine_with_temp_files(3);
    let cancel = CancelToken::new();
    cancel.cancel();

    let report = m.scan_with(&bundled(), &cancel, &mut |_| {});

    assert!(report.cancelled);
    assert!(report.rules.is_empty());
    assert_eq!(report.findings_total, 0);
}

#[test]
fn protected_files_and_rules_are_left_out_of_the_scan() {
    use oj_core::RuleStatus;
    use oj_safety::{Entry, EntryKind, ProtectedList};

    let m = machine_with_temp_files(3);
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join(r"keep\notes.log"));
    old_file(&temp.join("artwork.psd"));
    old_file(&m.system.local_app_data.join(r"CrashDumps\app.dmp"));
    let entry = |kind, value: String| Entry {
        kind,
        value,
        label: None,
        added_at: 0,
    };
    let protected = ProtectedList::from_entries(vec![
        entry(
            EntryKind::Folder,
            temp.join("keep").to_string_lossy().into_owned(),
        ),
        entry(EntryKind::Pattern, "*.psd".into()),
        entry(EntryKind::Rule, "windows.crash-dumps.user".into()),
    ])
    .unwrap();

    let report = m.scan_protected(&bundled(), &protected);

    let temp_rule = report
        .rules
        .iter()
        .find(|r| r.rule_id == "windows.temp.user")
        .unwrap();
    assert_eq!(temp_rule.findings, 3, "only the batch files");
    assert_eq!(temp_rule.skipped_user_protected, 2);
    let dumps = report
        .rules
        .iter()
        .find(|r| r.rule_id == "windows.crash-dumps.user")
        .unwrap();
    assert_eq!(dumps.status, RuleStatus::Protected);
    assert!(
        report
            .findings
            .iter()
            .all(|f| !f.path.starts_with(temp.join("keep"))
                && f.path.extension().is_none_or(|e| e != "psd"))
    );
}

#[test]
fn the_minimum_age_setting_never_shortens_a_rules_own_wait() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    let logs = m.system.windows.join(r"Logs\CBS");
    let aged = |path: PathBuf, days: u64| {
        old_file(&path);
        set_age(&path, Duration::from_secs(days * DAY));
        path
    };
    let temp_2d = aged(temp.join("two-days.tmp"), 2);
    let temp_8d = aged(temp.join("eight-days.tmp"), 8);
    let log_8d = aged(logs.join("CbsPersist_1.log"), 8);
    let log_40d = aged(logs.join("CbsPersist_2.log"), 40);

    let found = |floor_days: u64| {
        let mut options = ScanOptions::new(Level::Advanced);
        options.min_age_floor = Some(Duration::from_secs(floor_days * DAY));
        let mut paths: Vec<PathBuf> = m
            .scan_options(&bundled(), &options)
            .findings
            .into_iter()
            .map(|finding| finding.path)
            .collect();
        paths.sort();
        paths
    };
    let sorted = |mut paths: Vec<PathBuf>| {
        paths.sort();
        paths
    };

    // 1 day: each rule's own wait (24 hours for temp, 30 days for logs).
    assert_eq!(
        found(1),
        sorted(vec![temp_2d.clone(), temp_8d.clone(), log_40d.clone()])
    );
    // 7 days: temp files wait longer; logs keep their 30 days.
    assert_eq!(found(7), sorted(vec![temp_8d, log_40d.clone()]));
    assert!(!found(7).contains(&log_8d));
    // 30 days: everything waits 30 days.
    assert_eq!(found(30), vec![log_40d]);
}

#[test]
fn results_tree_reaches_every_finding() {
    let m = machine_with_temp_files(5);
    let temp = m.system.local_app_data.join("Temp");
    let report = m.scan(&bundled());
    let total = report.findings_total;
    let results = ScanResults::new(report);

    let categories = results.categories();
    let temp_files = categories
        .iter()
        .find(|c| c.name == "temporary-files")
        .expect("temporary files category");
    let rule = &temp_files.children.as_ref().unwrap()[0];
    assert_eq!(rule.rule_id.as_deref(), Some("windows.temp.user"));
    assert_eq!(rule.file_count, 5);

    let folders = results.children(rule.id, 0, 10).unwrap();
    assert_eq!(folders.total, 1);
    assert_eq!(folders.items[0].kind, NodeKind::Folder);
    assert_eq!(
        folders.items[0].path.as_deref(),
        Some(temp.join("batch").to_string_lossy().as_ref())
    );

    let reachable: usize = categories
        .iter()
        .map(|c| results.findings_under(c.id).len())
        .sum();
    assert_eq!(reachable as u64, total);
}
