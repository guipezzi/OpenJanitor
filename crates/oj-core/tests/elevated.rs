//! The elevated helper's checks and loop (D34), in-process on a fake
//! machine. Starting the real helper needs a UAC prompt, so the app's
//! own tests can't; everything it does once started is tested here.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use common::{FakeMachine, new_file, old_file};
use oj_core::elevated::{elevated_rule, serve};
use oj_core::{
    CancelToken, Checker, ElevatedItem, ElevatedRequest, Finding, HelperMessage, PROTOCOL_VERSION,
    RuleSet, ScanResults,
};
use oj_safety::{DenyList, Entry, EntryKind, Executor, Mode, Outcome, ProtectedList, SkipReason};

fn bundled() -> RuleSet {
    RuleSet::bundled().unwrap()
}

/// What the scan found, as items for the helper.
fn found(m: &FakeMachine) -> Vec<ElevatedItem> {
    let report = m.scan(&bundled());
    let mut items: Vec<ElevatedItem> = report
        .findings
        .iter()
        .filter(|f: &&Finding| f.needs_admin)
        .filter_map(ElevatedItem::from_finding)
        .collect();
    items.sort_by(|a, b| a.path.cmp(&b.path));
    items
}

fn check(
    m: &FakeMachine,
    item: &ElevatedItem,
    protected: &ProtectedList,
    floor: Duration,
) -> Result<PathBuf, SkipReason> {
    let rules = bundled();
    let checker = Checker::new(&rules, &m.vars, protected, floor, SystemTime::now());
    checker.check(item).map(|snapshot| snapshot.path)
}

fn ok(m: &FakeMachine, item: &ElevatedItem) -> Result<PathBuf, SkipReason> {
    check(m, item, &ProtectedList::new(), Duration::ZERO)
}

#[test]
fn every_bundled_admin_rule_only_looks_in_machine_wide_folders() {
    let rules = bundled();
    let admin: Vec<&str> = rules
        .iter()
        .filter(|c| c.rule.needs_admin)
        .map(|c| c.rule.id.as_str())
        .collect();
    assert!(admin.len() >= 4, "{admin:?}");
    for compiled in rules.iter().filter(|c| c.rule.needs_admin) {
        assert!(elevated_rule(compiled), "{}", compiled.rule.id);
    }
    for compiled in rules.iter().filter(|c| !c.rule.needs_admin) {
        assert!(!elevated_rule(compiled), "{}", compiled.rule.id);
    }
}

#[test]
fn a_file_its_rule_found_passes() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&temp.join("installer.log"));
    let items = found(&m);
    assert_eq!(items.len(), 1);
    assert_eq!(ok(&m, &items[0]), Ok(temp.join("installer.log")));
}

#[test]
fn anything_its_rule_wouldnt_find_is_refused() {
    let m = FakeMachine::new();
    let windows = &m.system.windows;
    old_file(&windows.join(r"Temp\installer.log"));
    old_file(&windows.join(r"Minidump\crash.dmp"));
    old_file(&windows.join(r"System32\kernel32.dll"));
    old_file(&windows.join(r"Minidump\notes.txt"));
    let items = found(&m);
    let temp_item = items
        .iter()
        .find(|i| i.rule_id == "windows.temp.system")
        .unwrap()
        .clone();
    let dump_item = items
        .iter()
        .find(|i| i.rule_id == "windows.crash-dumps.system")
        .unwrap()
        .clone();
    let refused = |item: &ElevatedItem| ok(&m, item) == Err(SkipReason::OutsideRule);

    let unknown = ElevatedItem {
        rule_id: "made.up".into(),
        ..temp_item.clone()
    };
    assert!(refused(&unknown), "a rule that doesn't exist");

    let not_admin = ElevatedItem {
        rule_id: "windows.temp.user".into(),
        ..temp_item.clone()
    };
    assert!(
        refused(&not_admin),
        "a rule that doesn't need administrator rights"
    );

    let elsewhere = ElevatedItem {
        path: windows.join(r"System32\kernel32.dll"),
        ..temp_item.clone()
    };
    assert!(refused(&elsewhere), "a path outside the rule's location");

    let forged_root = ElevatedItem {
        root: windows.join("System32"),
        path: windows.join(r"System32\kernel32.dll"),
        ..temp_item.clone()
    };
    assert!(refused(&forged_root), "a location the rule doesn't have");

    let wrong_pattern = ElevatedItem {
        path: windows.join(r"Minidump\notes.txt"),
        ..dump_item.clone()
    };
    assert!(
        refused(&wrong_pattern),
        "a file the rule's patterns don't match"
    );

    let traversal = ElevatedItem {
        path: PathBuf::from(format!(
            "{}\\..\\System32\\kernel32.dll",
            temp_item.root.display()
        )),
        ..temp_item.clone()
    };
    assert!(refused(&traversal), "'..' never gets out");

    let bad_id = ElevatedItem {
        file_id: "nope".into(),
        ..temp_item.clone()
    };
    assert!(refused(&bad_id));
}

#[test]
fn new_files_and_the_users_longer_minimum_age_are_respected() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&temp.join("old.log"));
    let mut item = found(&m).remove(0);

    // The user asked for 30 days; the file is 3 days old.
    let thirty = Duration::from_secs(30 * 24 * 60 * 60);
    assert_eq!(
        check(&m, &item, &ProtectedList::new(), thirty),
        Err(SkipReason::OutsideRule)
    );

    // A request claiming an old time for a new file: the age is checked on
    // what's claimed, and the executor then finds the real time differs.
    new_file(&temp.join("new.log"));
    item.path = temp.join("new.log");
    item.modified_secs = 0;
    item.modified_nanos = 0;
    let rules = bundled();
    let protected = ProtectedList::new();
    let checker = Checker::new(
        &rules,
        &m.vars,
        &protected,
        Duration::ZERO,
        SystemTime::now(),
    );
    let snapshot = checker.check(&item).unwrap();
    let deny = DenyList::new(&m.system).unwrap();
    let outcome = Executor::new(Mode::Live, &deny).delete_file(&snapshot);
    assert_eq!(
        outcome,
        Outcome::Skipped {
            reason: SkipReason::Changed
        }
    );
    assert!(temp.join("new.log").exists());
}

#[test]
fn the_users_protected_list_is_respected() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&temp.join("keep.log"));
    let item = found(&m).remove(0);
    let protected = ProtectedList::from_entries(vec![Entry {
        kind: EntryKind::File,
        value: temp.join("keep.log").to_string_lossy().into_owned(),
        label: None,
        added_at: 0,
    }])
    .unwrap();
    assert_eq!(
        check(&m, &item, &protected, Duration::ZERO),
        Err(SkipReason::Protected)
    );
}

fn request(items: Vec<ElevatedItem>) -> ElevatedRequest {
    ElevatedRequest {
        version: PROTOCOL_VERSION,
        mode: Mode::Live,
        min_age_floor_secs: 0,
        protected: Vec::new(),
        items,
    }
}

fn serve_all(
    m: &FakeMachine,
    request: &ElevatedRequest,
    cancel: &CancelToken,
) -> Vec<HelperMessage> {
    let rules = bundled();
    let protected = ProtectedList::new();
    let checker = Checker::new(
        &rules,
        &m.vars,
        &protected,
        Duration::ZERO,
        SystemTime::now(),
    );
    let deny = DenyList::new(&m.system).unwrap();
    let executor = Executor::new(Mode::Live, &deny);
    let mut messages = Vec::new();
    serve(request, &checker, &executor, cancel, &mut |message| {
        messages.push(message)
    });
    messages
}

#[test]
fn the_helper_deletes_what_passes_and_tidies_up() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&temp.join(r"setup\one.log"));
    old_file(&temp.join("two.log"));
    let mut items = found(&m);
    let forged = ElevatedItem {
        path: m.system.windows.join(r"System32\kernel32.dll"),
        ..items[0].clone()
    };
    items.push(forged);

    let messages = serve_all(&m, &request(items), &CancelToken::new());

    assert!(!temp.join(r"setup\one.log").exists());
    assert!(!temp.join("two.log").exists());
    assert!(!temp.join("setup").exists(), "its emptied folder went too");
    assert!(temp.exists(), "never the rule's location itself");
    let outcomes: Vec<(usize, bool)> = messages
        .iter()
        .filter_map(|message| match message {
            HelperMessage::Outcome { index, outcome } => {
                Some((*index, matches!(outcome, Outcome::Deleted { .. })))
            }
            _ => None,
        })
        .collect();
    assert_eq!(outcomes, [(0, true), (1, true), (2, false)]);
    assert!(messages.contains(&HelperMessage::FolderRemoved {
        path: temp.join("setup")
    }));
    assert_eq!(messages.last(), Some(&HelperMessage::Done));
}

#[test]
fn the_helper_stops_when_asked_and_refuses_other_versions() {
    let m = FakeMachine::new();
    old_file(&m.system.windows.join(r"Temp\one.log"));
    let items = found(&m);

    let cancel = CancelToken::new();
    cancel.cancel();
    let messages = serve_all(&m, &request(items.clone()), &cancel);
    assert_eq!(messages, [HelperMessage::Done]);
    assert!(m.system.windows.join(r"Temp\one.log").exists());

    let newer = ElevatedRequest {
        version: PROTOCOL_VERSION + 1,
        ..request(items)
    };
    let messages = serve_all(&m, &newer, &CancelToken::new());
    assert!(
        matches!(messages[..], [HelperMessage::Refused { .. }]),
        "{messages:?}"
    );
    assert!(m.system.windows.join(r"Temp\one.log").exists());
}

#[test]
fn requests_and_messages_survive_the_trip() {
    let m = FakeMachine::new();
    old_file(&m.system.windows.join(r"Temp\one.log"));
    let request = request(found(&m));
    let line = serde_json::to_string(&request).unwrap();
    assert!(!line.contains('\n'), "one request, one line");
    assert_eq!(
        serde_json::from_str::<ElevatedRequest>(&line).unwrap(),
        request
    );

    let message = HelperMessage::Outcome {
        index: 3,
        outcome: Outcome::Skipped {
            reason: SkipReason::OutsideRule,
        },
    };
    let line = serde_json::to_string(&message).unwrap();
    assert_eq!(
        serde_json::from_str::<HelperMessage>(&line).unwrap(),
        message
    );
}

// ----- Scanning with administrator rights (D35) -----

fn scan_request() -> oj_core::ScanRequest {
    oj_core::ScanRequest {
        version: PROTOCOL_VERSION,
        level: oj_core::Level::Simple,
        drives: Vec::new(),
        min_age_floor_secs: 0,
        protected: Vec::new(),
    }
}

/// The drive the fake machine is on.
fn drive(m: &FakeMachine) -> char {
    m.root
        .to_str()
        .unwrap()
        .chars()
        .next()
        .unwrap()
        .to_ascii_uppercase()
}

fn helper_scan(m: &FakeMachine, request: &oj_core::ScanRequest) -> Vec<HelperMessage> {
    let deny = DenyList::new(&m.system).unwrap();
    let mut messages = Vec::new();
    oj_core::elevated::scan_elevated(
        request,
        &bundled(),
        &m.vars,
        &deny,
        &CancelToken::new(),
        &mut |message| messages.push(message),
    );
    messages
}

#[test]
fn the_helper_scans_only_the_admin_rules() {
    let m = FakeMachine::new();
    old_file(&m.system.windows.join(r"Temp\setup.log"));
    old_file(&m.system.windows.join(r"Minidump\crash.dmp"));
    old_file(&m.system.local_app_data.join(r"Temp\user.tmp"));
    let request = oj_core::ScanRequest {
        drives: vec![drive(&m)],
        ..scan_request()
    };

    let messages = helper_scan(&m, &request);

    assert!(
        messages
            .iter()
            .any(|m| matches!(m, HelperMessage::ScanProgress { .. }))
    );
    assert_eq!(messages.last(), Some(&HelperMessage::Done));
    let Some(HelperMessage::Scanned { rules, files }) = messages
        .iter()
        .find(|m| matches!(m, HelperMessage::Scanned { .. }))
    else {
        panic!("{messages:?}")
    };
    assert!(
        rules.iter().all(|rule| rule.needs_admin),
        "only admin rules"
    );
    let mut found: Vec<&Path> = files.iter().map(|f| f.item.path.as_path()).collect();
    found.sort();
    let windows = &m.system.windows;
    assert_eq!(
        found,
        [
            windows.join(r"Minidump\crash.dmp"),
            windows.join(r"Temp\setup.log")
        ]
    );
}

#[test]
fn the_helpers_scan_respects_drives_protection_and_age() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&temp.join("keep.log"));
    old_file(&temp.join("three-days.log"));

    // Another drive only: nothing on this one is looked at.
    let elsewhere = oj_core::ScanRequest {
        drives: vec![if drive(&m) == 'Q' { 'R' } else { 'Q' }],
        ..scan_request()
    };
    let scanned = |messages: Vec<HelperMessage>| -> Vec<PathBuf> {
        messages
            .into_iter()
            .find_map(|m| match m {
                HelperMessage::Scanned { files, .. } => {
                    Some(files.into_iter().map(|f| f.item.path).collect())
                }
                _ => None,
            })
            .unwrap()
    };
    assert!(scanned(helper_scan(&m, &elsewhere)).is_empty());

    let careful = oj_core::ScanRequest {
        drives: vec![drive(&m)],
        min_age_floor_secs: 30 * 24 * 60 * 60,
        ..scan_request()
    };
    assert!(
        scanned(helper_scan(&m, &careful)).is_empty(),
        "too new for 30 days"
    );

    let protected = oj_core::ScanRequest {
        drives: vec![drive(&m)],
        protected: vec![Entry {
            kind: EntryKind::File,
            value: temp.join("keep.log").to_string_lossy().into_owned(),
            label: None,
            added_at: 0,
        }],
        ..scan_request()
    };
    assert_eq!(
        scanned(helper_scan(&m, &protected)),
        [temp.join("three-days.log")]
    );
}

#[test]
fn what_the_helper_found_replaces_only_the_admin_rules() {
    let m = FakeMachine::new();
    let temp = m.system.windows.join("Temp");
    old_file(&m.system.local_app_data.join(r"Temp\user.tmp"));
    old_file(&temp.join("seen.log"));
    let before = m.scan(&bundled());
    let admin_before = before.findings.iter().filter(|f| f.needs_admin).count();
    assert_eq!(admin_before, 1);

    // With admin rights, the helper finds more.
    old_file(&temp.join("hidden.log"));
    let messages = helper_scan(
        &m,
        &oj_core::ScanRequest {
            drives: vec![drive(&m)],
            ..scan_request()
        },
    );
    let Some(HelperMessage::Scanned { rules, mut files }) = messages
        .into_iter()
        .find(|m| matches!(m, HelperMessage::Scanned { .. }))
    else {
        panic!()
    };
    // A file claimed for a rule that isn't an admin rule is ignored.
    let mut stray = files[0].clone();
    stray.item.rule_id = "windows.temp.user".into();
    files.push(stray);

    let merged = oj_core::elevated::merge_elevated(&before, rules, files);

    let user: Vec<&Path> = merged
        .findings
        .iter()
        .filter(|f| f.rule_id == "windows.temp.user")
        .map(|f| f.path.as_path())
        .collect();
    assert_eq!(
        user,
        [m.system.local_app_data.join(r"Temp\user.tmp")],
        "kept as it was"
    );
    let mut admin: Vec<&Path> = merged
        .findings
        .iter()
        .filter(|f| f.rule_id == "windows.temp.system")
        .map(|f| f.path.as_path())
        .collect();
    admin.sort();
    assert_eq!(admin, [temp.join("hidden.log"), temp.join("seen.log")]);
    let ids: Vec<u64> = merged.findings.iter().map(|f| f.id).collect();
    assert_eq!(ids, (1..=merged.findings.len() as u64).collect::<Vec<_>>());
    assert_eq!(merged.findings_total, merged.findings.len() as u64);
    let rule = merged
        .rules
        .iter()
        .find(|r| r.rule_id == "windows.temp.system")
        .unwrap();
    assert_eq!(rule.findings, 2);
    assert!(
        merged
            .findings
            .iter()
            .all(|f| matches!(f.target, oj_core::Target::File(_))),
        "files the helper found can be cleaned like any other"
    );
    let results = ScanResults::new(merged);
    assert_eq!(results.categories().len(), 1);
}
