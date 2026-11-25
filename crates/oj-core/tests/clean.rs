//! Cleanup plans and running them, on a fake machine. Everything happens in
//! a temp folder.

mod common;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use common::{FakeMachine, new_file, old_file, write_file};
use oj_core::{
    Action, BinSkip, BinTally, CancelToken, CleanProgress, CleanReport, Cleaner, History, NodeId,
    Plan, Policy, QuarantineGroup, RuleSet, RunningPrograms, ScanResults, SkipCount,
};
use oj_safety::{DenyList, Executor, ItemState, Mode, Store};
use serde_json::Value;

/// One rule per risk level, plus one that needs admin rights.
const RULES: &str = r#"
[[rule]]
id          = "test.temp"
category    = "temporary-files"
level       = "simple"
risk        = "low"
paths       = ['%TEMP%']
name        = "Temp"
description = "Temporary files"

[[rule]]
id          = "test.logs"
category    = "logs"
level       = "simple"
risk        = "medium"
paths       = ['%LOCALAPPDATA%\Logs']
name        = "Logs"
description = "Old logs"

[[rule]]
id          = "test.leftovers"
category    = "leftovers"
level       = "simple"
risk        = "review"
paths       = ['%LOCALAPPDATA%\Leftovers']
name        = "Leftovers"
description = "Leftovers"

[[rule]]
id          = "test.system"
category    = "temporary-files"
level       = "simple"
risk        = "low"
needs_admin = true
paths       = ['%WINDIR%\Temp']
name        = "System temp"
description = "System temporary files"

[[rule]]
id          = "test.bin"
category    = "recycle-bin"
level       = "simple"
risk        = "low"
builtin     = "recycle-bin"
recommended = false
name        = "Recycle Bin"
description = "Deleted files"
"#;

struct Machine {
    m: FakeMachine,
    temp: PathBuf,
    logs: PathBuf,
    leftovers: PathBuf,
    system_temp: PathBuf,
}

/// A fake machine with something for every rule:
///
/// - `%TEMP%`: `a.tmp`, `setup\x.log`, `setup\deep\y.log`, and
///   `busy\old.tmp` next to a new file the scan leaves alone
/// - `Logs\app\old.log` (medium risk) and `Leftovers\thing.dat` (review)
/// - `%WINDIR%\Temp\sys.tmp` (needs admin rights)
/// - an empty Recycle Bin on `C:`, until a test fills it
fn machine() -> Machine {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    let logs = m.system.local_app_data.join("Logs");
    let leftovers = m.system.local_app_data.join("Leftovers");
    let system_temp = m.system.windows.join("Temp");
    for file in [
        temp.join("a.tmp"),
        temp.join(r"setup\x.log"),
        temp.join(r"setup\deep\y.log"),
        temp.join(r"busy\old.tmp"),
        logs.join(r"app\old.log"),
        leftovers.join("thing.dat"),
        system_temp.join("sys.tmp"),
    ] {
        old_file(&file);
    }
    new_file(&temp.join(r"busy\fresh.tmp"));
    Machine {
        m,
        temp,
        logs,
        leftovers,
        system_temp,
    }
}

fn scan(machine: &Machine) -> ScanResults {
    let rules = RuleSet::from_sources(&[("test.toml", RULES)]).unwrap();
    ScanResults::new(machine.m.scan(&rules))
}

/// Every category selected.
fn everything(results: &ScanResults) -> HashMap<NodeId, bool> {
    results.categories().iter().map(|c| (c.id, true)).collect()
}

fn node_named(results: &ScanResults, parent: NodeId, name: &str) -> NodeId {
    results
        .children(parent, 0, usize::MAX)
        .unwrap()
        .items
        .into_iter()
        .find(|n| n.name == name)
        .unwrap_or_else(|| panic!("no {name}"))
        .id
}

fn nothing_running() -> RunningPrograms {
    RunningPrograms::default()
}

/// Runs `plan` with no apps open and returns the report and the history
/// lines it wrote.
fn run(
    machine: &Machine,
    results: &ScanResults,
    plan: &Plan,
    executor: &Executor,
    cancel: &CancelToken,
    on_progress: &mut dyn FnMut(&CleanProgress),
) -> (CleanReport, Vec<Value>) {
    run_while(
        machine,
        results,
        plan,
        executor,
        cancel,
        on_progress,
        &nothing_running(),
    )
}

/// Runs `plan` while `running` programs are open.
fn run_while(
    machine: &Machine,
    results: &ScanResults,
    plan: &Plan,
    executor: &Executor,
    cancel: &CancelToken,
    on_progress: &mut dyn FnMut(&CleanProgress),
    running: &RunningPrograms,
) -> (CleanReport, Vec<Value>) {
    let store = Store::new(machine.m.system.personal_quarantine());
    let history_path = machine.m.system.history_path();
    let mut history = History::open(&history_path).unwrap();
    let report = Cleaner {
        executor,
        store: &store,
        history: &mut history,
        running,
    }
    .run(results, plan, SystemTime::now(), cancel, on_progress);
    let lines = fs::read_to_string(&history_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (report, lines)
}

fn deny(machine: &Machine) -> DenyList {
    DenyList::new(&machine.m.system).unwrap()
}

fn exists(paths: &[&Path]) -> Vec<bool> {
    paths.iter().map(|p| p.exists()).collect()
}

#[test]
fn a_plan_follows_the_selection_and_the_policy() {
    let machine = machine();
    let results = scan(&machine);
    let size = |files: u64| files * 8192;

    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let summary = plan.summary();
    assert_eq!(summary.delete.files, 4);
    assert!(summary.delete.size >= size(4), "{summary:?}");
    assert_eq!(
        summary
            .quarantine
            .iter()
            .map(|g| (g.days, g.files))
            .collect::<Vec<_>>(),
        [(7, 1), (30, 1)]
    );
    assert_eq!(summary.needs_admin.files, 1, "left out until the helper");
    assert_eq!(plan.len(), 6);
    assert_eq!(summary.files(), 6);

    // Unselecting a folder inside a selected rule leaves its files out.
    let temp_files = results
        .categories()
        .into_iter()
        .find(|c| c.name == "temporary-files")
        .unwrap();
    let temp_rule = temp_files
        .children
        .unwrap()
        .into_iter()
        .find(|r| r.rule_id.as_deref() == Some("test.temp"))
        .unwrap();
    let busy = node_named(&results, temp_rule.id, "busy");
    let choices = HashMap::from([(temp_rule.id, true), (busy, false)]);
    let plan = Plan::build(&results, &choices, &Policy::default(), &nothing_running());
    assert_eq!(plan.summary().delete.files, 3);
    assert!(plan.summary().quarantine.is_empty());
    assert_eq!(plan.summary().needs_admin.files, 0);

    assert!(
        Plan::build(
            &results,
            &HashMap::new(),
            &Policy::default(),
            &nothing_running()
        )
        .is_empty()
    );
}

#[test]
fn a_cleanup_deletes_quarantines_and_tidies_up() {
    let machine = machine();
    let results = scan(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny);
    let mut progress = Vec::new();

    let (report, history) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |p| progress.push(p.clone()),
    );

    let temp = &machine.temp;
    assert_eq!(
        exists(&[
            &temp.join("a.tmp"),
            &temp.join(r"setup\x.log"),
            &temp.join(r"setup\deep\y.log"),
            &temp.join(r"busy\old.tmp"),
            &machine.logs.join(r"app\old.log"),
            &machine.leftovers.join("thing.dat"),
        ]),
        [false; 6]
    );
    // Emptied folders go; rule locations and folders with new files stay.
    assert_eq!(
        exists(&[
            &temp.join("setup"),
            &machine.logs.join("app"),
            temp,
            &machine.logs,
            &machine.leftovers,
            &temp.join(r"busy\fresh.tmp"),
            &machine.system_temp.join("sys.tmp"),
        ]),
        [false, false, true, true, true, true, true]
    );

    assert_eq!(report.mode, Mode::Live);
    assert!(!report.cancelled);
    assert_eq!(report.deleted.files, 4);
    assert_eq!(report.deleted.size, plan.summary().delete.size);
    assert_eq!(
        report
            .quarantined
            .iter()
            .map(|g| (g.days, g.files))
            .collect::<Vec<_>>(),
        [(7, 1), (30, 1)]
    );
    let in_a_week = report.quarantined[0].expires_at;
    assert_eq!(
        report.quarantined[1].expires_at - in_a_week,
        23 * 24 * 60 * 60
    );
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert_eq!(report.not_started, 0);
    assert_eq!(report.folders_removed, 3, "setup\\deep, setup, and app");
    assert_eq!(report.needs_admin.files, 1);
    assert_eq!(report.history_error, None);

    // Both quarantined files are in one batch, ready to restore.
    let store = Store::new(machine.m.system.personal_quarantine());
    let batch = store.open_batch(report.batch.as_deref().unwrap()).unwrap();
    let mut items: Vec<(&Path, ItemState, &str)> = batch
        .manifest()
        .items
        .iter()
        .map(|i| (i.original_path.as_path(), i.state, i.rule_id.as_str()))
        .collect();
    items.sort_by_key(|item| item.0);
    assert_eq!(
        items,
        [
            (
                machine.leftovers.join("thing.dat").as_path(),
                ItemState::Quarantined,
                "test.leftovers"
            ),
            (
                machine.logs.join(r"app\old.log").as_path(),
                ItemState::Quarantined,
                "test.logs"
            ),
        ]
    );

    assert_eq!(progress.len(), 6);
    assert_eq!(progress.last().unwrap().done, 6);
    assert_eq!(progress.last().unwrap().freed, report.deleted.size);

    // One line per file, one per removed folder, then the totals.
    let kinds: Vec<&str> = history
        .iter()
        .map(|l| l["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|k| **k == "file").count(), 6);
    assert_eq!(kinds.iter().filter(|k| **k == "folder").count(), 3);
    assert_eq!(kinds.last(), Some(&"cleanup"));
    let cleanup = &history[0]["cleanup"];
    assert!(
        history
            .iter()
            .all(|l| &l["cleanup"] == cleanup && l["v"] == 1)
    );
    let quarantined = history
        .iter()
        .find(|l| l["rule_id"] == "test.logs")
        .unwrap();
    assert_eq!(quarantined["result"], "quarantined");
    assert_eq!(quarantined["action"]["kind"], "quarantine");
    assert_eq!(quarantined["action"]["days"], 7);
    assert_eq!(quarantined["batch"], report.batch.as_deref().unwrap());
    assert_eq!(quarantined["mode"], "live");
    let totals = history.last().unwrap();
    assert_eq!(totals["deleted"]["files"], 4);
    assert_eq!(totals["folders_removed"], 3);

    // The History screen reads it back as one entry.
    let view = oj_core::HistoryView::load(&machine.m.system.history_path()).unwrap();
    let [entry] = view.entries() else {
        panic!("one entry expected, got {:?}", view.entries());
    };
    assert_eq!(entry.kind, oj_core::EntryKind::Cleanup);
    assert_eq!(entry.files, 6);
    assert_eq!(entry.freed, report.deleted.size);
    assert_eq!(entry.quarantined.files, 2);
    assert_eq!(entry.details, 9, "6 files and 3 folders");
    assert_eq!(view.totals().freed, report.deleted.size);
    assert_eq!(view.totals().cleanups, 1);
}

#[test]
fn a_dry_run_changes_nothing() {
    let machine = machine();
    let results = scan(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let deny = deny(&machine);
    let executor = Executor::new(Mode::DryRun, &deny);

    let (report, history) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );

    assert_eq!(
        exists(&[
            &machine.temp.join("a.tmp"),
            &machine.temp.join(r"setup\deep\y.log"),
            &machine.logs.join(r"app\old.log"),
            &machine.leftovers.join("thing.dat"),
        ]),
        [true; 4]
    );
    assert!(!machine.m.system.personal_quarantine().exists());
    assert_eq!(report.mode, Mode::DryRun);
    assert_eq!(report.deleted.files, 4, "what would be deleted");
    assert_eq!(report.quarantined.len(), 2);
    assert_eq!(report.batch, None);
    assert_eq!(report.folders_removed, 0);
    let results: Vec<&str> = history
        .iter()
        .filter(|l| l["type"] == "file")
        .map(|l| l["result"].as_str().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| **r == "would_delete").count(), 4);
    assert_eq!(
        results.iter().filter(|r| **r == "would_quarantine").count(),
        2
    );
    assert!(history.iter().all(|l| l["mode"] == "dry_run"));
}

#[test]
fn files_that_changed_or_are_protected_or_in_use_are_skipped() {
    use std::os::windows::fs::OpenOptionsExt;

    let machine = machine();
    let results = scan(&machine);
    let temp = &machine.temp;
    let choices: HashMap<NodeId, bool> = results
        .categories()
        .iter()
        .filter(|c| c.name == "temporary-files")
        .map(|c| (c.id, true))
        .collect();
    let plan = Plan::build(&results, &choices, &Policy::default(), &nothing_running());
    assert_eq!(plan.len(), 4);

    write_file(&temp.join("a.tmp"), 100);
    let _open = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(temp.join(r"busy\old.tmp"))
        .unwrap();
    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny).with_protected(&[temp.join(r"setup\deep")]);

    let (report, _) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );

    assert_eq!(report.deleted.files, 1, "only setup\\x.log");
    assert_eq!(
        report.skipped,
        [
            SkipCount {
                reason: "changed",
                files: 1
            },
            SkipCount {
                reason: "in_use",
                files: 1
            },
            SkipCount {
                reason: "protected",
                files: 1
            },
        ]
    );
    assert!(temp.join("a.tmp").exists());
    assert!(temp.join(r"setup\deep\y.log").exists());
    assert!(
        temp.join("setup").exists(),
        "it still holds the protected file"
    );
}

#[test]
fn cancelling_stops_before_the_next_file() {
    let machine = machine();
    let results = scan(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny);
    let cancel = CancelToken::new();

    let (report, history) = run(&machine, &results, &plan, &executor, &cancel, &mut |_| {
        cancel.cancel()
    });

    assert!(report.cancelled);
    assert_eq!(report.not_started, 5);
    assert_eq!(report.deleted.files + report.quarantined.len() as u64, 1);
    let files = history.iter().filter(|l| l["type"] == "file").count();
    assert_eq!(files, 1);
    assert_eq!(history.last().unwrap()["cancelled"], true);
}

#[test]
#[should_panic(expected = "a plan only runs against the results it was built from")]
fn a_plan_never_runs_against_other_results() {
    let machine = machine();
    let first = scan(&machine);
    let second = scan(&machine);
    let plan = Plan::build(
        &first,
        &everything(&first),
        &Policy::default(),
        &nothing_running(),
    );
    let deny = deny(&machine);
    let executor = Executor::new(Mode::DryRun, &deny);

    run(
        &machine,
        &second,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );
}

/// A browser rule, for the open-app tests.
const BROWSER_RULE: &str = r#"
[[rule]]
id          = "test.browser"
category    = "browser-caches"
level       = "simple"
risk        = "low"
paths       = ['%LOCALAPPDATA%\TestBrowser']
app         = { name = "Test Browser", processes = ["TestBrowser.exe"] }
name        = "Test Browser cache"
description = "Pages the browser saved"
"#;

/// The usual machine plus two cache files of Test Browser.
fn scan_with_browser(machine: &Machine) -> (ScanResults, PathBuf) {
    let cache = machine.m.system.local_app_data.join(r"TestBrowser\Cache");
    old_file(&cache.join("data_1"));
    old_file(&cache.join("data_2"));
    let rules =
        RuleSet::from_sources(&[("test.toml", RULES), ("browser.toml", BROWSER_RULE)]).unwrap();
    (ScanResults::new(machine.m.scan(&rules)), cache)
}

#[test]
fn an_open_app_is_left_out_of_the_plan() {
    let machine = machine();
    let (results, _) = scan_with_browser(&machine);

    let running = RunningPrograms::new(["explorer.exe", "testbrowser.EXE"]);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &running,
    );
    let open: Vec<(&str, u64)> = plan
        .summary()
        .apps_open
        .iter()
        .map(|app| (app.name.as_str(), app.files))
        .collect();
    assert_eq!(open, [("Test Browser", 2)]);
    assert_eq!(
        plan.summary().delete.files,
        4,
        "only the other low-risk files"
    );

    let closed = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    assert!(closed.summary().apps_open.is_empty());
    assert_eq!(closed.summary().delete.files, 6);
}

#[test]
fn an_app_opened_after_the_plan_keeps_its_files() {
    let machine = machine();
    let (results, cache) = scan_with_browser(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny);

    let (report, history) = run_while(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
        &RunningPrograms::new(["TestBrowser.exe"]),
    );

    assert!(cache.join("data_1").exists() && cache.join("data_2").exists());
    assert_eq!(
        report.skipped,
        [SkipCount {
            reason: "app_running",
            files: 2
        }]
    );
    assert_eq!(report.deleted.files, 4);
    let skipped = history
        .iter()
        .filter(|l| l["reason"]["kind"] == "app_running")
        .count();
    assert_eq!(skipped, 2);
}

#[test]
fn quarantine_groups_compare_by_days() {
    // The confirmation lists the shortest stay first.
    let machine = machine();
    let results = scan(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    let days: Vec<u32> = plan
        .summary()
        .quarantine
        .iter()
        .map(|g: &QuarantineGroup| g.days)
        .collect();
    assert_eq!(days, [7, 30]);
}

// ----- Recycle Bin (D32) -----

/// The plan for the Recycle Bin alone, with `policy`.
fn bin_plan(results: &ScanResults, policy: &Policy) -> Plan {
    let category = results
        .categories()
        .into_iter()
        .find(|c| c.name == "recycle-bin")
        .expect("the Recycle Bin holds something");
    Plan::build(
        results,
        &HashMap::from([(category.id, true)]),
        policy,
        &nothing_running(),
    )
}

const FIVE_ITEMS: BinTally = BinTally {
    drive: 'C',
    items: 5,
    size: 50_000,
};

#[test]
fn the_recycle_bin_is_emptied_whole_and_recorded() {
    let machine = machine();
    machine.m.bin.set('C', 5, 50_000);
    let results = scan(&machine);
    let plan = Plan::build(
        &results,
        &everything(&results),
        &Policy::default(),
        &nothing_running(),
    );
    assert_eq!(plan.summary().recycle_bins, [FIVE_ITEMS]);
    assert_eq!(plan.summary().delete.files, 4, "files are counted apart");
    assert_eq!(plan.len(), 7, "6 files and the Recycle Bin");

    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&machine.m.bin);
    let mut progress = Vec::new();
    let (report, history) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |p| progress.push(p.clone()),
    );

    assert_eq!(machine.m.bin.emptied(), ['C']);
    assert_eq!(report.recycle_bins, [FIVE_ITEMS]);
    assert!(report.recycle_bins_skipped.is_empty());
    assert_eq!(report.deleted.files, 4);
    assert_eq!(
        progress.last().unwrap().freed,
        report.deleted.size + 50_000,
        "progress counts the Recycle Bin's space"
    );

    let line = history.iter().find(|l| l["rule_id"] == "test.bin").unwrap();
    assert_eq!(line["type"], "file");
    assert_eq!(line["path"], r"C:\$Recycle.Bin");
    assert_eq!(
        (line["items"].as_u64(), line["size"].as_u64()),
        (Some(5), Some(50_000))
    );
    assert_eq!(line["result"], "deleted");
    let totals = history.last().unwrap();
    assert_eq!(totals["recycle_bins"][0]["drive"], "C");
    assert_eq!(totals["recycle_bins"][0]["items"], 5);

    let view = oj_core::HistoryView::load(&machine.m.system.history_path()).unwrap();
    let entry = &view.entries()[0];
    assert_eq!(entry.freed, report.deleted.size + 50_000);
    assert_eq!(entry.files, 6 + 5, "its items count as files");
    let files = view.files(0, 0, 100).unwrap().items;
    let bin = files.iter().find(|f| f.items.is_some()).unwrap();
    assert_eq!((bin.items, bin.result.as_str()), (Some(5), "deleted"));
}

#[test]
fn a_recycle_bin_that_changed_since_the_scan_is_left_alone() {
    let machine = machine();
    machine.m.bin.set('C', 5, 50_000);
    let results = scan(&machine);
    let plan = bin_plan(&results, &Policy::default());
    // Something else was deleted after the scan: it must not go too.
    machine.m.bin.set('C', 6, 60_000);

    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&machine.m.bin);
    let (report, history) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );

    assert!(machine.m.bin.emptied().is_empty());
    assert!(report.recycle_bins.is_empty());
    assert_eq!(
        report.recycle_bins_skipped,
        [BinSkip {
            drive: 'C',
            reason: "changed"
        }]
    );
    assert!(report.skipped.is_empty(), "files are counted apart");
    let line = history.iter().find(|l| l["rule_id"] == "test.bin").unwrap();
    assert_eq!(line["result"], "skipped");
}

#[test]
fn a_dry_run_leaves_the_recycle_bin_full() {
    let machine = machine();
    machine.m.bin.set('C', 5, 50_000);
    let results = scan(&machine);
    let plan = bin_plan(&results, &Policy::default());
    let deny = deny(&machine);
    let executor = Executor::new(Mode::DryRun, &deny).with_recycle_bin(&machine.m.bin);

    let (report, _) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );

    assert!(machine.m.bin.emptied().is_empty());
    assert_eq!(report.recycle_bins, [FIVE_ITEMS], "what would be emptied");
}

#[test]
fn always_using_the_quarantine_leaves_the_recycle_bin_out() {
    let machine = machine();
    machine.m.bin.set('C', 5, 50_000);
    let results = scan(&machine);
    let careful = Policy {
        low: Action::Quarantine { days: 7 },
        ..Policy::default()
    };

    let plan = bin_plan(&results, &careful);
    assert!(plan.is_empty(), "it can't go to quarantine");
    assert!(plan.summary().recycle_bins.is_empty());
    assert_eq!(plan.summary().recycle_bins_kept, [FIVE_ITEMS]);

    let deny = deny(&machine);
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&machine.m.bin);
    let (report, _) = run(
        &machine,
        &results,
        &plan,
        &executor,
        &CancelToken::new(),
        &mut |_| {},
    );
    assert!(machine.m.bin.emptied().is_empty());
    assert_eq!(report.recycle_bins_kept, [FIVE_ITEMS]);
}
