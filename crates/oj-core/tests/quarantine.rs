//! The Quarantine screen's tree and actions, on a fake machine. Everything
//! happens in a temp folder.

mod common;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use common::{FakeMachine, old_file, write_file};
use oj_core::{
    History, ItemRef, NodeId, NodeKind, QuarantineKeeper, QuarantineView, restore_conflicts,
};
use oj_safety::{DenyList, Executor, FileSnapshot, IfExists, Mode, Outcome, Store};
use serde_json::Value;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

struct Setup {
    m: FakeMachine,
    deny: DenyList,
    store: Store,
    /// When the first batch was made; the second is a minute later.
    then: SystemTime,
    logs: PathBuf,
    leftovers: PathBuf,
}

/// Two cleanups' worth of quarantine:
///
/// - the first (7 days): `Logs\app\a.log`, `Logs\app\b.log`,
///   `Logs\other\c.log`
/// - the second (30 days): `Leftovers\x.dat`
fn setup() -> Setup {
    let m = FakeMachine::new();
    let deny = DenyList::new(&m.system).unwrap();
    let store = Store::new(m.system.personal_quarantine());
    let logs = m.system.local_app_data.join("Logs");
    let leftovers = m.system.local_app_data.join("Leftovers");
    let then = SystemTime::now();
    let setup = Setup {
        m,
        deny,
        store,
        then,
        logs,
        leftovers,
    };
    setup.quarantine(
        &[
            setup.logs.join(r"app\a.log"),
            setup.logs.join(r"app\b.log"),
            setup.logs.join(r"other\c.log"),
        ],
        "test.logs",
        7,
        then,
    );
    setup.quarantine(
        &[setup.leftovers.join("x.dat")],
        "test.leftovers",
        30,
        then + Duration::from_secs(60),
    );
    setup
}

impl Setup {
    fn quarantine(&self, files: &[PathBuf], rule: &str, days: u64, now: SystemTime) {
        let executor = Executor::new(Mode::Live, &self.deny);
        let mut batch = self.store.new_batch(now);
        for file in files {
            old_file(file);
            let snapshot =
                FileSnapshot::capture(file, &fs::symlink_metadata(file).unwrap()).unwrap();
            let outcome = executor.quarantine_file(
                &self.store,
                &mut batch,
                &snapshot,
                rule,
                DAY * days as u32,
                now,
            );
            assert!(
                matches!(outcome, Outcome::Quarantined { .. }),
                "{outcome:?}"
            );
        }
    }

    fn view(&self) -> QuarantineView {
        QuarantineView::load(&self.store).unwrap()
    }

    /// Runs `action` with a live (or dry-run) keeper and returns what it
    /// wrote to the history.
    fn keep<T>(
        &self,
        mode: Mode,
        action: impl FnOnce(&mut QuarantineKeeper) -> T,
    ) -> (T, Vec<Value>) {
        let executor = Executor::new(mode, &self.deny);
        let path = self.m.system.history_path();
        let mut history = History::open(&path).unwrap();
        let result = action(&mut QuarantineKeeper {
            executor: &executor,
            store: &self.store,
            history: &mut history,
        });
        let lines = fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (result, lines)
    }

    /// The item that came from `path`.
    fn item(&self, path: &Path) -> ItemRef {
        let view = self.view();
        view.everything()
            .into_iter()
            .find(|item| {
                let batch = self.store.open_batch(&item.batch).unwrap();
                batch.item(item.id).unwrap().original_path == path
            })
            .unwrap()
    }
}

fn names(nodes: &[oj_core::NodeView]) -> Vec<String> {
    nodes.iter().map(|n| n.name.clone()).collect()
}

#[test]
fn the_tree_groups_files_by_cleanup_then_folder() {
    let s = setup();
    let view = s.view();

    let batches = view.batches();
    assert_eq!(batches.len(), 2);
    assert!(batches.iter().all(|b| b.kind == NodeKind::Batch));
    assert!(batches[0].name > batches[1].name, "newest first");
    assert_eq!(batches[1].file_count, 3);
    assert!(batches[1].quarantined_at.is_some());
    assert!(
        batches[1].expires_at < batches[0].expires_at,
        "7 days vs 30"
    );

    let folders = batches[1].children.as_ref().unwrap();
    assert_eq!(
        names(folders),
        [
            s.logs.join("app").display().to_string(),
            s.logs.join("other").display().to_string()
        ],
        "biggest first"
    );
    let files = view.children(folders[0].id, 0, 10).unwrap();
    assert_eq!(files.total, 2);
    assert_eq!(names(&files.items), ["a.log", "b.log"]);
    assert_eq!(files.items[0].rule_id.as_deref(), Some("test.logs"));
    assert_eq!(
        files.items[0].path.as_deref(),
        Some(s.logs.join(r"app\a.log").display().to_string().as_str())
    );

    let summary = view.summary();
    assert_eq!(summary.held.files, 4);
    assert!(summary.held.size > 0);
    let next = summary.next_expiry.unwrap();
    assert_eq!(next.files, 3, "the 7-day batch comes up first");
    assert!(summary.unreadable.is_empty());
}

#[test]
fn a_selection_resolves_to_quarantined_files() {
    let s = setup();
    let view = s.view();
    let batches = view.batches();
    let older = &batches[1];
    let other = older.children.as_ref().unwrap()[1].id;

    let choices: HashMap<NodeId, bool> = HashMap::from([(older.id, true), (other, false)]);
    assert_eq!(view.selected(&choices).len(), 2);
    assert!(view.selected(&HashMap::new()).is_empty());
    assert_eq!(view.everything().len(), 4);
}

#[test]
fn restoring_puts_files_back_and_writes_history() {
    let s = setup();
    let a = s.logs.join(r"app\a.log");
    let item = s.item(&a);

    let (report, history) = s.keep(Mode::Live, |k| {
        k.restore(&[item], IfExists::Skip, SystemTime::now())
    });

    assert!(a.exists());
    assert_eq!(report.done.files, 1);
    assert!(report.skipped.is_empty());
    assert_eq!(s.view().summary().held.files, 3);
    let line = &history[0];
    assert_eq!(line["type"], "quarantine");
    assert_eq!(line["action"], "restore");
    assert_eq!(line["result"], "restored");
    assert_eq!(line["path"], a.display().to_string());
}

#[test]
fn conflicts_are_found_and_each_choice_works() {
    let s = setup();
    let a = s.logs.join(r"app\a.log");
    let b = s.logs.join(r"app\b.log");
    let c = s.logs.join(r"other\c.log");
    let items = [s.item(&a), s.item(&b), s.item(&c)];
    // New files took a.log's and b.log's places.
    write_file(&a, 10);
    write_file(&b, 20);

    let conflicts = restore_conflicts(&s.store, &items);
    assert_eq!(conflicts.count, 2);
    assert_eq!(conflicts.samples, [a.clone(), b.clone()]);

    let (report, _) = s.keep(Mode::Live, |k| {
        k.restore(&items[..1], IfExists::Skip, SystemTime::now())
    });
    assert_eq!(report.skipped[0].reason, "conflict");
    assert_eq!(fs::metadata(&a).unwrap().len(), 10, "left alone");

    let (_, _) = s.keep(Mode::Live, |k| {
        k.restore(&items[..1], IfExists::KeepBoth, SystemTime::now())
    });
    assert!(s.logs.join(r"app\a (restored).log").exists());
    assert_eq!(fs::metadata(&a).unwrap().len(), 10);

    let (report, history) = s.keep(Mode::Live, |k| {
        k.restore(&items[1..2], IfExists::Replace, SystemTime::now())
    });
    assert_eq!(report.done.files, 1);
    assert_eq!(
        fs::metadata(&b).unwrap().len(),
        8192,
        "the quarantined file is back"
    );
    let replaced = history.iter().find(|l| l["action"] == "replace").unwrap();
    assert_eq!(replaced["result"], "quarantined");
    let held = s.view();
    assert!(
        held.everything().iter().any(|item| {
            let batch = s.store.open_batch(&item.batch).unwrap();
            let it = batch.item(item.id).unwrap();
            it.original_path == b && it.rule_id == oj_safety::quarantine::REPLACED_BY_RESTORE
        }),
        "the 20-byte b.log is in quarantine now"
    );

    // c.log's place was free.
    let (report, _) = s.keep(Mode::Live, |k| {
        k.restore(&items[2..], IfExists::Skip, SystemTime::now())
    });
    assert_eq!(report.done.files, 1);
    assert!(c.exists());
}

#[test]
fn deleting_now_frees_the_space() {
    let s = setup();
    let item = s.item(&s.logs.join(r"app\b.log"));
    let stored = s
        .store
        .open_batch(&item.batch)
        .unwrap()
        .stored_path(item.id);
    assert!(stored.exists());

    let (report, history) = s.keep(Mode::Live, |k| k.delete(std::slice::from_ref(&item)));

    assert!(!stored.exists());
    assert_eq!(report.done.files, 1);
    assert!(report.done.size > 0);
    assert_eq!(s.view().summary().held.files, 3);
    assert_eq!(history[0]["action"], "delete");
    assert_eq!(history[0]["result"], "deleted");

    let (again, _) = s.keep(Mode::Live, |k| k.delete(&[item]));
    assert_eq!(again.skipped[0].reason, "not_in_quarantine");
}

#[test]
fn expired_files_are_deleted_and_the_rest_stay() {
    let s = setup();

    let (report, history) = s.keep(Mode::Live, |k| k.delete_expired(s.then + DAY * 8).unwrap());

    assert_eq!(report.done.files, 3, "the 7-day batch");
    let view = s.view();
    assert_eq!(view.summary().held.files, 1, "the 30-day file stays");
    assert_eq!(view.batches().len(), 1);
    assert!(history.iter().all(|l| l["action"] == "expired"));

    let (nothing, _) = s.keep(Mode::Live, |k| k.delete_expired(s.then + DAY * 8).unwrap());
    assert_eq!(nothing.done.files, 0);
}

#[test]
fn a_dry_run_moves_and_deletes_nothing() {
    let s = setup();
    let a = s.logs.join(r"app\a.log");
    let everything = s.view().everything();

    let (restored, _) = s.keep(Mode::DryRun, |k| {
        k.restore(&everything, IfExists::Skip, SystemTime::now())
    });
    let (deleted, history) = s.keep(Mode::DryRun, |k| k.delete(&everything));
    let (expired, _) = s.keep(Mode::DryRun, |k| {
        k.delete_expired(s.then + DAY * 365).unwrap()
    });

    assert_eq!(restored.done.files, 4);
    assert_eq!(deleted.done.files, 4);
    assert_eq!(expired.done.files, 4);
    assert!(!a.exists());
    assert_eq!(s.view().summary().held.files, 4);
    assert!(history.iter().all(|l| l["mode"] == "dry_run"));
    assert!(history.iter().any(|l| l["result"] == "would_restore"));
    assert!(history.iter().any(|l| l["result"] == "would_delete"));
}

#[test]
fn unreadable_batches_are_listed_and_left_alone() {
    let s = setup();
    let broken = s.m.system.personal_quarantine().join("20200101-000000");
    write_file(&broken.join("manifest.json"), 0);
    fs::write(broken.join("manifest.json"), "not json").unwrap();

    let view = s.view();
    assert_eq!(view.summary().unreadable.len(), 1);
    assert_eq!(view.summary().unreadable[0].folder, broken);
    assert_eq!(view.summary().held.files, 4);

    s.keep(Mode::Live, |k| {
        k.delete_expired(s.then + DAY * 365).unwrap()
    });
    assert!(broken.join("manifest.json").exists());
}
