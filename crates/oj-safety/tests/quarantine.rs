//! Quarantine (PLANNING.md §4.5), always inside temporary folders.
//!
//! The rule these tests defend: a file is never lost. It's at its original
//! path or in the quarantine, and the manifest says which.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use common::{temp_root, write_file};
use oj_safety::quarantine::REPLACED_BY_RESTORE;
use oj_safety::{
    Batch, DenyList, Executor, FileSnapshot, IfExists, ItemState, Manifest, ManifestError, Mode,
    Outcome, SkipReason, Store, SystemPaths,
};
use tempfile::TempDir;

const WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

struct Setup {
    _dir: TempDir,
    root: PathBuf,
    deny: DenyList,
    store: Store,
}

/// A temp folder, a deny list for a fake system at `root\sys`, and a store
/// at `root\store`.
fn setup() -> Setup {
    let (dir, root) = temp_root();
    let deny = DenyList::new(&SystemPaths::fake(&root.join("sys"))).unwrap();
    let store = Store::new(root.join("store"));
    Setup {
        _dir: dir,
        root,
        deny,
        store,
    }
}

fn snapshot(path: &Path) -> FileSnapshot {
    FileSnapshot::capture(path, &fs::symlink_metadata(path).unwrap()).unwrap()
}

fn file_with(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// Quarantines `file` in a new batch and returns the batch name and item id.
fn quarantine(s: &Setup, file: &Path) -> (String, u32) {
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.new_batch(SystemTime::now());
    match executor.quarantine_file(
        &s.store,
        &mut batch,
        &snapshot(file),
        "test.rule",
        WEEK,
        SystemTime::now(),
    ) {
        Outcome::Quarantined { batch, item } => (batch, item),
        other => panic!("expected quarantined, got {other:?}"),
    }
}

fn restore(s: &Setup, batch: &str, id: u32, if_exists: IfExists) -> (Outcome, Batch) {
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.open_batch(batch).unwrap();
    let mut replaced = s.store.new_batch(SystemTime::now());
    let outcome = executor.restore(
        &s.store,
        &mut batch,
        id,
        if_exists,
        &mut replaced,
        WEEK,
        SystemTime::now(),
    );
    (outcome, replaced)
}

fn skipped(outcome: Outcome) -> SkipReason {
    match outcome {
        Outcome::Skipped { reason } => reason,
        other => panic!("expected a skip, got {other:?}"),
    }
}

/// Rewrites a batch's manifest, to simulate crashes and tampering.
fn edit_manifest(s: &Setup, batch: &str, change: impl FnOnce(&mut Manifest)) {
    let path = s.store.root().join(batch).join("manifest.json");
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    change(&mut manifest);
    fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

#[test]
fn a_file_goes_in_and_comes_back_unchanged() {
    let s = setup();
    let file = s.root.join(r"data\report.log");
    file_with(&file, "important log");
    let identity = snapshot(&file).file_id;

    let (name, id) = quarantine(&s, &file);

    assert!(!file.exists());
    let batch = s.store.open_batch(&name).unwrap();
    let item = batch.item(id).unwrap();
    assert_eq!(item.state, ItemState::Quarantined);
    assert_eq!(item.original_path, file);
    assert_eq!(item.stored_as, "items/000001");
    assert_eq!(item.rule_id, "test.rule");
    assert_eq!(item.expires_at - item.quarantined_at, WEEK.as_secs());
    assert_eq!(item.hash, None, "no hash unless a feature asks for one");
    let stored = batch.stored_path(id);
    assert_eq!(fs::read_to_string(&stored).unwrap(), "important log");
    assert_eq!(stored.extension(), None, "stored without its extension");

    let (outcome, _) = restore(&s, &name, id, IfExists::Skip);

    assert_eq!(outcome, Outcome::Restored { to: file.clone() });
    assert_eq!(fs::read_to_string(&file).unwrap(), "important log");
    assert_eq!(
        snapshot(&file).file_id,
        identity,
        "the same file, not a copy"
    );
    assert!(
        !s.store.root().join(&name).exists(),
        "an empty batch folder is removed"
    );
}

#[test]
fn a_dry_run_changes_nothing() {
    let s = setup();
    let file = s.root.join("a.tmp");
    file_with(&file, "x");
    let executor = Executor::new(Mode::DryRun, &s.deny);
    let mut batch = s.store.new_batch(SystemTime::now());

    let outcome = executor.quarantine_file(
        &s.store,
        &mut batch,
        &snapshot(&file),
        "r",
        WEEK,
        SystemTime::now(),
    );

    assert_eq!(outcome, Outcome::WouldQuarantine);
    assert!(file.exists());
    assert!(!s.store.root().exists(), "no store folder in a dry run");
}

#[test]
fn quarantine_revalidates_like_a_delete() {
    let s = setup();
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.new_batch(SystemTime::now());

    // Changed since the scan.
    let changed = s.root.join("changed.tmp");
    file_with(&changed, "before");
    let snap = snapshot(&changed);
    file_with(&changed, "after, and longer");
    assert_eq!(
        skipped(executor.quarantine_file(
            &s.store,
            &mut batch,
            &snap,
            "r",
            WEEK,
            SystemTime::now()
        )),
        SkipReason::Changed
    );

    // Replaced by a different file with the same name and size.
    let swapped = s.root.join("swapped.tmp");
    file_with(&swapped, "aaaa");
    let snap = snapshot(&swapped);
    let modified = fs::metadata(&swapped).unwrap().modified().unwrap();
    fs::remove_file(&swapped).unwrap();
    file_with(&swapped, "bbbb");
    fs::File::options()
        .write(true)
        .open(&swapped)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    assert_eq!(
        skipped(executor.quarantine_file(
            &s.store,
            &mut batch,
            &snap,
            "r",
            WEEK,
            SystemTime::now()
        )),
        SkipReason::Changed,
        "a different file ID means a different file"
    );

    // Protected by the user.
    let protected = s.root.join(r"keep\file.tmp");
    file_with(&protected, "x");
    let guarded = Executor::new(Mode::Live, &s.deny).with_protected(&[s.root.join("keep")]);
    assert_eq!(
        skipped(guarded.quarantine_file(
            &s.store,
            &mut batch,
            &snapshot(&protected),
            "r",
            WEEK,
            SystemTime::now()
        )),
        SkipReason::Protected
    );

    // Denied: inside the fake Windows folder.
    let system = s.root.join(r"sys\Windows\System32\kernel32.dll");
    file_with(&system, "x");
    assert!(matches!(
        skipped(executor.quarantine_file(
            &s.store,
            &mut batch,
            &snapshot(&system),
            "r",
            WEEK,
            SystemTime::now()
        )),
        SkipReason::Denied(_)
    ));

    assert!(changed.exists() && swapped.exists() && protected.exists() && system.exists());
    assert!(!s.store.root().exists(), "nothing was quarantined");
}

#[test]
fn one_batch_holds_many_files() {
    let s = setup();
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.new_batch(SystemTime::now());
    for name in ["a.log", "b.log", "c.log"] {
        let file = s.root.join(name);
        file_with(&file, name);
        let outcome = executor.quarantine_file(
            &s.store,
            &mut batch,
            &snapshot(&file),
            "r",
            WEEK,
            SystemTime::now(),
        );
        assert!(
            matches!(outcome, Outcome::Quarantined { .. }),
            "{outcome:?}"
        );
    }
    let reopened = s.store.open_batch(batch.name()).unwrap();
    let ids: Vec<u32> = reopened.manifest().items.iter().map(|i| i.id).collect();
    assert_eq!(ids, [1, 2, 3]);
    assert_eq!(s.store.batch_names().unwrap(), [batch.name().to_owned()]);
}

#[test]
fn two_batches_in_the_same_second_get_different_folders() {
    let s = setup();
    let now = SystemTime::now();
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut names = Vec::new();
    for name in ["first.log", "second.log"] {
        let file = s.root.join(name);
        file_with(&file, name);
        let mut batch = s.store.new_batch(now);
        executor.quarantine_file(&s.store, &mut batch, &snapshot(&file), "r", WEEK, now);
        names.push(batch.name().to_owned());
    }
    assert_ne!(names[0], names[1]);
    assert!(names[1].starts_with(&names[0]));
}

#[test]
fn restoring_into_a_taken_spot_can_skip() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "old");
    let (name, id) = quarantine(&s, &file);
    file_with(&file, "new file, same name");

    let (outcome, _) = restore(&s, &name, id, IfExists::Skip);

    assert_eq!(skipped(outcome), SkipReason::Conflict);
    assert_eq!(fs::read_to_string(&file).unwrap(), "new file, same name");
    let batch = s.store.open_batch(&name).unwrap();
    assert_eq!(batch.item(id).unwrap().state, ItemState::Quarantined);
}

#[test]
fn restoring_into_a_taken_spot_can_keep_both() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "old");
    let (name, id) = quarantine(&s, &file);
    file_with(&file, "new");

    let (outcome, _) = restore(&s, &name, id, IfExists::KeepBoth);

    let beside = s.root.join("a (restored).txt");
    assert_eq!(outcome, Outcome::Restored { to: beside.clone() });
    assert_eq!(fs::read_to_string(&file).unwrap(), "new");
    assert_eq!(fs::read_to_string(&beside).unwrap(), "old");
}

#[test]
fn replacing_quarantines_the_file_that_was_there() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "old");
    let (name, id) = quarantine(&s, &file);
    file_with(&file, "new");

    let (outcome, replaced) = restore(&s, &name, id, IfExists::Replace);

    assert_eq!(outcome, Outcome::Restored { to: file.clone() });
    assert_eq!(fs::read_to_string(&file).unwrap(), "old");
    // Nothing was lost: the newer file is in quarantine now.
    let replaced = s.store.open_batch(replaced.name()).unwrap();
    let item = &replaced.manifest().items[0];
    assert_eq!(item.rule_id, REPLACED_BY_RESTORE);
    assert_eq!(item.original_path, file);
    assert_eq!(
        fs::read_to_string(replaced.stored_path(item.id)).unwrap(),
        "new"
    );
}

#[test]
fn restoring_recreates_missing_folders() {
    let s = setup();
    let file = s.root.join(r"gone\deep\a.txt");
    file_with(&file, "x");
    let (name, id) = quarantine(&s, &file);
    fs::remove_dir_all(s.root.join("gone")).unwrap();

    let (outcome, _) = restore(&s, &name, id, IfExists::Skip);

    assert_eq!(outcome, Outcome::Restored { to: file.clone() });
    assert!(file.exists());
}

#[test]
fn a_restore_never_writes_into_a_denied_place() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "x");
    let (name, id) = quarantine(&s, &file);
    let target = s.root.join(r"sys\Windows\System32\evil.dll");
    edit_manifest(&s, &name, |m| m.items[0].original_path = target.clone());

    let (outcome, _) = restore(&s, &name, id, IfExists::Skip);

    assert!(matches!(skipped(outcome), SkipReason::Denied(_)));
    assert!(!target.exists());
}

#[test]
fn a_swapped_stored_file_is_neither_restored_nor_deleted() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "mine");
    let (name, id) = quarantine(&s, &file);
    let stored = s.store.open_batch(&name).unwrap().stored_path(id);
    fs::remove_file(&stored).unwrap();
    file_with(&stored, "evil");

    let (outcome, _) = restore(&s, &name, id, IfExists::Skip);
    assert_eq!(skipped(outcome), SkipReason::Changed);
    assert!(!file.exists());

    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.open_batch(&name).unwrap();
    assert_eq!(skipped(executor.purge(&mut batch, id)), SkipReason::Changed);
    assert!(stored.exists());
}

#[test]
fn tampered_manifests_are_refused() {
    let s = setup();
    let file = s.root.join("a.txt");
    file_with(&file, "x");
    let (name, _) = quarantine(&s, &file);

    edit_manifest(&s, &name, |m| {
        m.items[0].stored_as = r"..\..\..\Documents\thesis.docx".into()
    });
    assert!(matches!(
        s.store.open_batch(&name),
        Err(ManifestError::Invalid(_))
    ));

    edit_manifest(&s, &name, |m| {
        m.items[0].stored_as = "items/000001".into();
        m.items[0].original_path = PathBuf::from(r"relative\path.txt");
    });
    assert!(matches!(
        s.store.open_batch(&name),
        Err(ManifestError::Invalid(_))
    ));

    edit_manifest(&s, &name, |m| {
        m.items[0].original_path = file.clone();
        m.version = 99;
    });
    assert!(matches!(
        s.store.open_batch(&name),
        Err(ManifestError::NewerVersion(99))
    ));

    assert!(matches!(
        s.store.open_batch(r"..\store"),
        Err(ManifestError::Invalid(_))
    ));
}

#[test]
fn purging_deletes_for_good_and_reports_the_space() {
    let s = setup();
    let file = s.root.join("big.log");
    write_file(&file, 64 * 1024);
    let (name, id) = quarantine(&s, &file);
    let executor = Executor::new(Mode::Live, &s.deny);
    let mut batch = s.store.open_batch(&name).unwrap();
    let freed = batch.item(id).unwrap().reclaimable();
    assert!(freed >= 64 * 1024);

    assert_eq!(executor.purge(&mut batch, id), Outcome::Deleted { freed });

    assert!(!file.exists());
    assert!(!s.store.root().join(&name).exists());
    assert_eq!(
        skipped(executor.purge(&mut batch, id)),
        SkipReason::NotInQuarantine
    );
}

#[test]
fn only_expired_items_are_purged() {
    let s = setup();
    let executor = Executor::new(Mode::Live, &s.deny);
    let now = SystemTime::now();
    let mut batch = s.store.new_batch(now);
    let short = s.root.join("short.log");
    let long = s.root.join("long.log");
    file_with(&short, "x");
    file_with(&long, "y");
    executor.quarantine_file(
        &s.store,
        &mut batch,
        &snapshot(&short),
        "r",
        Duration::from_secs(60),
        now,
    );
    executor.quarantine_file(&s.store, &mut batch, &snapshot(&long), "r", WEEK, now);

    let report = s
        .store
        .purge_expired(&executor, now + Duration::from_secs(3600))
        .unwrap();

    assert_eq!(report.items.len(), 1);
    assert!(matches!(report.items[0].2, Outcome::Deleted { .. }));
    let batch = s.store.open_batch(batch.name()).unwrap();
    assert_eq!(batch.item(1).unwrap().state, ItemState::Purged);
    assert_eq!(batch.item(2).unwrap().state, ItemState::Quarantined);
}

#[test]
fn a_dry_run_purge_deletes_nothing() {
    let s = setup();
    let file = s.root.join("a.log");
    file_with(&file, "x");
    let (name, id) = quarantine(&s, &file);
    let mut batch = s.store.open_batch(&name).unwrap();

    let outcome = Executor::new(Mode::DryRun, &s.deny).purge(&mut batch, id);

    assert!(matches!(outcome, Outcome::WouldDelete { .. }));
    assert!(batch.stored_path(id).exists());
}

#[test]
fn recovery_after_a_crash_finds_every_file() {
    let s = setup();
    let in_store = s.root.join("moved.log");
    let not_moved = s.root.join("stayed.log");
    let restored = s.root.join("restored.log");
    let vanished = s.root.join("vanished.log");
    for file in [&in_store, &not_moved, &restored, &vanished] {
        file_with(file, "x");
    }
    let (b1, i1) = quarantine(&s, &in_store);
    let (b2, i2) = quarantine(&s, &not_moved);
    let (b3, i3) = quarantine(&s, &restored);
    let (b4, i4) = quarantine(&s, &vanished);

    // Crash before the "moved" note was written: the file is in the store.
    edit_manifest(&s, &b1, |m| m.items[0].state = ItemState::MovingIn);
    // Crash before the move itself: the file is still at its original path.
    let stored2 = s.store.open_batch(&b2).unwrap().stored_path(i2);
    fs::rename(&stored2, &not_moved).unwrap();
    edit_manifest(&s, &b2, |m| m.items[0].state = ItemState::MovingIn);
    // Crash after moving back out, before the "restored" note.
    let stored3 = s.store.open_batch(&b3).unwrap().stored_path(i3);
    fs::rename(&stored3, &restored).unwrap();
    edit_manifest(&s, &b3, |m| {
        m.items[0].state = ItemState::Restoring;
        m.items[0].restored_to = Some(restored.clone());
    });
    // Something else deleted a quarantined file.
    fs::remove_file(s.store.open_batch(&b4).unwrap().stored_path(i4)).unwrap();

    let recovery = s.store.recover().unwrap();

    let by_batch = |list: &mut Vec<(String, u32, ItemState)>| list.sort_by(|a, b| a.0.cmp(&b.0));
    let mut fixed = recovery.fixed.clone();
    by_batch(&mut fixed);
    let mut expected = vec![
        (b1.clone(), i1, ItemState::Quarantined),
        (b2.clone(), i2, ItemState::NotMoved),
        (b3.clone(), i3, ItemState::Restored),
        (b4.clone(), i4, ItemState::Missing),
    ];
    by_batch(&mut expected);
    assert_eq!(fixed, expected);
    assert!(recovery.unreadable.is_empty());
    // Batches with nothing left in them are tidied away.
    assert_eq!(s.store.batch_names().unwrap(), [b1]);
    assert!(not_moved.exists() && restored.exists());
}

#[test]
fn an_empty_store_has_no_batches() {
    let s = setup();
    assert!(s.store.batch_names().unwrap().is_empty());
    assert!(s.store.recover().unwrap().fixed.is_empty());
}
