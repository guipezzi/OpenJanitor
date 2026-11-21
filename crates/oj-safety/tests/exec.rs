mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{junction, temp_root, write_file};
use oj_safety::{
    DenyList, DenyReason, EntryClass, Executor, FileSnapshot, Mode, Outcome, SkipReason,
    SystemPaths,
};
use tempfile::TempDir;

struct Setup {
    _dir: TempDir,
    root: PathBuf,
    deny: DenyList,
}

/// A temp folder plus a deny list built from a fake layout at `root\sys`.
fn setup() -> Setup {
    let (dir, root) = temp_root();
    let deny = DenyList::new(&SystemPaths::fake(&root.join("sys"))).unwrap();
    Setup {
        _dir: dir,
        root,
        deny,
    }
}

fn snapshot(path: &Path) -> FileSnapshot {
    FileSnapshot::capture(path, &fs::symlink_metadata(path).unwrap()).unwrap()
}

fn skipped(outcome: Outcome) -> SkipReason {
    match outcome {
        Outcome::Skipped { reason } => reason,
        other => panic!("expected a skip, got {other:?}"),
    }
}

#[test]
fn dry_run_keeps_the_file() {
    let s = setup();
    let file = s.root.join("a.tmp");
    write_file(&file, 8192);
    let snap = snapshot(&file);

    let outcome = Executor::new(Mode::DryRun, &s.deny).delete_file(&snap);
    assert_eq!(
        outcome,
        Outcome::WouldDelete {
            freed: snap.reclaimable()
        }
    );
    assert!(file.exists());
}

#[test]
fn live_mode_deletes_the_file() {
    let s = setup();
    let file = s.root.join("a.tmp");
    write_file(&file, 8192);
    let snap = snapshot(&file);
    assert!(snap.reclaimable() > 0);

    let outcome = Executor::new(Mode::Live, &s.deny).delete_file(&snap);
    assert_eq!(
        outcome,
        Outcome::Deleted {
            freed: snap.reclaimable()
        }
    );
    assert!(!file.exists());
}

#[test]
fn changed_file_is_skipped() {
    let s = setup();
    let file = s.root.join("a.tmp");
    write_file(&file, 100);
    let snap = snapshot(&file);
    write_file(&file, 200);

    let outcome = Executor::new(Mode::Live, &s.deny).delete_file(&snap);
    assert_eq!(skipped(outcome), SkipReason::Changed);
    assert!(file.exists());
}

#[test]
fn missing_file_is_skipped() {
    let s = setup();
    let file = s.root.join("a.tmp");
    write_file(&file, 100);
    let snap = snapshot(&file);
    let executor = Executor::new(Mode::Live, &s.deny);
    assert!(matches!(
        executor.delete_file(&snap),
        Outcome::Deleted { .. }
    ));

    assert_eq!(skipped(executor.delete_file(&snap)), SkipReason::Missing);
}

#[test]
fn protected_paths_are_skipped() {
    let s = setup();
    let file = s.root.join(r"keep\a.tmp");
    write_file(&file, 100);
    let snap = snapshot(&file);

    let executor = Executor::new(Mode::Live, &s.deny).with_protected(&[s.root.join("keep")]);
    assert_eq!(skipped(executor.delete_file(&snap)), SkipReason::Protected);
    assert!(file.exists());
}

#[test]
fn denied_paths_are_skipped_even_with_a_valid_snapshot() {
    let s = setup();
    let file = s.root.join(r"sys\Windows\System32\kernel32.dll");
    write_file(&file, 100);
    let snap = snapshot(&file);

    let outcome = Executor::new(Mode::Live, &s.deny).delete_file(&snap);
    assert_eq!(
        skipped(outcome),
        SkipReason::Denied(DenyReason::ProtectedTree("the Windows folder"))
    );
    assert!(file.exists());
}

#[test]
fn junctions_are_never_deleted() {
    let s = setup();
    let outside = s.root.join("outside");
    write_file(&outside.join("keep.txt"), 100);
    let link = s.root.join("link");
    junction(&link, &outside);
    let metadata = fs::symlink_metadata(&link).unwrap();
    let snap = FileSnapshot {
        path: link.clone(),
        len: metadata.len(),
        allocated: 0,
        links: 1,
        modified: metadata.modified().unwrap(),
    };

    let outcome = Executor::new(Mode::Live, &s.deny).delete_file(&snap);
    assert_eq!(
        skipped(outcome),
        SkipReason::NotARegularFile(EntryClass::ReparsePoint)
    );
    assert!(link.exists());
    assert!(outside.join("keep.txt").exists());
}

#[test]
fn hard_linked_file_frees_nothing() {
    let s = setup();
    let file = s.root.join("a.bin");
    write_file(&file, 8192);
    fs::hard_link(&file, s.root.join("b.bin")).unwrap();

    let snap = snapshot(&file);
    assert_eq!(snap.links, 2);
    assert_eq!(snap.reclaimable(), 0);
}
