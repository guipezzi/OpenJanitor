//! Emptying the Recycle Bin through the executor. Every test uses a fake
//! Recycle Bin; the real one is never read or emptied.

mod common;

use common::temp_root;
use oj_safety::{
    BinContents, DenyList, Executor, FakeRecycleBin, Mode, Outcome, SkipReason, SystemPaths,
};

fn deny() -> DenyList {
    let (_dir, root) = temp_root();
    DenyList::new(&SystemPaths::fake(&root)).unwrap()
}

const SEEN: BinContents = BinContents {
    items: 3,
    size: 3_000,
};

#[test]
fn a_dry_run_empties_nothing() {
    let deny = deny();
    let bin = FakeRecycleBin::new();
    bin.set('C', 3, 3_000);
    let executor = Executor::new(Mode::DryRun, &deny).with_recycle_bin(&bin);

    let outcome = executor.empty_recycle_bin('C', SEEN);

    assert_eq!(outcome, Outcome::WouldDelete { freed: 3_000 });
    assert!(bin.emptied().is_empty());
}

#[test]
fn an_unchanged_bin_is_emptied_and_only_that_drive() {
    let deny = deny();
    let bin = FakeRecycleBin::new();
    bin.set('C', 3, 3_000);
    bin.set('D', 1, 10);
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&bin);

    let outcome = executor.empty_recycle_bin('c', SEEN);

    assert_eq!(outcome, Outcome::Deleted { freed: 3_000 });
    assert_eq!(bin.emptied(), ['C']);
    let d = oj_safety::RecycleBin::contents(&bin, 'D').unwrap();
    assert_eq!(d.items, 1, "other drives keep theirs");
}

#[test]
fn a_bin_that_changed_since_the_scan_is_left_alone() {
    let deny = deny();
    let bin = FakeRecycleBin::new();
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&bin);

    // Something else was deleted after the scan.
    bin.set('C', 4, 3_500);
    assert_eq!(
        executor.empty_recycle_bin('C', SEEN),
        Outcome::Skipped {
            reason: SkipReason::Changed
        }
    );
    // Same count, different size: something was swapped.
    bin.set('C', 3, 2_000);
    assert_eq!(
        executor.empty_recycle_bin('C', SEEN),
        Outcome::Skipped {
            reason: SkipReason::Changed
        }
    );
    // Emptied in File Explorer meanwhile.
    bin.set('C', 0, 0);
    assert_eq!(
        executor.empty_recycle_bin('C', SEEN),
        Outcome::Skipped {
            reason: SkipReason::Missing
        }
    );
    assert!(bin.emptied().is_empty());
}

#[test]
fn without_a_recycle_bin_nothing_is_emptied() {
    let deny = deny();
    let outcome = Executor::new(Mode::Live, &deny).empty_recycle_bin('C', SEEN);
    assert!(matches!(
        outcome,
        Outcome::Skipped {
            reason: SkipReason::Failed(_)
        }
    ));
}

#[test]
fn errors_and_bad_drives_leave_it_alone() {
    let deny = deny();
    let bin = FakeRecycleBin::new();
    bin.set('C', 3, 3_000);
    let executor = Executor::new(Mode::Live, &deny).with_recycle_bin(&bin);

    assert!(matches!(
        executor.empty_recycle_bin('1', SEEN),
        Outcome::Skipped {
            reason: SkipReason::Failed(_)
        }
    ));
    bin.fail_with(5);
    assert_eq!(
        executor.empty_recycle_bin('C', SEEN),
        Outcome::Skipped {
            reason: SkipReason::AccessDenied
        }
    );
    assert!(bin.emptied().is_empty());
}
