mod common;

use std::path::PathBuf;

use common::{junction, temp_root, write_file};
use oj_safety::{CancelToken, DenyList, SystemPaths, walk_files};

/// A deny list whose protected folders live in a separate fake layout, so
/// nothing under the walk root is protected unless a test puts it there.
fn unrelated_deny(root: &std::path::Path) -> DenyList {
    DenyList::new(&SystemPaths::fake(&root.join("sys"))).unwrap()
}

fn walk(root: &std::path::Path, deny: &DenyList) -> (Vec<PathBuf>, oj_safety::WalkStats) {
    let mut found = Vec::new();
    let stats = walk_files(root, deny, &CancelToken::new(), |snapshot| {
        found.push(snapshot.path)
    });
    found.sort();
    (found, stats)
}

#[test]
fn a_cancelled_walk_reads_nothing() {
    let (_dir, root) = temp_root();
    let target = root.join("target");
    write_file(&target.join(r"sub\a.txt"), 10);
    let cancel = CancelToken::new();
    cancel.cancel();

    let mut found = 0;
    let stats = walk_files(&target, &unrelated_deny(&root), &cancel, |_| found += 1);
    assert_eq!(found, 0);
    assert_eq!(stats.directories, 0);
}

#[test]
fn cancelling_mid_walk_stops_at_the_next_file() {
    let (_dir, root) = temp_root();
    let target = root.join("target");
    for name in ["a.txt", "b.txt", "c.txt", r"sub\d.txt", r"sub\e.txt"] {
        write_file(&target.join(name), 10);
    }
    let cancel = CancelToken::new();

    let mut found = 0;
    walk_files(&target, &unrelated_deny(&root), &cancel, |_| {
        found += 1;
        cancel.cancel();
    });
    assert_eq!(found, 1);
}

#[test]
fn finds_files_recursively() {
    let (_dir, root) = temp_root();
    let target = root.join("target");
    for name in [r"a.txt", r"sub\b.txt", r"sub\deep\c.txt"] {
        write_file(&target.join(name), 10);
    }
    let (found, stats) = walk(&target, &unrelated_deny(&root));
    assert_eq!(
        found,
        vec![
            target.join("a.txt"),
            target.join(r"sub\b.txt"),
            target.join(r"sub\deep\c.txt"),
        ]
    );
    assert_eq!(stats.files, 3);
    assert_eq!(stats.directories, 3);
}

#[test]
fn never_enters_junctions() {
    let (_dir, root) = temp_root();
    let target = root.join("target");
    let outside = root.join("outside");
    write_file(&target.join("a.txt"), 10);
    write_file(&outside.join("secret.txt"), 10);
    junction(&target.join("link"), &outside);

    let (found, stats) = walk(&target, &unrelated_deny(&root));
    assert_eq!(found, vec![target.join("a.txt")]);
    assert_eq!(stats.skipped_reparse_points, 1);
}

#[test]
fn junction_as_root_is_not_entered() {
    let (_dir, root) = temp_root();
    let outside = root.join("outside");
    write_file(&outside.join("secret.txt"), 10);
    let link = root.join("link");
    junction(&link, &outside);

    let (found, stats) = walk(&link, &unrelated_deny(&root));
    assert!(found.is_empty());
    assert_eq!(stats.skipped_reparse_points, 1);
}

#[test]
fn skips_protected_files_and_folders() {
    let (_dir, root) = temp_root();
    let system = SystemPaths::fake(&root);
    let deny = DenyList::new(&system).unwrap();
    let local = &system.local_app_data;
    let chrome = local.join(r"Google\Chrome\User Data\Default");
    write_file(&local.join(r"Temp\t.tmp"), 10);
    write_file(&local.join(r"Microsoft\Vault\v.dat"), 10);
    write_file(&chrome.join("Cookies"), 10);
    write_file(&chrome.join(r"Cache\c.bin"), 10);

    let (found, stats) = walk(local, &deny);
    assert_eq!(
        found,
        vec![chrome.join(r"Cache\c.bin"), local.join(r"Temp\t.tmp")]
    );
    assert_eq!(stats.skipped_protected, 2, "Vault folder and Cookies file");
}

#[test]
fn missing_root_is_reported() {
    let (_dir, root) = temp_root();
    let (found, stats) = walk(&root.join("missing"), &unrelated_deny(&root));
    assert!(found.is_empty());
    assert_eq!(stats.unreadable, 1);
}
