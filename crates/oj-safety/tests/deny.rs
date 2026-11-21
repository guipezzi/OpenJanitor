//! Every deny-list entry has a test proving it's blocked (PLANNING.md §9).
//!
//! These checks are purely lexical, so they run against a fake layout under
//! `C:\fake` without creating anything.

use std::path::Path;

use oj_safety::{DenyList, DenyReason, SystemPaths};

fn deny() -> DenyList {
    DenyList::new(&SystemPaths::fake(Path::new(r"C:\fake"))).unwrap()
}

fn reason(list: &DenyList, path: &str) -> DenyReason {
    match list.check(Path::new(path)) {
        Ok(()) => panic!("{path} should be denied"),
        Err(reason) => reason,
    }
}

fn assert_allowed(list: &DenyList, path: &str) {
    if let Err(reason) = list.check(Path::new(path)) {
        panic!("{path} should be allowed, but was denied: {reason}");
    }
}

fn assert_tree(list: &DenyList, path: &str, label: &'static str) {
    assert_eq!(
        reason(list, path),
        DenyReason::ProtectedTree(label),
        "{path}"
    );
}

fn assert_folder(list: &DenyList, path: &str) {
    assert!(
        matches!(reason(list, path), DenyReason::ProtectedFolder(_)),
        "{path} should be protected as a folder"
    );
}

#[test]
fn drive_roots_are_protected() {
    let d = deny();
    assert_eq!(reason(&d, r"C:\"), DenyReason::DriveRoot);
    assert_eq!(reason(&d, r"D:\"), DenyReason::DriveRoot);
}

#[test]
fn windows_folder_is_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Windows",
        r"C:\fake\Windows\explorer.exe",
        r"C:\fake\Windows\System32\kernel32.dll",
        r"C:\fake\Windows\WinSxS\x\y.dll",
        r"C:\fake\Windows\SoftwareDistribution\DataStore\DataStore.edb",
        r"C:\fake\Windows\Installer\abc.msi",
        r"C:\fake\Windows\Prefetch\APP.EXE-1234.pf",
    ] {
        assert_tree(&d, path, "the Windows folder");
    }
}

#[test]
fn windows_exception_contents_are_allowed() {
    let d = deny();
    for path in [
        r"C:\fake\Windows\Temp\setup.log",
        r"C:\fake\Windows\Temp\sub\file.tmp",
        r"C:\fake\Windows\Logs\CBS\CBS.log",
        r"C:\fake\Windows\Minidump\112026-01.dmp",
        r"C:\fake\Windows\LiveKernelReports\WATCHDOG.dmp",
        r"C:\fake\Windows\SoftwareDistribution\Download\abc\update.cab",
        r"C:\fake\Windows\MEMORY.DMP",
    ] {
        assert_allowed(&d, path);
    }
}

#[test]
fn windows_exception_folders_themselves_are_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Windows\Temp",
        r"C:\fake\Windows\Logs",
        r"C:\fake\Windows\Minidump",
        r"C:\fake\Windows\LiveKernelReports",
        r"C:\fake\Windows\SoftwareDistribution\Download",
    ] {
        assert_folder(&d, path);
    }
}

#[test]
fn similar_names_are_not_confused() {
    let d = deny();
    assert_tree(&d, r"C:\fake\Windows\TempBackup\x", "the Windows folder");
    assert_tree(&d, r"C:\fake\Windows\MEMORY.DMP.bak", "the Windows folder");
    assert_allowed(&d, r"C:\fake\WindowsOld\x.txt");
}

#[test]
fn program_files_are_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Program Files",
        r"C:\fake\Program Files\App\app.exe",
        r"C:\fake\Program Files (x86)\App\cache\x.bin",
    ] {
        assert_tree(&d, path, "Program Files");
    }
}

#[test]
fn program_data_is_protected_except_error_reports() {
    let d = deny();
    assert_tree(&d, r"C:\fake\ProgramData\App\config.ini", "ProgramData");
    assert_tree(
        &d,
        r"C:\fake\ProgramData\Microsoft\Windows\WER\Temp\x",
        "ProgramData",
    );
    assert_allowed(
        &d,
        r"C:\fake\ProgramData\Microsoft\Windows\WER\ReportArchive\r1\Report.wer",
    );
    assert_allowed(
        &d,
        r"C:\fake\ProgramData\Microsoft\Windows\WER\ReportQueue\r2\Report.wer",
    );
    assert_folder(
        &d,
        r"C:\fake\ProgramData\Microsoft\Windows\WER\ReportArchive",
    );
    assert_folder(&d, r"C:\fake\ProgramData\Microsoft\Windows\WER\ReportQueue");
}

#[test]
fn other_users_profiles_are_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Users",
        r"C:\fake\Users\other\AppData\Local\Temp\x.tmp",
        r"C:\fake\Users\Public\Documents\x.txt",
    ] {
        assert_tree(&d, path, "other users' profiles");
    }
}

#[test]
fn profile_root_is_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Users\tester",
        r"C:\fake\Users\tester\NTUSER.DAT",
        r"C:\fake\Users\tester\Projects\main.rs",
        r"C:\fake\Users\tester\.cargo\registry\cache\x.crate",
    ] {
        assert_tree(&d, path, "your user profile");
    }
}

#[test]
fn app_data_and_downloads_folders_themselves_are_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Users\tester\AppData",
        r"C:\fake\Users\tester\AppData\Roaming",
        r"C:\fake\Users\tester\AppData\Local",
        r"C:\fake\Users\tester\AppData\LocalLow",
        r"C:\fake\Users\tester\Downloads",
    ] {
        assert_folder(&d, path);
    }
}

#[test]
fn app_data_contents_are_allowed() {
    let d = deny();
    for path in [
        r"C:\fake\Users\tester\AppData\Local\Temp\x.tmp",
        r"C:\fake\Users\tester\AppData\Local\CrashDumps\app.exe.123.dmp",
        r"C:\fake\Users\tester\AppData\Roaming\SomeApp\Cache\x.bin",
        r"C:\fake\Users\tester\AppData\LocalLow\Game\cache.bin",
        r"C:\fake\Users\tester\Downloads\setup.exe",
    ] {
        assert_allowed(&d, path);
    }
}

#[test]
fn personal_folders_are_protected() {
    let d = deny();
    for folder in [
        "Desktop",
        "Documents",
        "Pictures",
        "Music",
        "Videos",
        "OneDrive",
    ] {
        assert_tree(
            &d,
            &format!(r"C:\fake\Users\tester\{folder}\file.txt"),
            "your personal folders",
        );
    }
}

#[test]
fn credential_storage_is_protected() {
    let d = deny();
    for path in [
        r"C:\fake\Users\tester\AppData\Roaming\Microsoft\Credentials\ABC",
        r"C:\fake\Users\tester\AppData\Roaming\Microsoft\Protect\S-1-5\key",
        r"C:\fake\Users\tester\AppData\Roaming\Microsoft\Crypto\RSA\key",
        r"C:\fake\Users\tester\AppData\Roaming\Microsoft\SystemCertificates\My\cert",
        r"C:\fake\Users\tester\AppData\Local\Microsoft\Credentials\ABC",
        r"C:\fake\Users\tester\AppData\Local\Microsoft\Vault\x\policy.vpol",
    ] {
        assert_tree(&d, path, "credential and key storage");
    }
}

#[test]
fn protected_names_are_blocked_anywhere() {
    let d = deny();
    for (path, name) in [
        (
            r"D:\System Volume Information\x",
            "system volume information",
        ),
        (r"C:\$Recycle.Bin\S-1-5-21\$R123.txt", "$recycle.bin"),
        (r"D:\pagefile.sys", "pagefile.sys"),
        (r"D:\hiberfil.sys", "hiberfil.sys"),
        (r"C:\swapfile.sys", "swapfile.sys"),
        (
            r"C:\fake\Users\tester\AppData\Local\Temp\.ssh\id_ed25519",
            ".ssh",
        ),
        (r"E:\backup\.gnupg\pubring.kbx", ".gnupg"),
        (r"E:\.openjanitor\quarantine\x", ".openjanitor"),
    ] {
        assert_eq!(
            reason(&d, path),
            DenyReason::ProtectedName(name.to_string()),
            "{path}"
        );
    }
}

#[test]
fn browser_profile_data_is_protected_inside_allowed_folders() {
    let d = deny();
    let chrome = r"C:\fake\Users\tester\AppData\Local\Google\Chrome\User Data";
    let firefox = r"C:\fake\Users\tester\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default";
    for path in [
        format!(r"{chrome}\Default\Cookies"),
        format!(r"{chrome}\Default\Network\Cookies"),
        format!(r"{chrome}\Default\Login Data"),
        format!(r"{chrome}\Default\History"),
        format!(r"{chrome}\Default\Web Data"),
        format!(r"{chrome}\Default\Bookmarks"),
        format!(r"{chrome}\Local State"),
        format!(r"{firefox}\places.sqlite"),
        format!(r"{firefox}\cookies.sqlite"),
        format!(r"{firefox}\key4.db"),
        format!(r"{firefox}\logins.json"),
    ] {
        assert!(
            matches!(reason(&d, &path), DenyReason::ProfileData(_)),
            "{path}"
        );
    }
    assert_allowed(&d, &format!(r"{chrome}\Default\Cache\Cache_Data\f_000001"));
    assert_allowed(&d, &format!(r"{firefox}\cache2\entries\ABC"));
}

#[test]
fn own_data_is_protected() {
    let d = deny();
    assert_tree(
        &d,
        r"C:\fake\Users\tester\AppData\Local\OpenJanitor\settings.json",
        "OpenJanitor's own data",
    );
}

#[test]
fn invalid_paths_are_refused() {
    let d = deny();
    for path in [
        r"Users\tester\AppData\Local\Temp\x",
        r"C:Temp\x",
        r"\\server\share\x",
        r"\\.\C:\x",
        r"C:\fake\Users\tester\AppData\Local\Temp\..\..\..\..\Documents\x",
        r"C:\fake\Users\TESTER~1\AppData\Local\Temp\x",
        r"C:\fake\Windows.\System32\x",
        r"C:\fake\Users\tester\AppData\Local\Temp\x.txt:hidden",
    ] {
        assert!(
            matches!(reason(&d, path), DenyReason::InvalidPath(_)),
            "{path}"
        );
    }
}

#[test]
fn verbatim_and_case_variants_are_still_protected() {
    let d = deny();
    for path in [
        r"\\?\C:\fake\Windows\System32\x.dll",
        r"c:\FAKE\windows\SYSTEM32\X.DLL",
        "C:/fake/Windows/System32/x.dll",
    ] {
        assert_tree(&d, path, "the Windows folder");
    }
}

#[test]
fn denies_subtree_prunes_only_fully_protected_folders() {
    let d = deny();
    let pruned = |path: &str| d.denies_subtree(Path::new(path));
    assert!(pruned(r"C:\fake\Windows\System32"));
    assert!(pruned(r"C:\fake\Program Files"));
    assert!(pruned(r"C:\fake\Users\tester\Documents"));
    assert!(pruned(r"C:\fake\Users\other"));
    assert!(pruned(
        r"C:\fake\Users\tester\AppData\Local\Microsoft\Vault"
    ));
    assert!(pruned(r"D:\System Volume Information"));
    assert!(pruned(r"C:\fake\Users\TESTER~1"));
    // These contain cleanable folders, so a walk must still go inside.
    assert!(!pruned(r"C:\fake\Windows"));
    assert!(!pruned(r"C:\fake\Windows\Temp"));
    assert!(!pruned(r"C:\fake\Windows\SoftwareDistribution"));
    assert!(!pruned(r"C:\fake\Users"));
    assert!(!pruned(r"C:\fake\Users\tester"));
    assert!(!pruned(r"C:\fake\Users\tester\AppData\Local"));
}
