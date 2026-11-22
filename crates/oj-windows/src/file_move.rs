//! The raw move primitive behind quarantine (PLANNING.md §4.5).
//!
//! Only `oj-safety` may call this: it decides *what* may move, after
//! revalidating everything. This file just performs one move.
//! `scripts/check-guardrails.ps1` allows the Win32 move call only in this
//! file, and calls to `move_no_replace` only in `oj-safety`.

use std::io;
use std::path::Path;

/// Moves `from` to `to` on the same volume, as one rename.
///
/// - **Never overwrites:** fails if something already exists at `to`.
///   (`std::fs::rename` replaces the destination on Windows.)
/// - **Never copies:** fails if `to` is on another volume, instead of
///   silently copying the data and deleting the original.
/// - The file keeps its contents, timestamps, permissions, and file ID.
/// - Returns only once the change is written to disk.
#[cfg(windows)]
pub fn move_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    use windows::core::PCWSTR;

    let from = crate::imp::wide(from);
    let to = crate::imp::wide(to);
    // SAFETY: both arguments are NUL-terminated UTF-16 strings that outlive
    // the call. Without MOVEFILE_REPLACE_EXISTING and MOVEFILE_COPY_ALLOWED,
    // Windows refuses to overwrite and refuses to copy across volumes.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(crate::imp::win32_error)
}

/// OpenJanitor only supports Windows; moving is never done elsewhere.
#[cfg(not(windows))]
pub fn move_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "moving files is only supported on Windows",
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn moves_and_keeps_the_file_identity() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a.txt");
        let to = dir.path().join(r"sub\b.txt");
        fs::write(&from, b"hello").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        let before = crate::disk_info(&from).unwrap().file_id;

        move_no_replace(&from, &to).unwrap();

        assert!(!from.exists());
        assert_eq!(fs::read(&to).unwrap(), b"hello");
        assert_eq!(crate::disk_info(&to).unwrap().file_id, before);
    }

    #[test]
    fn never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a.txt");
        let to = dir.path().join("b.txt");
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"keep me").unwrap();

        let error = move_no_replace(&from, &to).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&to).unwrap(), b"keep me");
        assert_eq!(fs::read(&from).unwrap(), b"new");
    }

    #[test]
    fn a_missing_source_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let error = move_no_replace(&dir.path().join("nope"), &dir.path().join("b")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
