//! The raw "empty the Recycle Bin" call (PLANNING.md §6.1 and D32).
//!
//! Only `oj-safety` may call this: it checks first that the Recycle Bin
//! still holds what the user confirmed. This file just makes the one call.
//! `scripts/check-guardrails.ps1` allows the shell call only in this file,
//! and calls to `shell_empty_recycle_bin` only in `oj-safety`.

use std::io;

/// Empties the signed-in user's Recycle Bin on `drive` (a letter, such as
/// `'C'`) for good, the way File Explorer's "Empty Recycle Bin" does, but
/// without asking, without a progress window, and without a sound. Other
/// drives and other users' Recycle Bins aren't touched.
#[cfg(windows)]
pub fn shell_empty_recycle_bin(drive: char) -> io::Result<()> {
    use windows::Win32::UI::Shell::{
        SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW,
    };
    use windows::core::PCWSTR;

    let root = crate::imp::drive_root(drive)?;
    // SAFETY: `root` is a NUL-terminated drive root (`C:\`) that outlives
    // the call. It's never empty: an empty path would empty the Recycle
    // Bin of every drive.
    unsafe {
        SHEmptyRecycleBinW(
            None,
            PCWSTR(root.as_ptr()),
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
        )
    }
    .map_err(crate::imp::win32_error)
}

/// OpenJanitor only supports Windows; nothing is emptied elsewhere.
#[cfg(not(windows))]
pub fn shell_empty_recycle_bin(_drive: char) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "emptying the Recycle Bin is only supported on Windows",
    ))
}
