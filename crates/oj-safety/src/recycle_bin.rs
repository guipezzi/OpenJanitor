//! The Recycle Bin (PLANNING.md §6.1 and D32).
//!
//! `$Recycle.Bin` is never deleted by hand (the deny list refuses it). A
//! Recycle Bin is emptied through the same shell call File Explorer uses,
//! and only by the [`Executor`](crate::Executor), right after checking that
//! it still holds what the user confirmed.

use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

pub use oj_windows::BinContents;

/// The signed-in user's Recycle Bins, one per drive.
///
/// Production code uses [`WindowsRecycleBin`]. Tests use a fake, so they
/// never read or empty the real one.
pub trait RecycleBin {
    /// What the Recycle Bin on `drive` (a letter, such as `'C'`) holds.
    /// Only reads.
    fn contents(&self, drive: char) -> io::Result<BinContents>;

    /// Empties the Recycle Bin on `drive` for good.
    ///
    /// Only the executor can call this, because only `oj-safety` can make an
    /// [`EmptyPermit`]. Other crates can still implement it, for a fake.
    fn empty(&self, drive: char, permit: EmptyPermit) -> io::Result<()>;
}

/// Proof that the executor is the caller of [`RecycleBin::empty`], after
/// its checks. It can't be made outside `oj-safety`.
#[derive(Debug)]
pub struct EmptyPermit(());

impl EmptyPermit {
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// The real Recycle Bins, through the Windows shell.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsRecycleBin;

impl RecycleBin for WindowsRecycleBin {
    fn contents(&self, drive: char) -> io::Result<BinContents> {
        oj_windows::recycle_bin_contents(drive)
    }

    fn empty(&self, drive: char, _permit: EmptyPermit) -> io::Result<()> {
        oj_windows::recycle_bin::shell_empty_recycle_bin(drive)
    }
}

/// A stand-in for the Recycle Bins, for tests and fixtures: it holds what
/// it's told to, and emptying it only forgets that. The real ones are never
/// read or touched.
#[derive(Debug, Default)]
pub struct FakeRecycleBin {
    bins: Mutex<HashMap<char, BinContents>>,
    emptied: Mutex<Vec<char>>,
    /// The Windows error code emptying fails with, if any.
    fail_with: Mutex<Option<i32>>,
}

impl FakeRecycleBin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts `items` items taking `size` bytes in the Recycle Bin on `drive`.
    pub fn set(&self, drive: char, items: u64, size: u64) {
        lock(&self.bins).insert(drive.to_ascii_uppercase(), BinContents { items, size });
    }

    /// The drives emptied so far, in order.
    pub fn emptied(&self) -> Vec<char> {
        lock(&self.emptied).clone()
    }

    /// Makes emptying fail with this Windows error code (5: access denied).
    pub fn fail_with(&self, code: i32) {
        *lock(&self.fail_with) = Some(code);
    }
}

impl RecycleBin for FakeRecycleBin {
    fn contents(&self, drive: char) -> io::Result<BinContents> {
        Ok(lock(&self.bins)
            .get(&drive.to_ascii_uppercase())
            .copied()
            .unwrap_or_default())
    }

    fn empty(&self, drive: char, _permit: EmptyPermit) -> io::Result<()> {
        if let Some(code) = *lock(&self.fail_with) {
            return Err(io::Error::from_raw_os_error(code));
        }
        let drive = drive.to_ascii_uppercase();
        lock(&self.bins).remove(&drive);
        lock(&self.emptied).push(drive);
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
