//! Revalidation and the actual delete (PLANNING.md §4.4).
//!
//! This is the only place in OpenJanitor that removes a file. Quarantine
//! (moving instead of deleting) comes in phase 1 and will live here too.

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::attrs::{EntryClass, classify_metadata};
use crate::deny::{DenyList, DenyReason};
use crate::path::NormPath;
use crate::snapshot::FileSnapshot;

/// Whether destructive operations really happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Report what would happen, change nothing.
    DryRun,
    /// Really delete.
    Live,
}

impl Mode {
    /// Reads `OJ_DRY_RUN`: `1`/`true` forces dry-run, `0`/`false` forces live.
    /// Without it, debug builds default to dry-run and release builds to live.
    pub fn from_env() -> Self {
        match std::env::var("OJ_DRY_RUN").as_deref() {
            Ok("1") | Ok("true") => Mode::DryRun,
            Ok("0") | Ok("false") => Mode::Live,
            _ if cfg!(debug_assertions) => Mode::DryRun,
            _ => Mode::Live,
        }
    }
}

/// What happened to one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    Deleted { freed: u64 },
    WouldDelete { freed: u64 },
    Skipped { reason: SkipReason },
}

/// Why a file was left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum SkipReason {
    /// The deny list refused it.
    Denied(DenyReason),
    /// The user protected it.
    Protected,
    /// It no longer exists.
    Missing,
    /// Its size or modified time changed since the scan.
    Changed,
    /// It's no longer a regular file (for example, it became a junction).
    NotARegularFile(EntryClass),
    /// Another program has it open.
    InUse,
    AccessDenied,
    Failed(String),
}

/// Performs file operations after revalidating every target.
pub struct Executor<'a> {
    mode: Mode,
    deny: &'a DenyList,
    protected: Vec<NormPath>,
}

impl<'a> Executor<'a> {
    pub fn new(mode: Mode, deny: &'a DenyList) -> Self {
        Self {
            mode,
            deny,
            protected: Vec::new(),
        }
    }

    /// Adds the user's Protected list: files and folders (with everything
    /// inside) that must never be touched.
    pub fn with_protected(mut self, protected: &[impl AsRef<Path>]) -> Self {
        self.protected.extend(
            protected
                .iter()
                .filter_map(|path| NormPath::new(path.as_ref()).ok()),
        );
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Checks that `snapshot` may still be acted on: allowed by the deny
    /// list, not protected, still a regular file, and unchanged since the
    /// scan.
    pub fn revalidate(&self, snapshot: &FileSnapshot) -> Result<(), SkipReason> {
        let path = NormPath::new(&snapshot.path)
            .map_err(|e| SkipReason::Denied(DenyReason::InvalidPath(e)))?;
        self.deny.check_norm(&path).map_err(SkipReason::Denied)?;
        if self.protected.iter().any(|p| path.starts_with(p)) {
            return Err(SkipReason::Protected);
        }
        let metadata = match fs::symlink_metadata(&snapshot.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(SkipReason::Missing),
            Err(e) => return Err(SkipReason::Failed(e.to_string())),
        };
        match classify_metadata(&metadata) {
            EntryClass::File => {}
            other => return Err(SkipReason::NotARegularFile(other)),
        }
        let modified = metadata.modified().ok();
        if metadata.len() != snapshot.len || modified != Some(snapshot.modified) {
            return Err(SkipReason::Changed);
        }
        Ok(())
    }

    /// Deletes one file, or reports what would happen in dry-run mode.
    ///
    /// Only regular files are ever deleted; folders are not. If the file is
    /// swapped for a reparse point between revalidation and deletion,
    /// Windows removes the link itself, never its target.
    pub fn delete_file(&self, snapshot: &FileSnapshot) -> Outcome {
        if let Err(reason) = self.revalidate(snapshot) {
            return Outcome::Skipped { reason };
        }
        let freed = snapshot.reclaimable();
        if self.mode == Mode::DryRun {
            return Outcome::WouldDelete { freed };
        }
        match fs::remove_file(&snapshot.path) {
            Ok(()) => Outcome::Deleted { freed },
            Err(e) => Outcome::Skipped {
                reason: skip_reason_for(&e),
            },
        }
    }
}

fn skip_reason_for(error: &io::Error) -> SkipReason {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    match (error.kind(), error.raw_os_error()) {
        (io::ErrorKind::NotFound, _) => SkipReason::Missing,
        (_, Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)) => SkipReason::InUse,
        (io::ErrorKind::PermissionDenied, _) => SkipReason::AccessDenied,
        _ => SkipReason::Failed(error.to_string()),
    }
}
