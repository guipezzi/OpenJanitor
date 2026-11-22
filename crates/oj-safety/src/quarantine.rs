//! Quarantine: removal you can undo (PLANNING.md §4.5).
//!
//! Each cleanup that quarantines files creates a **batch**: a folder named
//! after the date and time, holding a `manifest.json` and the files under
//! numbered names (`items/000001`, ...). Numbered names without extensions
//! mean a quarantined program can't be started by accident, and names never
//! collide.
//!
//! Files move in and out with a single rename on the same drive, never a
//! copy, so they keep their contents, timestamps, permissions, and file ID.
//! The move never overwrites anything.
//!
//! Every step is written to the manifest *before* it happens. After a crash
//! or a power cut, [`Store::recover`] finds each file where the manifest
//! says it could be. Nothing is ever in neither place.
//!
//! A manifest can be edited by anyone who can write to the store, so
//! nothing in it is trusted: item names must look exactly like
//! `items/000001`, restore destinations go through the deny list, and a
//! stored file must still be the same file (size, modified time, file ID)
//! before it's restored or deleted.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_windows::FileId;
use oj_windows::file_move::move_no_replace;
use serde::{Deserialize, Serialize};

use crate::attrs::{EntryClass, classify_metadata};
use crate::deny::DenyReason;
use crate::exec::{Executor, Mode, Outcome, SkipReason, skip_reason_for};
use crate::path::NormPath;
use crate::persist::{tmp_path, write_atomic};
use crate::snapshot::FileSnapshot;

/// The manifest format written by this version. Newer formats are refused,
/// never guessed at.
pub const MANIFEST_VERSION: u32 = 1;

/// The rule id recorded for a file that "Replace" moved aside during a
/// restore.
pub const REPLACED_BY_RESTORE: &str = "quarantine.replaced-by-restore";

const MANIFEST: &str = "manifest.json";
const ITEMS: &str = "items";

/// Where an item is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Recorded and about to move in. Only seen after a crash.
    MovingIn,
    Quarantined,
    /// About to move back out. Only seen after a crash.
    Restoring,
    Restored,
    /// Deleted for good.
    Purged,
    /// Moving in failed; the file stayed where it was.
    NotMoved,
    /// Gone from the quarantine without OpenJanitor removing it.
    Missing,
}

impl ItemState {
    /// The item is done with: nothing of it is left in the store.
    fn is_final(self) -> bool {
        matches!(
            self,
            ItemState::Restored | ItemState::Purged | ItemState::NotMoved | ItemState::Missing
        )
    }
}

/// One quarantined file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: u32,
    pub state: ItemState,
    pub original_path: PathBuf,
    /// Where the file is inside the batch, always `items/` plus the
    /// six-digit id.
    pub stored_as: String,
    /// Logical size in bytes.
    pub size: u64,
    /// Bytes allocated on disk.
    pub allocated: u64,
    pub links: u32,
    /// Last modified, in nanoseconds since the Unix epoch.
    pub modified_ns: u64,
    /// The file's identity: volume serial number and file ID.
    pub file_id: String,
    pub rule_id: String,
    /// Seconds since the Unix epoch.
    pub quarantined_at: u64,
    /// When the item may be deleted for good, in seconds since the Unix
    /// epoch.
    pub expires_at: u64,
    /// Where the file went back to (the original path, or a "(restored)"
    /// name next to it). Written before the move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_to: Option<PathBuf>,
    /// A BLAKE3 fingerprint of the contents, if a feature needed one. Not
    /// computed when quarantining: moving within a drive never changes the
    /// contents, and hashing means reading every byte (D21).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl Item {
    /// Bytes freed when the item is deleted for good. A file with other
    /// hard links frees nothing.
    pub fn reclaimable(&self) -> u64 {
        if self.links <= 1 { self.allocated } else { 0 }
    }
}

/// A batch's manifest, stored as `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// The batch folder's name.
    pub batch: String,
    /// Seconds since the Unix epoch.
    pub created_at: u64,
    pub items: Vec<Item>,
}

/// A batch that can't be used.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("couldn't read the manifest: {0}")]
    Io(#[from] io::Error),
    #[error("the manifest isn't valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("the manifest was written by a newer version of OpenJanitor (format {0})")]
    NewerVersion(u32),
    #[error("the manifest was tampered with or is damaged: {0}")]
    Invalid(String),
}

/// What to do when restoring a file whose original path is taken again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IfExists {
    /// Move the file that's there now into quarantine, then restore (D23).
    Replace,
    /// Restore next to it, as "name (restored).ext".
    KeepBoth,
    /// Leave both alone.
    Skip,
}

/// One quarantine folder: the personal one, the system one, or one per
/// extra drive.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// What a store-wide operation did, item by item.
#[derive(Debug, Default)]
pub struct StoreReport {
    /// `(batch, item id, outcome)` for each item acted on.
    pub items: Vec<(String, u32, Outcome)>,
    /// Batches that couldn't be read, with the reason. They're left alone.
    pub unreadable: Vec<(String, String)>,
}

/// What [`Store::recover`] fixed, as `(batch, item id, new state)`.
#[derive(Debug, Default)]
pub struct Recovery {
    pub fixed: Vec<(String, u32, ItemState)>,
    pub unreadable: Vec<(String, String)>,
}

impl Store {
    /// A store rooted at `root`. Nothing is created until a file moves in.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A new, empty batch. Its folder is created when the first file moves
    /// in, so dry runs and cleanups that quarantine nothing leave no trace.
    pub fn new_batch(&self, now: SystemTime) -> Batch {
        let name = batch_name(now);
        Batch {
            dir: self.root.join(&name),
            on_disk: false,
            manifest: Manifest {
                version: MANIFEST_VERSION,
                batch: name,
                created_at: unix_secs(now),
                items: Vec::new(),
            },
        }
    }

    /// The batches in the store, oldest first.
    pub fn batch_names(&self) -> io::Result<Vec<String>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
                && is_batch_name(name)
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Reads and checks one batch's manifest.
    pub fn open_batch(&self, name: &str) -> Result<Batch, ManifestError> {
        if !is_batch_name(name) {
            return Err(ManifestError::Invalid(format!(
                "{name:?} isn't a batch name"
            )));
        }
        let dir = self.root.join(name);
        let manifest: Manifest = serde_json::from_slice(&fs::read(dir.join(MANIFEST))?)?;
        validate(&manifest, name)?;
        Ok(Batch {
            dir,
            manifest,
            on_disk: true,
        })
    }

    /// Puts every batch back in a consistent state after a crash or a power
    /// cut. Run it when the app starts, before anything else. It only
    /// edits manifests and removes empty batch folders; files stay where
    /// they are.
    pub fn recover(&self) -> io::Result<Recovery> {
        let mut recovery = Recovery::default();
        for name in self.batch_names()? {
            let mut batch = match self.open_batch(&name) {
                Ok(batch) => batch,
                Err(e) => {
                    recovery.unreadable.push((name, e.to_string()));
                    continue;
                }
            };
            let mut changed = false;
            for index in 0..batch.manifest.items.len() {
                let item = &batch.manifest.items[index];
                let stored = batch.stored_path(item.id).exists();
                let new_state = match item.state {
                    ItemState::MovingIn if stored => ItemState::Quarantined,
                    ItemState::MovingIn if item.original_path.exists() => ItemState::NotMoved,
                    ItemState::Restoring if stored => ItemState::Quarantined,
                    ItemState::Restoring
                        if item.restored_to.as_deref().is_some_and(Path::exists) =>
                    {
                        ItemState::Restored
                    }
                    ItemState::MovingIn | ItemState::Restoring => ItemState::Missing,
                    ItemState::Quarantined if !stored => ItemState::Missing,
                    _ => continue,
                };
                let item = &mut batch.manifest.items[index];
                if new_state == ItemState::Quarantined {
                    item.restored_to = None;
                }
                item.state = new_state;
                recovery.fixed.push((name.clone(), item.id, new_state));
                changed = true;
            }
            if changed {
                batch.save()?;
            }
            batch.tidy()?;
        }
        Ok(recovery)
    }

    /// Deletes every item whose time in quarantine is up.
    pub fn purge_expired(&self, executor: &Executor, now: SystemTime) -> io::Result<StoreReport> {
        let now = unix_secs(now);
        let mut report = StoreReport::default();
        for name in self.batch_names()? {
            let mut batch = match self.open_batch(&name) {
                Ok(batch) => batch,
                Err(e) => {
                    report.unreadable.push((name, e.to_string()));
                    continue;
                }
            };
            let expired: Vec<u32> = batch
                .manifest
                .items
                .iter()
                .filter(|item| item.state == ItemState::Quarantined && item.expires_at <= now)
                .map(|item| item.id)
                .collect();
            for id in expired {
                let outcome = executor.purge(&mut batch, id);
                report.items.push((name.clone(), id, outcome));
            }
        }
        Ok(report)
    }
}

/// One batch: a folder in the store with its manifest and files.
#[derive(Debug)]
pub struct Batch {
    dir: PathBuf,
    manifest: Manifest,
    on_disk: bool,
}

impl Batch {
    pub fn name(&self) -> &str {
        &self.manifest.batch
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn item(&self, id: u32) -> Option<&Item> {
        self.manifest.items.iter().find(|item| item.id == id)
    }

    /// Where item `id` is stored.
    pub fn stored_path(&self, id: u32) -> PathBuf {
        self.dir.join(stored_name(id))
    }

    fn item_mut(&mut self, id: u32) -> Option<&mut Item> {
        self.manifest.items.iter_mut().find(|item| item.id == id)
    }

    fn set_state(&mut self, id: u32, state: ItemState) {
        if let Some(item) = self.item_mut(id) {
            item.state = state;
        }
    }

    /// Creates the batch folder the first time a file moves in. If another
    /// batch already took the name (two cleanups in the same second), the
    /// new one gets a numbered suffix.
    fn ensure_on_disk(&mut self, store_root: &Path) -> io::Result<()> {
        if self.on_disk {
            return Ok(());
        }
        fs::create_dir_all(store_root)?;
        let base = self.manifest.batch.clone();
        for attempt in 1..=100 {
            let name = if attempt == 1 {
                base.clone()
            } else {
                format!("{base}-{attempt}")
            };
            let dir = store_root.join(&name);
            match fs::create_dir(&dir) {
                Ok(()) => {
                    fs::create_dir(dir.join(ITEMS))?;
                    self.dir = dir;
                    self.manifest.batch = name;
                    self.on_disk = true;
                    return self.save();
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("couldn't find a free batch name"))
    }

    /// Writes the manifest so that a crash leaves either the old version or
    /// the new one, never half of either.
    fn save(&self) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(&self.manifest).map_err(io::Error::other)?;
        write_atomic(&self.dir.join(MANIFEST), &json)
    }

    /// Removes the batch folder once nothing in it needs keeping. Returns
    /// whether it was removed. Folders are removed one by one and only when
    /// empty, so an unexpected file keeps the batch (and its manifest)
    /// around.
    fn tidy(&mut self) -> io::Result<bool> {
        if !self.on_disk || !self.manifest.items.iter().all(|i| i.state.is_final()) {
            return Ok(false);
        }
        match fs::remove_dir(self.dir.join(ITEMS)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Ok(false),
        }
        fs::remove_file(self.dir.join(MANIFEST))?;
        let _ = fs::remove_file(tmp_path(&self.dir.join(MANIFEST)));
        fs::remove_dir(&self.dir)?;
        self.on_disk = false;
        Ok(true)
    }
}

impl Executor<'_> {
    /// Moves one file into `batch` (a batch of `store`), or reports what
    /// would happen in dry-run mode. The file is revalidated first, exactly
    /// as before a delete. It stays in quarantine for `keep_for`.
    pub fn quarantine_file(
        &self,
        store: &Store,
        batch: &mut Batch,
        snapshot: &FileSnapshot,
        rule_id: &str,
        keep_for: Duration,
        now: SystemTime,
    ) -> Outcome {
        if let Err(reason) = self.revalidate(snapshot) {
            return Outcome::Skipped { reason };
        }
        if self.mode() == Mode::DryRun {
            return Outcome::WouldQuarantine;
        }
        match self.move_in(store, batch, snapshot, rule_id, keep_for, now) {
            Ok(id) => Outcome::Quarantined {
                batch: batch.name().to_owned(),
                item: id,
            },
            Err(reason) => Outcome::Skipped { reason },
        }
    }

    fn move_in(
        &self,
        store: &Store,
        batch: &mut Batch,
        snapshot: &FileSnapshot,
        rule_id: &str,
        keep_for: Duration,
        now: SystemTime,
    ) -> Result<u32, SkipReason> {
        let failed = |e: io::Error| SkipReason::Failed(e.to_string());
        batch.ensure_on_disk(&store.root).map_err(failed)?;

        let id = batch
            .manifest
            .items
            .iter()
            .map(|item| item.id)
            .max()
            .unwrap_or(0)
            + 1;
        batch.manifest.items.push(Item {
            id,
            state: ItemState::MovingIn,
            original_path: snapshot.path.clone(),
            stored_as: stored_name(id),
            size: snapshot.len,
            allocated: snapshot.allocated,
            links: snapshot.links,
            modified_ns: unix_nanos(snapshot.modified),
            file_id: snapshot.file_id.to_string(),
            rule_id: rule_id.to_owned(),
            quarantined_at: unix_secs(now),
            expires_at: unix_secs(now + keep_for),
            restored_to: None,
            hash: None,
        });
        // The record goes to disk before the file moves.
        if let Err(e) = batch.save() {
            batch.manifest.items.pop();
            return Err(failed(e));
        }

        match move_no_replace(&snapshot.path, &batch.stored_path(id)) {
            Ok(()) => {
                batch.set_state(id, ItemState::Quarantined);
                // If this write fails, the file is safe in the batch and
                // `recover` marks it quarantined.
                let _ = batch.save();
                Ok(id)
            }
            Err(e) => {
                batch.set_state(id, ItemState::NotMoved);
                let _ = batch.save();
                let _ = batch.tidy();
                Err(skip_reason_for(&e))
            }
        }
    }

    /// Moves item `id` back to where it came from (or next to it, with
    /// [`IfExists::KeepBoth`]).
    ///
    /// The stored file must still be the one that was quarantined, and the
    /// destination must pass the deny list. With [`IfExists::Replace`], the
    /// file currently at the destination goes into `replaced`, a batch of
    /// `store`, for `keep_replaced_for`.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        &self,
        store: &Store,
        batch: &mut Batch,
        id: u32,
        if_exists: IfExists,
        replaced: &mut Batch,
        keep_replaced_for: Duration,
        now: SystemTime,
    ) -> Outcome {
        match self.try_restore(
            store,
            batch,
            id,
            if_exists,
            replaced,
            keep_replaced_for,
            now,
        ) {
            Ok(outcome) => outcome,
            Err(reason) => Outcome::Skipped { reason },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn try_restore(
        &self,
        store: &Store,
        batch: &mut Batch,
        id: u32,
        if_exists: IfExists,
        replaced: &mut Batch,
        keep_replaced_for: Duration,
        now: SystemTime,
    ) -> Result<Outcome, SkipReason> {
        let failed = |e: io::Error| SkipReason::Failed(e.to_string());
        let item = batch
            .item(id)
            .filter(|item| item.state == ItemState::Quarantined)
            .cloned()
            .ok_or(SkipReason::NotInQuarantine)?;
        let stored = batch.stored_path(id);
        check_identity(&stored, &item)?;
        self.check_destination(&item.original_path)?;

        let mut target = item.original_path.clone();
        match fs::symlink_metadata(&target) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(failed(e)),
            Ok(existing) => match if_exists {
                IfExists::Skip => return Err(SkipReason::Conflict),
                IfExists::KeepBoth => {
                    target = free_name(&target).ok_or(SkipReason::Conflict)?;
                    self.check_destination(&target)?;
                }
                IfExists::Replace => {
                    if classify_metadata(&existing) != EntryClass::File {
                        return Err(SkipReason::Conflict);
                    }
                    let current = FileSnapshot::capture(&target, &existing).map_err(failed)?;
                    match self.quarantine_file(
                        store,
                        replaced,
                        &current,
                        REPLACED_BY_RESTORE,
                        keep_replaced_for,
                        now,
                    ) {
                        Outcome::Quarantined { .. } | Outcome::WouldQuarantine => {}
                        Outcome::Skipped { reason } => return Err(reason),
                        other => return Err(SkipReason::Failed(format!("unexpected {other:?}"))),
                    }
                }
            },
        }

        if self.mode() == Mode::DryRun {
            return Ok(Outcome::WouldRestore { to: target });
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(failed)?;
        }
        // Record where the file is going before it moves.
        if let Some(item) = batch.item_mut(id) {
            item.state = ItemState::Restoring;
            item.restored_to = Some(target.clone());
        }
        batch.save().map_err(failed)?;

        match move_no_replace(&stored, &target) {
            Ok(()) => {
                batch.set_state(id, ItemState::Restored);
                let _ = batch.save();
                let _ = batch.tidy();
                Ok(Outcome::Restored { to: target })
            }
            Err(e) => {
                if let Some(item) = batch.item_mut(id) {
                    item.state = ItemState::Quarantined;
                    item.restored_to = None;
                }
                let _ = batch.save();
                Err(skip_reason_for(&e))
            }
        }
    }

    /// Deletes item `id` for good, or reports what would happen in dry-run
    /// mode. The path is built from the item's number inside the store, and
    /// the stored file must still be the one that was quarantined.
    pub fn purge(&self, batch: &mut Batch, id: u32) -> Outcome {
        let Some(item) = batch
            .item(id)
            .filter(|item| item.state == ItemState::Quarantined)
            .cloned()
        else {
            return Outcome::Skipped {
                reason: SkipReason::NotInQuarantine,
            };
        };
        let stored = batch.stored_path(id);
        if let Err(reason) = check_identity(&stored, &item) {
            if reason == SkipReason::Missing && self.mode() == Mode::Live {
                batch.set_state(id, ItemState::Missing);
                let _ = batch.save();
                let _ = batch.tidy();
            }
            return Outcome::Skipped { reason };
        }
        let freed = item.reclaimable();
        if self.mode() == Mode::DryRun {
            return Outcome::WouldDelete { freed };
        }
        match fs::remove_file(&stored) {
            Ok(()) => {
                batch.set_state(id, ItemState::Purged);
                let _ = batch.save();
                let _ = batch.tidy();
                Outcome::Deleted { freed }
            }
            Err(e) => Outcome::Skipped {
                reason: skip_reason_for(&e),
            },
        }
    }

    /// A restore destination must be a valid path the deny list allows.
    fn check_destination(&self, path: &Path) -> Result<(), SkipReason> {
        let path =
            NormPath::new(path).map_err(|e| SkipReason::Denied(DenyReason::InvalidPath(e)))?;
        self.deny().check_norm(&path).map_err(SkipReason::Denied)
    }
}

/// The stored file must still be exactly what was quarantined: a regular
/// file with the same size, modified time, and file ID.
fn check_identity(stored: &Path, item: &Item) -> Result<(), SkipReason> {
    let metadata = fs::symlink_metadata(stored).map_err(|e| skip_reason_for(&e))?;
    match classify_metadata(&metadata) {
        EntryClass::File => {}
        other => return Err(SkipReason::NotARegularFile(other)),
    }
    let modified = metadata.modified().map(unix_nanos).ok();
    if metadata.len() != item.size || modified != Some(item.modified_ns) {
        return Err(SkipReason::Changed);
    }
    let expected: FileId = item.file_id.parse().map_err(|_| SkipReason::Changed)?;
    match oj_windows::disk_info(stored) {
        Ok(info) if info.file_id == expected => Ok(()),
        Ok(_) => Err(SkipReason::Changed),
        Err(e) => Err(skip_reason_for(&e)),
    }
}

/// Checks everything a tampered or damaged manifest could get wrong.
fn validate(manifest: &Manifest, folder: &str) -> Result<(), ManifestError> {
    let invalid = |message: String| ManifestError::Invalid(message);
    if manifest.version > MANIFEST_VERSION {
        return Err(ManifestError::NewerVersion(manifest.version));
    }
    if manifest.batch != folder {
        return Err(invalid(format!(
            "it names batch {:?} but sits in {folder:?}",
            manifest.batch
        )));
    }
    let mut ids = std::collections::HashSet::new();
    for item in &manifest.items {
        if !ids.insert(item.id) {
            return Err(invalid(format!("item {} appears twice", item.id)));
        }
        if item.stored_as != stored_name(item.id) {
            return Err(invalid(format!(
                "item {} is stored as {:?}",
                item.id, item.stored_as
            )));
        }
        for path in std::iter::once(&item.original_path).chain(&item.restored_to) {
            NormPath::new(path)
                .map_err(|e| invalid(format!("item {} has a bad path: {e}", item.id)))?;
        }
    }
    Ok(())
}

/// `items/000042`, always built from the number, never read from outside.
fn stored_name(id: u32) -> String {
    format!("{ITEMS}/{id:06}")
}

/// The first free "name (restored).ext" next to `path`.
fn free_name(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    let stem = path.file_stem()?.to_string_lossy();
    let extension = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..=100)
        .map(|n| match n {
            1 => format!("{stem} (restored){extension}"),
            n => format!("{stem} (restored {n}){extension}"),
        })
        .map(|name| parent.join(name))
        .find(|candidate| fs::symlink_metadata(candidate).is_err())
}

/// Batch folders are named `YYYYMMDD-HHMMSS` (UTC), plus `-N` when two
/// cleanups start in the same second.
fn batch_name(now: SystemTime) -> String {
    let secs = unix_secs(now);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn is_batch_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 15
        && bytes.len() <= 20
        && bytes[8] == b'-'
        && bytes.iter().all(|b| b.is_ascii_digit() || *b == b'-')
}

/// Calendar date for a count of days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`), so batch names don't need a date library.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_names_are_utc_dates() {
        assert_eq!(batch_name(UNIX_EPOCH), "19700101-000000");
        let then = UNIX_EPOCH + Duration::from_secs(1_763_740_800 + 3_725);
        assert_eq!(batch_name(then), "20251121-170205");
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(batch_name(leap), "20240229-000000");
    }

    #[test]
    fn only_batch_names_are_accepted() {
        assert!(is_batch_name("20261122-143005"));
        assert!(is_batch_name("20261122-143005-2"));
        for bad in [
            "..",
            r"..\..\Windows",
            "20261122_143005",
            "2026112-1430059",
            "",
        ] {
            assert!(!is_batch_name(bad), "{bad}");
        }
    }

    #[test]
    fn stored_names_come_from_the_number() {
        assert_eq!(stored_name(7), "items/000007");
    }
}
