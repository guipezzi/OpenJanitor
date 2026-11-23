//! The quarantine as the Quarantine screen sees it (PLANNING.md §4.5 and
//! §7.3): a tree of cleanup → original folder → file, and what can be done
//! with it: restore, delete now, and deleting expired files at startup.
//!
//! The tree is read from the manifests and identifies files by node id, so
//! the UI never sends a path. Every file operation goes through the
//! [`Executor`] in `oj-safety`, which checks the stored file again first.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oj_safety::{Batch, Executor, IfExists, Item, ItemState, Mode, Outcome, SkipReason, Store};
use serde::Serialize;

use crate::clean::{SkipCount, Tally};
use crate::history::{HeldFile, History, QuarantineAction};
use crate::results::{ChildPage, NodeId, NodeKind, NodeView};

/// How long a file that a restore replaced stays in quarantine (D23).
pub const REPLACED_KEEP_DAYS: u64 = 30;

const DAY: u64 = 24 * 60 * 60;

/// How many conflicting paths a restore check names.
const CONFLICT_SAMPLES: usize = 5;

/// Numbers each [`QuarantineView`] built in this process.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// One quarantined file: its batch and its number in it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemRef {
    pub batch: String,
    pub id: u32,
}

/// A batch whose manifest couldn't be read. It's left alone, never
/// deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnreadableBatch {
    pub batch: String,
    pub folder: PathBuf,
    pub error: String,
}

/// The next files whose time in quarantine is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NextExpiry {
    /// Seconds since the Unix epoch.
    pub at: u64,
    pub files: u64,
    pub size: u64,
}

/// The quarantine in totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QuarantineSummary {
    /// Files held, and the space deleting them would free.
    pub held: Tally,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_expiry: Option<NextExpiry>,
    pub unreadable: Vec<UnreadableBatch>,
}

#[derive(Debug, Clone)]
struct Node {
    kind: NodeKind,
    name: String,
    children: Vec<NodeId>,
    path: Option<PathBuf>,
    item: Option<ItemRef>,
    rule_id: Option<String>,
    size: u64,
    files: u64,
    quarantined_at: u64,
    /// The earliest expiry inside.
    expires_at: u64,
}

impl Node {
    fn new(kind: NodeKind, name: String) -> Self {
        Self {
            kind,
            name,
            children: Vec::new(),
            path: None,
            item: None,
            rule_id: None,
            size: 0,
            files: 0,
            quarantined_at: u64::MAX,
            expires_at: u64::MAX,
        }
    }
}

/// What's in a quarantine store, as a tree: batches (newest first), then
/// the folders the files came from, then the files. Node ids are only
/// valid for this view.
#[derive(Debug)]
pub struct QuarantineView {
    id: u64,
    nodes: Vec<Node>,
    batches: Vec<NodeId>,
    summary: QuarantineSummary,
}

impl QuarantineView {
    /// Reads every batch in `store`. Only files still in quarantine are
    /// shown; batches that can't be read are listed in the summary.
    pub fn load(store: &Store) -> io::Result<Self> {
        let mut view = Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            nodes: Vec::new(),
            batches: Vec::new(),
            summary: QuarantineSummary::default(),
        };
        let mut expiries: BTreeMap<u64, Tally> = BTreeMap::new();
        for name in store.batch_names()?.into_iter().rev() {
            let batch = match store.open_batch(&name) {
                Ok(batch) => batch,
                Err(error) => {
                    view.summary.unreadable.push(UnreadableBatch {
                        folder: store.root().join(&name),
                        batch: name,
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            view.add_batch(&batch, &mut expiries);
        }
        for index in 0..view.nodes.len() {
            let mut children = std::mem::take(&mut view.nodes[index].children);
            children.sort_by(|&a, &b| {
                let (a, b) = (&view.nodes[a as usize], &view.nodes[b as usize]);
                b.size
                    .cmp(&a.size)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            view.nodes[index].children = children;
        }
        view.summary.held = Tally {
            files: view
                .batches
                .iter()
                .map(|&b| view.nodes[b as usize].files)
                .sum(),
            size: view
                .batches
                .iter()
                .map(|&b| view.nodes[b as usize].size)
                .sum(),
        };
        view.summary.next_expiry = expiries.into_iter().next().map(|(at, tally)| NextExpiry {
            at,
            files: tally.files,
            size: tally.size,
        });
        Ok(view)
    }

    fn add_batch(&mut self, batch: &Batch, expiries: &mut BTreeMap<u64, Tally>) {
        let held: Vec<&Item> = batch
            .manifest()
            .items
            .iter()
            .filter(|item| item.state == ItemState::Quarantined)
            .collect();
        if held.is_empty() {
            return;
        }
        let mut root = Node::new(NodeKind::Batch, batch.name().to_owned());
        root.quarantined_at = batch.manifest().created_at;
        let batch_id = self.push(root, None);
        self.batches.push(batch_id);

        let mut folders: HashMap<&Path, NodeId> = HashMap::new();
        for item in held {
            let parent = item.original_path.parent().unwrap_or(Path::new(""));
            let folder = match folders.get(parent) {
                Some(&id) => id,
                None => {
                    let mut node = Node::new(NodeKind::Folder, parent.display().to_string());
                    node.path = Some(parent.to_path_buf());
                    let id = self.push(node, Some(batch_id));
                    folders.insert(parent, id);
                    id
                }
            };
            let name = item
                .original_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| item.original_path.display().to_string());
            let mut file = Node::new(NodeKind::File, name);
            file.path = Some(item.original_path.clone());
            file.item = Some(ItemRef {
                batch: batch.name().to_owned(),
                id: item.id,
            });
            file.rule_id = Some(item.rule_id.clone());
            file.size = item.reclaimable();
            file.files = 1;
            file.quarantined_at = item.quarantined_at;
            file.expires_at = item.expires_at;
            let size = file.size;
            self.push(file, Some(folder));
            for id in [folder, batch_id] {
                let node = &mut self.nodes[id as usize];
                node.size += size;
                node.files += 1;
                node.expires_at = node.expires_at.min(item.expires_at);
                node.quarantined_at = node.quarantined_at.min(item.quarantined_at);
            }
            expiries.entry(item.expires_at).or_default().add(size);
        }
    }

    fn push(&mut self, node: Node, parent: Option<NodeId>) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(node);
        if let Some(parent) = parent {
            self.nodes[parent as usize].children.push(id);
        }
        id
    }

    /// Tells this view apart from any other, so actions can't mix up node
    /// ids from an older one.
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn summary(&self) -> &QuarantineSummary {
        &self.summary
    }

    /// The top level: batches, newest first, each with its folders.
    pub fn batches(&self) -> Vec<NodeView> {
        self.batches
            .iter()
            .map(|&id| {
                let mut view = self.view(id);
                view.children = Some(
                    self.nodes[id as usize]
                        .children
                        .iter()
                        .map(|&child| self.view(child))
                        .collect(),
                );
                view
            })
            .collect()
    }

    /// Up to `limit` children of `id`, starting at `offset`, biggest first.
    pub fn children(&self, id: NodeId, offset: usize, limit: usize) -> Option<ChildPage> {
        let node = self.nodes.get(id as usize)?;
        Some(ChildPage {
            items: node
                .children
                .iter()
                .skip(offset)
                .take(limit)
                .map(|&child| self.view(child))
                .collect(),
            total: node.children.len(),
        })
    }

    /// The files a selection covers, by the same rule as the results tree
    /// (see [`crate::ScanResults::selected`]).
    pub fn selected(&self, choices: &HashMap<NodeId, bool>) -> Vec<ItemRef> {
        let mut found = Vec::new();
        let mut pending: Vec<(NodeId, bool)> =
            self.batches.iter().rev().map(|&id| (id, false)).collect();
        while let Some((id, inherited)) = pending.pop() {
            let node = &self.nodes[id as usize];
            let selected = choices.get(&id).copied().unwrap_or(inherited);
            match &node.item {
                Some(item) if selected => found.push(item.clone()),
                Some(_) => {}
                None => pending.extend(node.children.iter().rev().map(|&child| (child, selected))),
            }
        }
        found
    }

    /// Every file in the view, for "Empty quarantine now".
    pub fn everything(&self) -> Vec<ItemRef> {
        self.nodes
            .iter()
            .filter_map(|node| node.item.clone())
            .collect()
    }

    fn view(&self, id: NodeId) -> NodeView {
        let node = &self.nodes[id as usize];
        let known = |time: u64| (time != u64::MAX).then_some(time);
        NodeView {
            id,
            kind: node.kind,
            name: node.name.clone(),
            rule_id: node.rule_id.clone(),
            risk: None,
            recommended: None,
            needs_admin: false,
            size_on_disk: node.size,
            file_count: node.files,
            last_modified: 0,
            path: node.path.as_ref().map(|p| p.display().to_string()),
            evidence: Vec::new(),
            quarantined_at: known(node.quarantined_at),
            expires_at: known(node.expires_at),
            has_children: !node.children.is_empty(),
            children: None,
        }
    }
}

/// Selected files whose original place is taken again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Conflicts {
    pub count: u64,
    /// The first few of those places.
    pub samples: Vec<PathBuf>,
}

/// Which of `items` would land where something already is, so the user can
/// choose Replace, Keep both, or Skip once for all of them. Changes
/// nothing.
pub fn restore_conflicts(store: &Store, items: &[ItemRef]) -> Conflicts {
    let mut conflicts = Conflicts::default();
    for (name, ids) in by_batch(items) {
        let Ok(batch) = store.open_batch(name) else {
            continue;
        };
        for id in ids {
            let Some(item) = batch
                .item(id)
                .filter(|item| item.state == ItemState::Quarantined)
            else {
                continue;
            };
            if fs::symlink_metadata(&item.original_path).is_ok() {
                conflicts.count += 1;
                if conflicts.samples.len() < CONFLICT_SAMPLES {
                    conflicts.samples.push(item.original_path.clone());
                }
            }
        }
    }
    conflicts
}

/// What a restore or a delete did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineReport {
    pub mode: Mode,
    /// Restored, or deleted for good (in dry-run mode: would have been).
    /// For deletes, `size` is the space freed.
    pub done: Tally,
    /// Files left alone, most common reason first.
    pub skipped: Vec<SkipCount>,
    /// The history couldn't be written in full.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_error: Option<String>,
}

/// Restores and deletes quarantined files.
pub struct QuarantineKeeper<'a> {
    pub executor: &'a Executor<'a>,
    pub store: &'a Store,
    pub history: &'a mut History,
}

impl QuarantineKeeper<'_> {
    /// Moves `items` back where they came from. Where something is there
    /// again, `if_exists` decides; with [`IfExists::Replace`], the file
    /// that's there goes into quarantine first (D23).
    pub fn restore(
        &mut self,
        items: &[ItemRef],
        if_exists: IfExists,
        now: SystemTime,
    ) -> QuarantineReport {
        let mode = self.executor.mode();
        let mut tally = Counter::default();
        let mut replaced = self.store.new_batch(now);
        let keep_replaced_for = Duration::from_secs(REPLACED_KEEP_DAYS * DAY);
        for (name, ids) in by_batch(items) {
            let Some(mut batch) = self.open(name, ids.len(), &mut tally) else {
                continue;
            };
            for id in ids {
                let Some(item) = held(&batch, id, &mut tally) else {
                    continue;
                };
                let outcome = self.executor.restore(
                    self.store,
                    &mut batch,
                    id,
                    if_exists,
                    &mut replaced,
                    keep_replaced_for,
                    now,
                );
                if matches!(
                    outcome,
                    Outcome::Restored { .. } | Outcome::WouldRestore { .. }
                ) {
                    tally.done.files += 1;
                    tally.done.size += item.reclaimable();
                }
                tally.note(&outcome);
                self.log(mode, QuarantineAction::Restore, name, &item, &outcome);
            }
        }
        // The files Replace moved aside are quarantined like any other.
        for item in &replaced.manifest().items {
            if item.state == ItemState::Quarantined {
                let outcome = Outcome::Quarantined {
                    batch: replaced.name().to_owned(),
                    item: item.id,
                };
                self.log(
                    mode,
                    QuarantineAction::Replace,
                    replaced.name(),
                    item,
                    &outcome,
                );
            }
        }
        tally.report(mode, self.history)
    }

    /// Deletes `items` for good.
    pub fn delete(&mut self, items: &[ItemRef]) -> QuarantineReport {
        let mode = self.executor.mode();
        let mut tally = Counter::default();
        for (name, ids) in by_batch(items) {
            let Some(mut batch) = self.open(name, ids.len(), &mut tally) else {
                continue;
            };
            for id in ids {
                if let Some(item) = held(&batch, id, &mut tally) {
                    self.delete_one(
                        mode,
                        QuarantineAction::Delete,
                        &mut batch,
                        &item,
                        &mut tally,
                    );
                }
            }
        }
        tally.report(mode, self.history)
    }

    /// Deletes every file whose time in quarantine is up. Run at startup.
    /// Batches that can't be read are left alone.
    pub fn delete_expired(&mut self, now: SystemTime) -> io::Result<QuarantineReport> {
        let mode = self.executor.mode();
        let now = unix_secs(now);
        let mut tally = Counter::default();
        for name in self.store.batch_names()? {
            let Ok(mut batch) = self.store.open_batch(&name) else {
                continue;
            };
            let expired: Vec<Item> = batch
                .manifest()
                .items
                .iter()
                .filter(|item| item.state == ItemState::Quarantined && item.expires_at <= now)
                .cloned()
                .collect();
            for item in expired {
                self.delete_one(
                    mode,
                    QuarantineAction::Expired,
                    &mut batch,
                    &item,
                    &mut tally,
                );
            }
        }
        Ok(tally.report(mode, self.history))
    }

    fn delete_one(
        &mut self,
        mode: Mode,
        action: QuarantineAction,
        batch: &mut Batch,
        item: &Item,
        tally: &mut Counter,
    ) {
        let name = batch.name().to_owned();
        let outcome = self.executor.purge(batch, item.id);
        if let Outcome::Deleted { freed } | Outcome::WouldDelete { freed } = outcome {
            tally.done.files += 1;
            tally.done.size += freed;
        }
        tally.note(&outcome);
        self.log(mode, action, &name, item, &outcome);
    }

    /// Opens a batch, or counts its `count` files as failed.
    fn open(&self, name: &str, count: usize, tally: &mut Counter) -> Option<Batch> {
        match self.store.open_batch(name) {
            Ok(batch) => Some(batch),
            Err(_) => {
                *tally.skipped.entry("failed").or_default() += count as u64;
                None
            }
        }
    }

    fn log(
        &mut self,
        mode: Mode,
        action: QuarantineAction,
        batch: &str,
        item: &Item,
        outcome: &Outcome,
    ) {
        let file = HeldFile {
            batch,
            item: item.id,
            path: &item.original_path,
            size: item.reclaimable(),
        };
        self.history.quarantine(mode, action, &file, outcome);
    }
}

/// The item, if it's still in quarantine; otherwise it's counted as
/// skipped.
fn held(batch: &Batch, id: u32, tally: &mut Counter) -> Option<Item> {
    let item = batch
        .item(id)
        .filter(|item| item.state == ItemState::Quarantined)
        .cloned();
    if item.is_none() {
        tally.note(&Outcome::Skipped {
            reason: SkipReason::NotInQuarantine,
        });
    }
    item
}

#[derive(Default)]
struct Counter {
    done: Tally,
    skipped: BTreeMap<&'static str, u64>,
}

impl Counter {
    fn note(&mut self, outcome: &Outcome) {
        if let Outcome::Skipped { reason } = outcome {
            *self.skipped.entry(reason.key()).or_default() += 1;
        }
    }

    fn report(self, mode: Mode, history: &History) -> QuarantineReport {
        let mut skipped: Vec<SkipCount> = self
            .skipped
            .into_iter()
            .map(|(reason, files)| SkipCount { reason, files })
            .collect();
        skipped.sort_by_key(|count| Reverse(count.files));
        QuarantineReport {
            mode,
            done: self.done,
            skipped,
            history_error: history.error().map(str::to_owned),
        }
    }
}

/// Items grouped by batch, each batch once, in a stable order.
fn by_batch(items: &[ItemRef]) -> BTreeMap<&str, Vec<u32>> {
    let mut groups: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for item in items {
        groups.entry(item.batch.as_str()).or_default().push(item.id);
    }
    groups
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
