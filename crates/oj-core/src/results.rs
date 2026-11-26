//! The results tree the UI shows (PLANNING.md §7.1): Category → Rule →
//! Folder → File, built from a scan report.
//!
//! The UI loads the tree one level at a time and one page at a time, so a
//! scan with many thousands of files never reaches the webview at once.
//! Nodes are identified by number; the UI never sends a path back.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oj_safety::ProtectedList;
use serde::Serialize;

use crate::rule::Risk;
use crate::scan::{Finding, ScanReport, Target};

/// A node's number, valid for the results it came from.
pub type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Category,
    Rule,
    /// One of a rule's locations. Only used when a rule found files in more
    /// than one location; otherwise folders sit directly under the rule.
    Location,
    Folder,
    File,
    /// One drive's Recycle Bin. Like a file, it's cleaned as a whole; its
    /// name is the drive (`C:`) and its file count is the items in it.
    RecycleBin,
    /// One cleanup's files in quarantine (only in the quarantine tree).
    Batch,
}

/// A node as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeView {
    pub id: NodeId,
    pub kind: NodeKind,
    /// The category id, the rule name, the location path, the folder name,
    /// or the file name. A folder that only holds one subfolder is merged
    /// with it, and the name shows both (`Cache\Cache_Data`).
    pub name: String,
    /// The rule that found the files, for every node below a category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    /// Whether "Select recommended" may pick the rule (see `Rule`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended: Option<bool>,
    /// The built-in action of the rule, such as `recycle-bin`. A category
    /// has one when all its rules share it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtin: Option<String>,
    /// Something inside needs administrator rights to clean.
    pub needs_admin: bool,
    pub size_on_disk: u64,
    pub file_count: u64,
    /// The newest modification time inside, in seconds since the Unix epoch.
    pub last_modified: u64,
    /// The full path of a location, folder, or file. For display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Why a file was flagged, for the details panel.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Quarantine tree only: when the files went into quarantine, in
    /// seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_at: Option<u64>,
    /// Quarantine tree only: when the first of the files may be deleted for
    /// good, in seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub has_children: bool,
    /// Children sent ahead of time (the rules inside each category). Other
    /// children are fetched with [`ScanResults::children`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<NodeView>>,
}

/// One page of a node's children.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChildPage {
    pub items: Vec<NodeView>,
    /// How many children the node has in all.
    pub total: usize,
}

#[derive(Debug, Clone)]
struct Node {
    kind: NodeKind,
    name: String,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    /// Index into `report.rules`.
    rule: Option<usize>,
    path: Option<PathBuf>,
    /// Index into `report.findings`, for files.
    finding: Option<usize>,
    size_on_disk: u64,
    file_count: u64,
    last_modified: u64,
    needs_admin: bool,
    /// Protected after the scan, or left empty by that. Hidden nodes keep
    /// their ids, so the UI's other node ids stay valid.
    hidden: bool,
}

impl Node {
    fn new(kind: NodeKind, name: String, parent: Option<NodeId>) -> Self {
        Self {
            kind,
            name,
            parent,
            children: Vec::new(),
            rule: None,
            path: None,
            finding: None,
            size_on_disk: 0,
            file_count: 0,
            last_modified: 0,
            needs_admin: false,
            hidden: false,
        }
    }
}

/// Numbers each [`ScanResults`] built in this process.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A finished scan and its results tree.
#[derive(Debug)]
pub struct ScanResults {
    id: u64,
    report: ScanReport,
    nodes: Vec<Node>,
    categories: Vec<NodeId>,
    /// Each rule's protected-file count from the scan itself, before any
    /// [`hide_protected`](Self::hide_protected).
    protected_at_scan: Vec<u64>,
}

impl ScanResults {
    pub fn new(report: ScanReport) -> Self {
        let mut nodes = Vec::new();
        let categories = build(&report, &mut nodes);
        let protected_at_scan = report
            .rules
            .iter()
            .map(|rule| rule.skipped_user_protected)
            .collect();
        let mut results = Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            report,
            nodes,
            categories,
            protected_at_scan,
        };
        results.add_up();
        results.link_children();
        results.merge_folder_chains();
        results
    }

    /// Tells these results apart from any others built in this process, so
    /// a cleanup plan only ever runs against the results it was made from.
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    /// The findings a selection covers, as indices into
    /// `report().findings`, in tree order (category, rule, folder, file).
    ///
    /// `choices` are the UI's explicit choices by node id. A node without
    /// one follows its closest ancestor that has one; nodes with no such
    /// ancestor aren't selected. Hidden nodes are never included, and ids
    /// that aren't in the tree are ignored.
    pub fn selected(&self, choices: &HashMap<NodeId, bool>) -> Vec<usize> {
        let mut found = Vec::new();
        let mut pending: Vec<(NodeId, bool)> = self
            .categories
            .iter()
            .rev()
            .map(|&id| (id, false))
            .collect();
        while let Some((id, inherited)) = pending.pop() {
            let Some(node) = self.visible(id) else {
                continue;
            };
            let selected = choices.get(&id).copied().unwrap_or(inherited);
            match node.finding {
                Some(finding) if selected => found.push(finding),
                Some(_) => {}
                None => pending.extend(node.children.iter().rev().map(|&child| (child, selected))),
            }
        }
        found
    }

    /// The top level: categories, biggest first, each with its rules.
    pub fn categories(&self) -> Vec<NodeView> {
        self.categories
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

    /// One node, if it exists and isn't hidden.
    pub fn node(&self, id: NodeId) -> Option<NodeView> {
        self.visible(id).map(|_| self.view(id))
    }

    /// Up to `limit` children of `id`, starting at `offset`, biggest first.
    /// `None` if there's no such node (or it's hidden).
    pub fn children(&self, id: NodeId, offset: usize, limit: usize) -> Option<ChildPage> {
        let node = self.visible(id)?;
        let items = node
            .children
            .iter()
            .skip(offset)
            .take(limit)
            .map(|&child| self.view(child))
            .collect();
        Some(ChildPage {
            items,
            total: node.children.len(),
        })
    }

    /// The path of a location, folder, or file node.
    pub fn path(&self, id: NodeId) -> Option<&Path> {
        self.nodes.get(id as usize)?.path.as_deref()
    }

    /// Every finding inside `id`. Empty if there's no such node (or it's
    /// hidden). Hidden findings are never included.
    pub fn findings_under(&self, id: NodeId) -> Vec<&Finding> {
        let mut found = Vec::new();
        let mut pending = vec![id];
        while let Some(id) = pending.pop() {
            let Some(node) = self.visible(id) else {
                continue;
            };
            if let Some(finding) = node.finding {
                found.push(&self.report.findings[finding]);
            }
            pending.extend(&node.children);
        }
        found
    }

    /// Hides every file the Protected list covers (or whose rule it
    /// protects), then recomputes totals up the tree. Folders, rules, and
    /// categories left empty are hidden too. Returns how many files were
    /// hidden. Node ids don't change, so the UI keeps its selection.
    pub fn hide_protected(&mut self, protected: &ProtectedList) -> usize {
        let mut hidden = 0;
        for node in &mut self.nodes {
            let Some(index) = node.finding.filter(|_| !node.hidden) else {
                continue;
            };
            let finding = &self.report.findings[index];
            if protected.protects_rule(&finding.rule_id) || protected.covers(&finding.path) {
                node.hidden = true;
                hidden += 1;
            }
        }
        if hidden > 0 {
            self.recompute();
        }
        hidden
    }

    /// Recomputes every total, the child lists, and the report's per-rule
    /// numbers from the visible files.
    fn recompute(&mut self) {
        for node in self.nodes.iter_mut().filter(|node| node.finding.is_none()) {
            node.size_on_disk = 0;
            node.file_count = 0;
            node.last_modified = 0;
            node.needs_admin = false;
            node.hidden = false;
        }
        self.add_up();
        for node in self.nodes.iter_mut().filter(|node| node.finding.is_none()) {
            node.hidden = node.file_count == 0;
        }
        self.link_children();

        let mut per_rule = vec![(0u64, 0u64, 0u64); self.report.rules.len()];
        for node in self.nodes.iter().filter(|node| node.finding.is_some()) {
            if let Some(rule) = node.rule {
                let (files, size, protected) = &mut per_rule[rule];
                if node.hidden {
                    *protected += 1;
                } else {
                    *files += 1;
                    *size += node.size_on_disk;
                }
            }
        }
        for ((report, (files, size, hidden)), at_scan) in self
            .report
            .rules
            .iter_mut()
            .zip(per_rule)
            .zip(&self.protected_at_scan)
        {
            report.findings = files;
            report.size_on_disk = size;
            report.skipped_user_protected = at_scan + hidden;
        }
        self.report.findings_total = self.report.rules.iter().map(|r| r.findings).sum();
        self.report.size_on_disk_total = self.report.rules.iter().map(|r| r.size_on_disk).sum();
    }

    fn visible(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id as usize).filter(|node| !node.hidden)
    }

    fn view(&self, id: NodeId) -> NodeView {
        let node = &self.nodes[id as usize];
        let rule = node.rule.map(|index| &self.report.rules[index]);
        NodeView {
            id,
            kind: node.kind,
            name: node.name.clone(),
            rule_id: rule.map(|rule| rule.rule_id.clone()),
            risk: rule.map(|rule| rule.risk),
            recommended: rule.map(|rule| rule.recommended),
            builtin: match rule {
                Some(rule) => rule.builtin.clone(),
                None => self.shared_builtin(node),
            },
            needs_admin: node.needs_admin,
            size_on_disk: node.size_on_disk,
            file_count: node.file_count,
            last_modified: node.last_modified,
            path: node
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            evidence: node
                .finding
                .map(|index| self.report.findings[index].evidence.clone())
                .unwrap_or_default(),
            quarantined_at: None,
            expires_at: None,
            has_children: !node.children.is_empty(),
            children: None,
        }
    }

    /// The builtin all of a category's rules share, if they do.
    fn shared_builtin(&self, category: &Node) -> Option<String> {
        let mut builtins = category.children.iter().map(|&child| {
            let rule = self.nodes[child as usize].rule?;
            self.report.rules[rule].builtin.as_deref()
        });
        let first = builtins.next()??;
        builtins
            .all(|other| other == Some(first))
            .then(|| first.to_owned())
    }

    /// Adds every visible node's numbers into its parent. Children always
    /// come after their parent in `nodes`, so one backward pass is enough.
    fn add_up(&mut self) {
        for index in (0..self.nodes.len()).rev() {
            if self.nodes[index].hidden {
                continue;
            }
            let Some(parent) = self.nodes[index].parent else {
                continue;
            };
            let (size, files, modified, admin) = {
                let node = &self.nodes[index];
                (
                    node.size_on_disk,
                    node.file_count,
                    node.last_modified,
                    node.needs_admin,
                )
            };
            let parent = &mut self.nodes[parent as usize];
            parent.size_on_disk += size;
            parent.file_count += files;
            parent.last_modified = parent.last_modified.max(modified);
            parent.needs_admin |= admin;
        }
    }

    /// Fills in each node's visible children, biggest first, then by name.
    fn link_children(&mut self) {
        for node in &mut self.nodes {
            node.children.clear();
        }
        for index in 0..self.nodes.len() {
            if self.nodes[index].hidden {
                continue;
            }
            if let Some(parent) = self.nodes[index].parent {
                self.nodes[parent as usize].children.push(index as NodeId);
            }
        }
        self.categories
            .retain(|&id| !self.nodes[id as usize].hidden);
        let order = |nodes: &[Node], ids: &mut Vec<NodeId>| {
            ids.sort_by(|&a, &b| {
                let (a, b) = (&nodes[a as usize], &nodes[b as usize]);
                b.size_on_disk
                    .cmp(&a.size_on_disk)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
        };
        for index in 0..self.nodes.len() {
            let mut children = std::mem::take(&mut self.nodes[index].children);
            order(&self.nodes, &mut children);
            self.nodes[index].children = children;
        }
        let mut categories = std::mem::take(&mut self.categories);
        order(&self.nodes, &mut categories);
        self.categories = categories;
    }

    /// Merges a folder whose only content is one subfolder into that
    /// subfolder, so `Default\Cache\Cache_Data` takes one click, not three.
    fn merge_folder_chains(&mut self) {
        for index in 0..self.nodes.len() {
            loop {
                let node = &self.nodes[index];
                let [only] = node.children[..] else { break };
                if node.kind != NodeKind::Folder
                    || self.nodes[only as usize].kind != NodeKind::Folder
                {
                    break;
                }
                let child = std::mem::replace(
                    &mut self.nodes[only as usize],
                    Node::new(NodeKind::Folder, String::new(), None),
                );
                for &grandchild in &child.children {
                    self.nodes[grandchild as usize].parent = Some(index as NodeId);
                }
                let node = &mut self.nodes[index];
                node.name = format!("{}\\{}", node.name, child.name);
                node.path = child.path;
                node.children = child.children;
            }
        }
    }
}

/// Creates the nodes (without totals or child lists) and returns the
/// category ids.
fn build(report: &ScanReport, nodes: &mut Vec<Node>) -> Vec<NodeId> {
    let push = |nodes: &mut Vec<Node>, node: Node| {
        nodes.push(node);
        (nodes.len() - 1) as NodeId
    };

    let rule_index: HashMap<&str, usize> = report
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.rule_id.as_str(), index))
        .collect();
    let mut by_rule: Vec<Vec<usize>> = vec![Vec::new(); report.rules.len()];
    for (index, finding) in report.findings.iter().enumerate() {
        if let Some(&rule) = rule_index.get(finding.rule_id.as_str()) {
            by_rule[rule].push(index);
        }
    }

    let mut categories = Vec::new();
    let mut category_ids: HashMap<&str, NodeId> = HashMap::new();
    for (rule_index, findings) in by_rule.iter().enumerate() {
        if findings.is_empty() {
            continue;
        }
        let rule = &report.rules[rule_index];
        let category = *category_ids
            .entry(rule.category.as_str())
            .or_insert_with(|| {
                let id = push(
                    nodes,
                    Node::new(NodeKind::Category, rule.category.clone(), None),
                );
                categories.push(id);
                id
            });
        let mut rule_node = Node::new(NodeKind::Rule, rule.name.clone(), Some(category));
        rule_node.rule = Some(rule_index);
        let rule_id = push(nodes, rule_node);

        let mut roots: Vec<&Path> = Vec::new();
        for &index in findings {
            let finding = &report.findings[index];
            // Each Recycle Bin is its own node already, named after its drive.
            if matches!(finding.target, Target::RecycleBin { .. }) {
                continue;
            }
            let root = finding.root.as_path();
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        let mut location_ids: HashMap<&Path, NodeId> = HashMap::new();
        if roots.len() > 1 {
            for &root in &roots {
                let mut location = Node::new(
                    NodeKind::Location,
                    root.to_string_lossy().into_owned(),
                    Some(rule_id),
                );
                location.rule = Some(rule_index);
                location.path = Some(root.to_path_buf());
                location_ids.insert(root, push(nodes, location));
            }
        }

        let mut folder_ids: HashMap<(NodeId, OsString), NodeId> = HashMap::new();
        for &index in findings {
            let finding = &report.findings[index];
            if let Target::RecycleBin { drive, .. } = finding.target {
                let mut bin = Node::new(NodeKind::RecycleBin, format!("{drive}:"), Some(rule_id));
                bin.rule = Some(rule_index);
                bin.path = Some(finding.path.clone());
                bin.finding = Some(index);
                bin.size_on_disk = finding.size_on_disk;
                bin.file_count = finding.file_count;
                bin.needs_admin = finding.needs_admin;
                push(nodes, bin);
                continue;
            }
            let mut parent = location_ids
                .get(finding.root.as_path())
                .copied()
                .unwrap_or(rule_id);
            let relative = finding
                .path
                .strip_prefix(&finding.root)
                .unwrap_or(&finding.path);
            let mut parts: Vec<_> = relative.iter().collect();
            // A rule location that is itself a file has no relative parts.
            let file_name = parts
                .pop()
                .or_else(|| finding.path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| finding.path.to_string_lossy().into_owned());

            let mut folder_path = finding.root.clone();
            for part in parts {
                folder_path.push(part);
                let key = (parent, part.to_os_string());
                parent = match folder_ids.get(&key) {
                    Some(&id) => id,
                    None => {
                        let mut folder = Node::new(
                            NodeKind::Folder,
                            part.to_string_lossy().into_owned(),
                            Some(parent),
                        );
                        folder.rule = Some(rule_index);
                        folder.path = Some(folder_path.clone());
                        let id = push(nodes, folder);
                        folder_ids.insert(key, id);
                        id
                    }
                };
            }

            let mut file = Node::new(NodeKind::File, file_name, Some(parent));
            file.rule = Some(rule_index);
            file.path = Some(finding.path.clone());
            file.finding = Some(index);
            file.size_on_disk = finding.size_on_disk;
            file.file_count = 1;
            file.last_modified = finding.last_modified;
            file.needs_admin = finding.needs_admin;
            push(nodes, file);
        }
    }
    categories
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use oj_safety::{FileSnapshot, WalkStats};

    use super::*;
    use crate::rule::Level;
    use crate::scan::{RuleReport, RuleStatus};

    const TEMP: &str = r"C:\Users\me\AppData\Local\Temp";
    const WIN_TEMP: &str = r"C:\Windows\Temp";

    fn rule(id: &str, category: &str, risk: Risk, needs_admin: bool) -> RuleReport {
        RuleReport {
            rule_id: id.into(),
            name: format!("Rule {id}"),
            description: format!("What {id} cleans"),
            category: category.into(),
            level: Level::Simple,
            risk,
            recommended: true,
            needs_admin,
            builtin: None,
            app: None,
            status: RuleStatus::Scanned,
            roots: Vec::new(),
            findings: 0,
            size_on_disk: 0,
            skipped_recent: 0,
            skipped_duplicates: 0,
            skipped_user_protected: 0,
            walk: WalkStats::default(),
            warnings: Vec::new(),
        }
    }

    /// A report with the given rules and `(rule id, root, relative path,
    /// size)` findings.
    fn report(rules: Vec<RuleReport>, files: &[(&str, &str, &str, u64)]) -> ScanReport {
        let findings: Vec<Finding> = files
            .iter()
            .enumerate()
            .map(|(index, &(rule_id, root, relative, size))| {
                let rule = rules.iter().find(|r| r.rule_id == rule_id).unwrap();
                // An empty relative path means the location is the file itself.
                let path = if relative.is_empty() {
                    PathBuf::from(root)
                } else {
                    Path::new(root).join(relative)
                };
                Finding {
                    id: index as u64 + 1,
                    rule_id: rule_id.into(),
                    category: rule.category.clone(),
                    risk: rule.risk,
                    path: path.clone(),
                    root: root.into(),
                    size_on_disk: size,
                    file_count: 1,
                    last_modified: 1_000 + index as u64,
                    needs_admin: rule.needs_admin,
                    evidence: vec![format!("evidence for {relative}")],
                    target: Target::File(FileSnapshot {
                        path,
                        len: size,
                        allocated: size,
                        links: 1,
                        modified: UNIX_EPOCH,
                        file_id: Default::default(),
                    }),
                }
            })
            .collect();
        ScanReport {
            level: Level::Simple,
            findings_total: findings.len() as u64,
            size_on_disk_total: findings.iter().map(|f| f.size_on_disk).sum(),
            rules,
            findings,
            cancelled: false,
            drives: None,
        }
    }

    fn names(views: &[NodeView]) -> Vec<&str> {
        views.iter().map(|v| v.name.as_str()).collect()
    }

    fn all_children(results: &ScanResults, id: NodeId) -> Vec<NodeView> {
        results.children(id, 0, usize::MAX).unwrap().items
    }

    #[test]
    fn groups_categories_rules_folders_and_files_biggest_first() {
        let results = ScanResults::new(report(
            vec![
                rule("temp.user", "temporary-files", Risk::Low, false),
                rule("temp.system", "temporary-files", Risk::Low, true),
                rule("dumps", "crash-reports", Risk::Medium, false),
            ],
            &[
                ("temp.user", TEMP, "a.tmp", 100),
                ("temp.user", TEMP, r"setup\b.log", 300),
                ("temp.user", TEMP, r"setup\c.log", 50),
                ("temp.system", WIN_TEMP, "d.tmp", 20),
                ("dumps", r"C:\Dumps", "app.dmp", 1_000),
            ],
        ));

        let categories = results.categories();
        assert_eq!(names(&categories), ["crash-reports", "temporary-files"]);
        let temp = &categories[1];
        assert_eq!(temp.kind, NodeKind::Category);
        assert_eq!((temp.size_on_disk, temp.file_count), (470, 4));
        assert!(temp.needs_admin, "a rule inside needs admin");
        assert_eq!(temp.risk, None);

        let rules = temp.children.as_ref().unwrap();
        assert_eq!(names(rules), ["Rule temp.user", "Rule temp.system"]);
        assert_eq!(rules[0].risk, Some(Risk::Low));
        assert!(!rules[0].needs_admin);
        assert!(rules[1].needs_admin);
        assert_eq!(rules[0].path, None);

        let inside = all_children(&results, rules[0].id);
        assert_eq!(names(&inside), ["setup", "a.tmp"]);
        assert_eq!(inside[0].kind, NodeKind::Folder);
        assert_eq!((inside[0].size_on_disk, inside[0].file_count), (350, 2));
        assert_eq!(
            inside[0].path.as_deref(),
            Some(r"C:\Users\me\AppData\Local\Temp\setup")
        );
        assert_eq!(inside[0].rule_id.as_deref(), Some("temp.user"));

        let files = all_children(&results, inside[0].id);
        assert_eq!(names(&files), ["b.log", "c.log"]);
        assert_eq!(files[0].kind, NodeKind::File);
        assert!(!files[0].has_children);
        assert_eq!(files[0].evidence, ["evidence for setup\\b.log"]);
        assert_eq!(inside[0].last_modified, 1_002);
    }

    #[test]
    fn folders_holding_one_subfolder_are_merged() {
        let results = ScanResults::new(report(
            vec![rule("cache", "browser-caches", Risk::Low, false)],
            &[
                ("cache", TEMP, r"Default\Cache\Cache_Data\f_1", 10),
                ("cache", TEMP, r"Default\Cache\Cache_Data\f_2", 10),
                ("cache", TEMP, r"Default\Code Cache\js\index", 5),
            ],
        ));
        let rule = &results.categories()[0].children.clone().unwrap()[0];

        let top = all_children(&results, rule.id);
        assert_eq!(
            names(&top),
            ["Default"],
            "Default holds two folders, so it stays"
        );
        let inside = all_children(&results, top[0].id);
        assert_eq!(names(&inside), [r"Cache\Cache_Data", r"Code Cache\js"]);
        assert_eq!(
            inside[0].path.as_deref(),
            Some(r"C:\Users\me\AppData\Local\Temp\Default\Cache\Cache_Data")
        );
        assert_eq!(names(&all_children(&results, inside[0].id)), ["f_1", "f_2"]);
        assert_eq!(results.findings_under(inside[0].id).len(), 2);
        assert_eq!(
            results.path(inside[0].id),
            Some(Path::new(TEMP).join(r"Default\Cache\Cache_Data").as_path())
        );
        assert_eq!(results.path(rule.id), None, "rules have no single path");
        assert_eq!(results.path(9_999), None);
    }

    #[test]
    fn a_rule_with_several_locations_shows_each_one() {
        let results = ScanResults::new(report(
            vec![rule("logs", "logs", Risk::Medium, false)],
            &[
                ("logs", r"C:\A", "one.log", 10),
                ("logs", r"C:\B", "two.log", 30),
            ],
        ));
        let rule = &results.categories()[0].children.clone().unwrap()[0];
        let locations = all_children(&results, rule.id);
        assert_eq!(names(&locations), [r"C:\B", r"C:\A"]);
        assert!(locations.iter().all(|l| l.kind == NodeKind::Location));
        assert_eq!(names(&all_children(&results, locations[0].id)), ["two.log"]);
    }

    #[test]
    fn children_come_in_pages() {
        let files: Vec<(&str, &str, String, u64)> = (0..5)
            .map(|i| ("temp", TEMP, format!("f{i}.tmp"), 100 - i))
            .collect();
        let files: Vec<(&str, &str, &str, u64)> = files
            .iter()
            .map(|(r, root, name, size)| (*r, *root, name.as_str(), *size))
            .collect();
        let results = ScanResults::new(report(
            vec![rule("temp", "temporary-files", Risk::Low, false)],
            &files,
        ));
        let rule = &results.categories()[0].children.clone().unwrap()[0];

        let page = results.children(rule.id, 0, 2).unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(names(&page.items), ["f0.tmp", "f1.tmp"]);
        let page = results.children(rule.id, 4, 2).unwrap();
        assert_eq!(names(&page.items), ["f4.tmp"]);
        assert!(results.children(rule.id, 10, 2).unwrap().items.is_empty());
        assert_eq!(results.children(9_999, 0, 2), None);
    }

    #[test]
    fn findings_under_a_node_are_exactly_its_files() {
        let results = ScanResults::new(report(
            vec![
                rule("a", "one", Risk::Low, false),
                rule("b", "two", Risk::Low, false),
            ],
            &[
                ("a", TEMP, r"x\1.tmp", 1),
                ("a", TEMP, r"y\2.tmp", 1),
                ("b", WIN_TEMP, "3.tmp", 1),
            ],
        ));
        let one = results
            .categories()
            .into_iter()
            .find(|c| c.name == "one")
            .unwrap();
        let mut ids: Vec<u64> = results
            .findings_under(one.id)
            .iter()
            .map(|f| f.id)
            .collect();
        ids.sort();
        assert_eq!(ids, [1, 2]);
        assert!(results.findings_under(9_999).is_empty());
    }

    #[test]
    fn rules_that_found_nothing_are_left_out() {
        let results = ScanResults::new(report(
            vec![
                rule("empty", "temporary-files", Risk::Low, false),
                rule("full", "temporary-files", Risk::Low, false),
            ],
            &[("full", TEMP, "a.tmp", 1)],
        ));
        let categories = results.categories();
        assert_eq!(categories.len(), 1);
        assert_eq!(
            names(categories[0].children.as_ref().unwrap()),
            ["Rule full"]
        );
    }

    #[test]
    fn a_location_that_is_a_file_shows_the_file_by_name() {
        let results = ScanResults::new(report(
            vec![rule("dumps", "crash-reports", Risk::Low, true)],
            &[
                ("dumps", r"C:\Windows\MEMORY.DMP", "", 500),
                ("dumps", r"C:\Windows\Minidump", "mini.dmp", 5),
            ],
        ));
        let rule = &results.categories()[0].children.clone().unwrap()[0];
        let locations = all_children(&results, rule.id);
        assert_eq!(
            names(&locations),
            [r"C:\Windows\MEMORY.DMP", r"C:\Windows\Minidump"]
        );
        let file = &all_children(&results, locations[0].id)[0];
        assert_eq!(
            (file.kind, file.name.as_str()),
            (NodeKind::File, "MEMORY.DMP")
        );
    }

    #[test]
    fn protecting_after_the_scan_hides_items_and_updates_totals() {
        use oj_safety::{Entry, EntryKind};

        let mut results = ScanResults::new(report(
            vec![
                rule("temp.user", "temporary-files", Risk::Low, false),
                rule("dumps", "crash-reports", Risk::Low, false),
            ],
            &[
                ("temp.user", TEMP, r"keep\a.log", 100),
                ("temp.user", TEMP, r"keep\b.log", 50),
                ("temp.user", TEMP, "c.tmp", 10),
                ("dumps", r"C:\Dumps", "app.dmp", 1_000),
            ],
        ));
        let temp_rule = results
            .categories()
            .into_iter()
            .find(|c| c.name == "temporary-files")
            .unwrap()
            .children
            .unwrap()[0]
            .clone();
        let keep = all_children(&results, temp_rule.id)
            .into_iter()
            .find(|n| n.name == "keep")
            .unwrap();
        let entry = |kind, value: &str| Entry {
            kind,
            value: value.into(),
            label: None,
            added_at: 0,
        };
        let list = ProtectedList::from_entries(vec![
            entry(EntryKind::Folder, &format!(r"{TEMP}\Keep")),
            entry(EntryKind::Rule, "dumps"),
        ])
        .unwrap();

        assert_eq!(results.hide_protected(&list), 3);

        let categories = results.categories();
        assert_eq!(
            names(&categories),
            ["temporary-files"],
            "an emptied category goes away"
        );
        let rule = &categories[0].children.as_ref().unwrap()[0];
        assert_eq!(rule.id, temp_rule.id, "ids don't change");
        assert_eq!((rule.size_on_disk, rule.file_count), (10, 1));
        assert_eq!(names(&all_children(&results, rule.id)), ["c.tmp"]);
        assert!(results.node(keep.id).is_none());
        assert!(results.children(keep.id, 0, 10).is_none());
        assert!(results.findings_under(keep.id).is_empty());
        assert_eq!(results.findings_under(categories[0].id).len(), 1);

        let report = results.report();
        assert_eq!((report.findings_total, report.size_on_disk_total), (1, 10));
        assert_eq!(report.rules[0].findings, 1);
        assert_eq!(report.rules[0].skipped_user_protected, 2);
        assert_eq!(report.rules[1].findings, 0);
        assert_eq!(report.rules[1].skipped_user_protected, 1);

        assert_eq!(results.hide_protected(&list), 0, "nothing left to hide");
    }

    #[test]
    fn a_selection_follows_the_closest_choice() {
        let mut results = ScanResults::new(report(
            vec![
                rule("temp", "temporary-files", Risk::Low, false),
                rule("dumps", "crash-reports", Risk::Low, false),
            ],
            &[
                ("temp", TEMP, r"setup\a.log", 100),
                ("temp", TEMP, r"setup\b.log", 50),
                ("temp", TEMP, "c.tmp", 10),
                ("dumps", r"C:\Dumps", "app.dmp", 1_000),
            ],
        ));
        let path_of = |results: &ScanResults, indices: Vec<usize>| -> Vec<String> {
            indices
                .into_iter()
                .map(|i| {
                    let path = &results.report().findings[i].path;
                    path.file_name().unwrap().to_string_lossy().into_owned()
                })
                .collect()
        };
        let temp = results
            .categories()
            .into_iter()
            .find(|c| c.name == "temporary-files")
            .unwrap();
        let rule = temp.children.as_ref().unwrap()[0].clone();
        let setup = all_children(&results, rule.id)
            .into_iter()
            .find(|n| n.name == "setup")
            .unwrap();
        let b = all_children(&results, setup.id)
            .into_iter()
            .find(|n| n.name == "b.log")
            .unwrap();

        assert!(
            results.selected(&HashMap::new()).is_empty(),
            "nothing by default"
        );

        let choices = HashMap::from([(temp.id, true), (setup.id, false), (b.id, true)]);
        assert_eq!(
            path_of(&results, results.selected(&choices)),
            ["b.log", "c.tmp"]
        );

        let everything: HashMap<NodeId, bool> = results
            .categories()
            .iter()
            .map(|c| (c.id, true))
            .chain([(9_999, false)])
            .collect();
        assert_eq!(
            results.selected(&everything).len(),
            4,
            "unknown ids are ignored"
        );

        let list = ProtectedList::from_entries(vec![oj_safety::Entry {
            kind: oj_safety::EntryKind::Folder,
            value: format!(r"{TEMP}\setup"),
            label: None,
            added_at: 0,
        }])
        .unwrap();
        results.hide_protected(&list);
        assert_eq!(
            path_of(&results, results.selected(&choices)),
            ["c.tmp"],
            "hidden files are never selected, even with their own choice"
        );
    }

    #[test]
    fn each_results_has_its_own_id() {
        let a = ScanResults::new(report(Vec::new(), &[]));
        let b = ScanResults::new(report(Vec::new(), &[]));
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn an_empty_scan_has_no_categories() {
        let results = ScanResults::new(report(Vec::new(), &[]));
        assert!(results.categories().is_empty());
    }
}
