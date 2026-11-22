//! The results tree the UI shows (PLANNING.md §7.1): Category → Rule →
//! Folder → File, built from a scan report.
//!
//! The UI loads the tree one level at a time and one page at a time, so a
//! scan with many thousands of files never reaches the webview at once.
//! Nodes are identified by number; the UI never sends a path back.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::rule::Risk;
use crate::scan::{Finding, ScanReport};

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
        }
    }
}

/// A finished scan and its results tree.
#[derive(Debug)]
pub struct ScanResults {
    report: ScanReport,
    nodes: Vec<Node>,
    categories: Vec<NodeId>,
}

impl ScanResults {
    pub fn new(report: ScanReport) -> Self {
        let mut nodes = Vec::new();
        let categories = build(&report, &mut nodes);
        let mut results = Self {
            report,
            nodes,
            categories,
        };
        results.add_up();
        results.link_children();
        results.merge_folder_chains();
        results
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
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

    /// Up to `limit` children of `id`, starting at `offset`, biggest first.
    /// `None` if there's no such node.
    pub fn children(&self, id: NodeId, offset: usize, limit: usize) -> Option<ChildPage> {
        let node = self.nodes.get(id as usize)?;
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

    /// Every finding inside `id`. Empty if there's no such node.
    pub fn findings_under(&self, id: NodeId) -> Vec<&Finding> {
        let mut found = Vec::new();
        let mut pending = vec![id];
        while let Some(id) = pending.pop() {
            let Some(node) = self.nodes.get(id as usize) else {
                continue;
            };
            if let Some(finding) = node.finding {
                found.push(&self.report.findings[finding]);
            }
            pending.extend(&node.children);
        }
        found
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
            has_children: !node.children.is_empty(),
            children: None,
        }
    }

    /// Adds every node's numbers into its parent. Children always come
    /// after their parent in `nodes`, so one backward pass is enough.
    fn add_up(&mut self) {
        for index in (0..self.nodes.len()).rev() {
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

    /// Fills in each node's children, biggest first, then by name.
    fn link_children(&mut self) {
        for index in 0..self.nodes.len() {
            if let Some(parent) = self.nodes[index].parent {
                self.nodes[parent as usize].children.push(index as NodeId);
            }
        }
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
            let root = report.findings[index].root.as_path();
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
            let mut parent = location_ids
                .get(finding.root.as_path())
                .copied()
                .unwrap_or(rule_id);
            let relative = finding
                .path
                .strip_prefix(&finding.root)
                .unwrap_or(&finding.path);
            let mut parts: Vec<_> = relative.iter().collect();
            let file_name = parts
                .pop()
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
            needs_admin,
            status: RuleStatus::Scanned,
            roots: Vec::new(),
            findings: 0,
            size_on_disk: 0,
            skipped_recent: 0,
            skipped_duplicates: 0,
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
                let path = Path::new(root).join(relative);
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
                    snapshot: FileSnapshot {
                        path,
                        len: size,
                        allocated: size,
                        links: 1,
                        modified: UNIX_EPOCH,
                    },
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
    fn an_empty_scan_has_no_categories() {
        let results = ScanResults::new(report(Vec::new(), &[]));
        assert!(results.categories().is_empty());
    }
}
