//! The Protected list (PLANNING.md §7.2): things the user never wants
//! cleaned, usually false positives.
//!
//! An entry is a file, a folder (with everything inside), a glob pattern
//! (`*.psd`, or a full-path pattern like `D:\Projects\**`), or a whole
//! rule. Protected items never show up in results, and the executor
//! refuses them even if something asks.
//!
//! The list is saved as `protected.json` in OpenJanitor's data folder. If
//! that file exists but can't be read, callers must refuse to scan or
//! clean rather than act as if nothing were protected.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::path::NormPath;
use crate::persist::write_atomic;

/// The `protected.json` format written by this version.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    /// A folder and everything inside it.
    Folder,
    /// A glob pattern. Without a `\` or `/` it matches file names
    /// anywhere (`*.psd`); with one, it matches full paths
    /// (`D:\Projects\**`).
    Pattern,
    /// Every finding of a rule, by rule id.
    Rule,
}

/// One protected item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub kind: EntryKind,
    /// The path, pattern, or rule id.
    pub value: String,
    /// What to show instead of `value`, such as a rule's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Seconds since the Unix epoch.
    #[serde(default)]
    pub added_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtectedError {
    #[error("couldn't read the file: {0}")]
    Io(#[from] io::Error),
    #[error("the file isn't valid: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("the file was written by a newer version of OpenJanitor (format {0})")]
    NewerVersion(u32),
    #[error("{0}")]
    InvalidEntry(String),
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    entries: Vec<Entry>,
}

/// The user's protected items, ready to match paths and rules.
#[derive(Debug, Clone, Default)]
pub struct ProtectedList {
    entries: Vec<Entry>,
    paths: Vec<NormPath>,
    names: GlobSet,
    full_paths: GlobSet,
    rules: HashSet<String>,
}

impl ProtectedList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a list, checking every entry.
    pub fn from_entries(entries: Vec<Entry>) -> Result<Self, ProtectedError> {
        let mut list = Self::new();
        for entry in entries {
            list.add(entry)?;
        }
        Ok(list)
    }

    /// Reads `protected.json`. A missing file is an empty list; a damaged
    /// one is an error, never an empty list.
    pub fn load(path: &Path) -> Result<Self, ProtectedError> {
        match fs::read(path) {
            Ok(bytes) => Self::from_json(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        write_atomic(path, &self.to_json())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ProtectedError> {
        let file: FileFormat = serde_json::from_slice(bytes)?;
        if file.version > FORMAT_VERSION {
            return Err(ProtectedError::NewerVersion(file.version));
        }
        Self::from_entries(file.entries)
    }

    pub fn to_json(&self) -> Vec<u8> {
        let file = FileFormat {
            version: FORMAT_VERSION,
            entries: self.entries.clone(),
        };
        serde_json::to_vec_pretty(&file).expect("the Protected list always serializes")
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds an entry. Returns `false` if the same thing is already
    /// protected.
    pub fn add(&mut self, mut entry: Entry) -> Result<bool, ProtectedError> {
        let invalid = |message: String| ProtectedError::InvalidEntry(message);
        entry.value = entry.value.trim().to_owned();
        if entry.value.is_empty() {
            return Err(invalid("an empty entry can't protect anything".into()));
        }
        if self.contains(entry.kind, &entry.value) {
            return Ok(false);
        }
        match entry.kind {
            EntryKind::File | EntryKind::Folder => {
                let path = NormPath::new(Path::new(&entry.value))
                    .map_err(|e| invalid(format!("{:?} isn't a usable path: {e}", entry.value)))?;
                self.paths.push(path);
            }
            EntryKind::Pattern => {
                // Validate first, then rebuild the sets with it.
                glob(&entry.value).map_err(|e| {
                    invalid(format!("{:?} isn't a valid pattern: {e}", entry.value))
                })?;
            }
            EntryKind::Rule => {
                self.rules.insert(entry.value.clone());
            }
        }
        let is_pattern = entry.kind == EntryKind::Pattern;
        self.entries.push(entry);
        if is_pattern {
            self.rebuild_patterns();
        }
        Ok(true)
    }

    /// Removes an entry. Returns whether it was there.
    pub fn remove(&mut self, kind: EntryKind, value: &str) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|entry| !(entry.kind == kind && same_value(kind, &entry.value, value)));
        if self.entries.len() == before {
            return false;
        }
        let entries = std::mem::take(&mut self.entries);
        *self = Self::from_entries(entries).expect("the remaining entries were already valid");
        true
    }

    /// Adds every entry of `other` that isn't here yet. Returns how many
    /// were added.
    pub fn merge(&mut self, other: &ProtectedList) -> usize {
        other
            .entries
            .iter()
            .filter(|entry| self.add((*entry).clone()).unwrap_or(false))
            .count()
    }

    /// Whether a file at `path` is protected by a file, folder, or pattern
    /// entry. Paths that can't be normalized count as protected.
    pub fn covers(&self, path: &Path) -> bool {
        match NormPath::new(path) {
            Ok(path) => self.covers_norm(&path),
            Err(_) => true,
        }
    }

    pub fn covers_norm(&self, path: &NormPath) -> bool {
        if self
            .paths
            .iter()
            .any(|protected| path.starts_with(protected))
        {
            return true;
        }
        if let Some(name) = path.file_name()
            && self.names.is_match(name)
        {
            return true;
        }
        let full = format!(
            "{}:/{}",
            path.drive(),
            path.components().collect::<Vec<_>>().join("/")
        );
        self.full_paths.is_match(full)
    }

    pub fn protects_rule(&self, rule_id: &str) -> bool {
        self.rules.contains(rule_id)
    }

    fn contains(&self, kind: EntryKind, value: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.kind == kind && same_value(kind, &entry.value, value))
    }

    fn rebuild_patterns(&mut self) {
        let mut names = GlobSetBuilder::new();
        let mut full_paths = GlobSetBuilder::new();
        for entry in self.entries.iter().filter(|e| e.kind == EntryKind::Pattern) {
            let Ok(compiled) = glob(&entry.value) else {
                continue;
            };
            if is_full_path_pattern(&entry.value) {
                full_paths.add(compiled);
            } else {
                names.add(compiled);
            }
        }
        self.names = names.build().unwrap_or_default();
        self.full_paths = full_paths.build().unwrap_or_default();
    }
}

/// Paths compare case-insensitively, like Windows; patterns and rule ids
/// compare exactly.
fn same_value(kind: EntryKind, a: &str, b: &str) -> bool {
    match kind {
        EntryKind::File | EntryKind::Folder => {
            match (NormPath::new(Path::new(a)), NormPath::new(Path::new(b))) {
                (Ok(a), Ok(b)) => a == b,
                _ => a.eq_ignore_ascii_case(b),
            }
        }
        EntryKind::Pattern | EntryKind::Rule => a == b,
    }
}

fn is_full_path_pattern(pattern: &str) -> bool {
    pattern.contains(['\\', '/'])
}

/// Compiles a pattern. Backslashes are path separators on Windows, so
/// they're turned into `/` and never treated as escapes.
fn glob(pattern: &str) -> Result<Glob, globset::Error> {
    GlobBuilder::new(&pattern.replace('\\', "/"))
        .case_insensitive(true)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: EntryKind, value: &str) -> Entry {
        Entry {
            kind,
            value: value.into(),
            label: None,
            added_at: 0,
        }
    }

    fn list(entries: &[(EntryKind, &str)]) -> ProtectedList {
        ProtectedList::from_entries(entries.iter().map(|(k, v)| entry(*k, v)).collect()).unwrap()
    }

    fn covers(list: &ProtectedList, path: &str) -> bool {
        list.covers(Path::new(path))
    }

    #[test]
    fn folders_protect_everything_inside() {
        let l = list(&[(EntryKind::Folder, r"C:\Users\me\AppData\Local\Temp\Keep")]);
        assert!(covers(&l, r"C:\Users\me\AppData\Local\Temp\Keep"));
        assert!(covers(
            &l,
            r"C:\Users\me\AppData\Local\Temp\keep\deep\a.log"
        ));
        assert!(!covers(&l, r"C:\Users\me\AppData\Local\Temp\Keeper\a.log"));
        assert!(!covers(&l, r"C:\Users\me\AppData\Local\Temp\other.log"));
    }

    #[test]
    fn files_protect_only_themselves() {
        let l = list(&[(EntryKind::File, r"C:\Temp\setup.log")]);
        assert!(covers(&l, r"c:\temp\SETUP.LOG"));
        assert!(!covers(&l, r"C:\Temp\setup.log.old"));
    }

    #[test]
    fn name_patterns_match_anywhere() {
        let l = list(&[(EntryKind::Pattern, "*.psd")]);
        assert!(covers(&l, r"C:\Temp\art\Poster.PSD"));
        assert!(!covers(&l, r"C:\Temp\art\poster.psd.tmp"));
    }

    #[test]
    fn full_path_patterns_match_whole_paths() {
        let l = list(&[(EntryKind::Pattern, r"D:\Projects\**\*.log")]);
        assert!(covers(&l, r"D:\Projects\app\build\out.log"));
        assert!(!covers(&l, r"C:\Projects\app\out.log"));
        assert!(!covers(&l, r"D:\Projects\app\out.txt"));
    }

    #[test]
    fn rules_are_protected_by_id() {
        let l = list(&[(EntryKind::Rule, "app.discord.cache")]);
        assert!(l.protects_rule("app.discord.cache"));
        assert!(!l.protects_rule("app.slack.cache"));
        assert!(!covers(&l, r"C:\anything.txt"));
    }

    #[test]
    fn unusable_paths_count_as_protected() {
        let l = ProtectedList::new();
        assert!(covers(&l, r"relative\path.txt"));
        assert!(!covers(&l, r"C:\Temp\a.txt"));
    }

    #[test]
    fn duplicates_are_ignored_and_bad_entries_refused() {
        let mut l = list(&[(EntryKind::Folder, r"C:\Temp\Keep")]);
        assert!(!l.add(entry(EntryKind::Folder, r"c:\temp\keep")).unwrap());
        assert!(l.add(entry(EntryKind::Folder, r"relative")).is_err());
        assert!(l.add(entry(EntryKind::Pattern, "[unclosed")).is_err());
        assert!(l.add(entry(EntryKind::Pattern, "   ")).is_err());
        assert_eq!(l.entries().len(), 1);
    }

    #[test]
    fn removing_an_entry_stops_protecting() {
        let mut l = list(&[
            (EntryKind::Pattern, "*.psd"),
            (EntryKind::Folder, r"C:\Keep"),
        ]);
        assert!(l.remove(EntryKind::Pattern, "*.psd"));
        assert!(!covers(&l, r"C:\Temp\a.psd"));
        assert!(covers(&l, r"C:\Keep\a.psd"));
        assert!(!l.remove(EntryKind::Pattern, "*.psd"));
    }

    #[test]
    fn saves_loads_and_merges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected.json");
        assert!(
            ProtectedList::load(&path).unwrap().is_empty(),
            "no file yet"
        );

        let l = list(&[
            (EntryKind::Pattern, "*.psd"),
            (EntryKind::Rule, "app.slack.cache"),
        ]);
        l.save(&path).unwrap();
        let loaded = ProtectedList::load(&path).unwrap();
        assert_eq!(loaded.entries(), l.entries());

        let mut other = list(&[
            (EntryKind::Rule, "app.slack.cache"),
            (EntryKind::File, r"C:\a.txt"),
        ]);
        assert_eq!(other.merge(&loaded), 1);
        assert_eq!(other.entries().len(), 3);
    }

    #[test]
    fn a_damaged_file_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected.json");
        fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(
            ProtectedList::load(&path),
            Err(ProtectedError::Parse(_))
        ));
        fs::write(&path, br#"{"version": 7, "entries": []}"#).unwrap();
        assert!(matches!(
            ProtectedList::load(&path),
            Err(ProtectedError::NewerVersion(7))
        ));
        fs::write(
            &path,
            br#"{"version": 1, "entries": [{"kind": "folder", "value": "nope"}]}"#,
        )
        .unwrap();
        assert!(matches!(
            ProtectedList::load(&path),
            Err(ProtectedError::InvalidEntry(_))
        ));
    }
}
