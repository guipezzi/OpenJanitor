//! Shared helpers for integration tests. Everything happens inside fresh
//! temporary folders; nothing touches the real system.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use oj_core::{Level, RuleSet, ScanOptions, ScanReport, Scanner};
use oj_safety::{DenyList, SystemPaths};
use tempfile::TempDir;

pub const OLD: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// A fake machine: a temp folder laid out like `SystemPaths::fake`, with
/// the rule variables pointing into it.
pub struct FakeMachine {
    _dir: TempDir,
    pub root: PathBuf,
    pub system: SystemPaths,
    pub vars: HashMap<String, PathBuf>,
}

impl FakeMachine {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        // CI runners have 8.3 short names in %TEMP%; use the long path.
        let root = oj_windows::long_path(dir.path());
        let system = SystemPaths::fake(&root);
        let vars = HashMap::from([
            ("TEMP".into(), system.local_app_data.join("Temp")),
            ("TMP".into(), system.local_app_data.join("Temp")),
            ("LOCALAPPDATA".into(), system.local_app_data.clone()),
            ("APPDATA".into(), system.roaming_app_data.clone()),
            ("USERPROFILE".into(), system.user_profile.clone()),
            ("WINDIR".into(), system.windows.clone()),
            ("SYSTEMROOT".into(), system.windows.clone()),
            ("PROGRAMDATA".into(), system.program_data.clone()),
        ]);
        Self {
            _dir: dir,
            root,
            system,
            vars,
        }
    }

    pub fn scan(&self, rules: &RuleSet) -> ScanReport {
        let deny = DenyList::new(&self.system).unwrap();
        let scanner = Scanner {
            rules,
            vars: &self.vars,
            deny: &deny,
        };
        scanner.scan(&ScanOptions::new(Level::Advanced))
    }

    /// Paths found for one rule, sorted.
    pub fn found(&self, rules: &RuleSet, rule_id: &str) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = self
            .scan(rules)
            .findings
            .into_iter()
            .filter(|f| f.rule_id == rule_id)
            .map(|f| f.path)
            .collect();
        found.sort();
        found
    }
}

/// Writes an 8 KB file (big enough to get disk clusters) and backdates it.
pub fn old_file(path: &Path) {
    write_file(path, 8192);
    set_age(path, OLD);
}

/// Writes an 8 KB file modified just now.
pub fn new_file(path: &Path) {
    write_file(path, 8192);
}

pub fn write_file(path: &Path, bytes: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![b'x'; bytes]).unwrap();
}

pub fn set_age(path: &Path, age: Duration) {
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - age).unwrap();
}

/// Creates a directory junction (no admin rights needed).
pub fn junction(link: &Path, target: &Path) {
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    let status = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .stdout(Stdio::null())
        .status()
        .expect("run mklink");
    assert!(status.success(), "mklink /J failed");
}
