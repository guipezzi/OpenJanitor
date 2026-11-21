//! Shared helpers for integration tests. Everything happens inside fresh
//! temporary folders; nothing touches the real system.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

/// A fresh temporary folder and its long path. CI runners have 8.3 short
/// names in `%TEMP%` (`RUNNER~1`), which the safety layer rejects on
/// purpose, so tests always work with the expanded path.
pub fn temp_root() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = oj_windows::long_path(dir.path());
    (dir, path)
}

/// Writes a file of `bytes` bytes, creating parent folders.
pub fn write_file(path: &Path, bytes: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![b'x'; bytes]).unwrap();
}

/// Sets a file's modified time to `age` ago.
pub fn make_old(path: &Path, age: Duration) {
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - age).unwrap();
}

/// Creates a directory junction (no admin rights needed).
pub fn junction(link: &Path, target: &Path) {
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
