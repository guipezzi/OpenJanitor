//! Saving OpenJanitor's own files (manifests, the Protected list, ...).

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Writes `bytes` to `path` so that a crash or power cut leaves either the
/// old file or the new one, never half of either: the data goes to
/// `<path>.tmp` first, is flushed to disk, and then replaces `path` in one
/// rename. Missing parent folders are created.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = tmp_path(path);
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

/// `<path>.tmp`, the scratch file [`write_atomic`] uses.
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".tmp");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_whole_file_and_leaves_no_scratch_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(r"sub\settings.json");
        write_atomic(&path, b"first, longer version").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(!tmp_path(&path).exists());
    }
}
