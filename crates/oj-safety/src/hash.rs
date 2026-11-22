//! Content fingerprints, computed only when a feature needs one (D21).
//!
//! Scanning and quarantining never read file contents. Features that do
//! need to compare contents (checking a copy between drives, telling
//! whether a restore conflict is the same file) call this on demand.

use std::fs::File;
use std::io;
use std::path::Path;

/// The BLAKE3 hash of a file's contents, as lowercase hex.
pub fn content_hash(path: &Path) -> io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(File::open(path)?)?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_vector() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("abc.txt");
        std::fs::write(&file, b"abc").unwrap();
        // BLAKE3 test vector for "abc".
        assert_eq!(
            content_hash(&file).unwrap(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }
}
