//! Lexical path normalization for safety checks.
//!
//! Paths are compared component by component, case-insensitively, without
//! touching the filesystem. Anything that can't be reasoned about safely is
//! rejected instead of guessed at:
//!
//! - relative paths, `.` and `..`
//! - network shares and device paths
//! - 8.3 short names (`PROGRA~1`), which could hide a protected folder
//! - alternate data streams (`file.txt:stream`)
//! - reserved device names (`NUL`, `COM1`, …)
//! - names ending in a dot or a space, which Windows silently strips
//!   (`C:\Windows.\System32` really means `C:\Windows\System32`)

use std::fmt;
use std::path::{Component, Path, Prefix};

use serde::Serialize;

/// A normalized, absolute path on a local drive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormPath {
    drive: char,
    parts: Vec<String>,
}

/// Why a path was rejected by [`NormPath::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum PathError {
    #[error("the path is not absolute")]
    NotAbsolute,
    #[error("network shares and device paths are not supported")]
    Unsupported,
    #[error("the path contains '.' or '..'")]
    Traversal,
    #[error("the path contains a name Windows would reinterpret: {0:?}")]
    Ambiguous(String),
    #[error("the path contains an 8.3 short name ({0:?}); expand it to its long form first")]
    ShortName(String),
    #[error("the path is not valid Unicode")]
    NotUnicode,
}

impl NormPath {
    /// Normalizes an absolute local path, or explains why it can't.
    pub fn new(path: &Path) -> Result<Self, PathError> {
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                    char::from(letter).to_ascii_lowercase()
                }
                _ => return Err(PathError::Unsupported),
            },
            _ => return Err(PathError::NotAbsolute),
        };
        // `C:foo` (no root) is relative to the drive's current directory.
        if components.next() != Some(Component::RootDir) {
            return Err(PathError::NotAbsolute);
        }
        let mut parts = Vec::new();
        for component in components {
            match component {
                Component::Normal(name) => {
                    let name = name.to_str().ok_or(PathError::NotUnicode)?;
                    parts.push(normalize_component(name)?);
                }
                Component::CurDir | Component::ParentDir => return Err(PathError::Traversal),
                Component::Prefix(_) | Component::RootDir => return Err(PathError::Unsupported),
            }
        }
        Ok(Self { drive, parts })
    }

    /// Appends a relative path written with `\` or `/` separators.
    pub fn join(&self, relative: &str) -> Result<Self, PathError> {
        let mut joined = self.clone();
        for name in relative.split(['\\', '/']).filter(|name| !name.is_empty()) {
            joined.parts.push(normalize_component(name)?);
        }
        Ok(joined)
    }

    /// The lowercase drive letter.
    pub fn drive(&self) -> char {
        self.drive
    }

    /// True for `C:\` itself.
    pub fn is_drive_root(&self) -> bool {
        self.parts.is_empty()
    }

    /// Number of components after the drive root.
    pub fn depth(&self) -> usize {
        self.parts.len()
    }

    /// True if `self` is `base` or lives anywhere inside it.
    pub fn starts_with(&self, base: &NormPath) -> bool {
        self.drive == base.drive
            && self.parts.len() >= base.parts.len()
            && self.parts.iter().zip(&base.parts).all(|(a, b)| a == b)
    }

    /// The last component, lowercased.
    pub fn file_name(&self) -> Option<&str> {
        self.parts.last().map(String::as_str)
    }

    /// All components after the drive root, lowercased.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().map(String::as_str)
    }
}

impl fmt::Display for NormPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:\\{}", self.drive, self.parts.join("\\"))
    }
}

fn normalize_component(name: &str) -> Result<String, PathError> {
    if name == "." || name == ".." {
        return Err(PathError::Traversal);
    }
    if name.ends_with('.')
        || name.ends_with(' ')
        || name.contains(':')
        || is_reserved_device_name(name)
    {
        return Err(PathError::Ambiguous(name.to_string()));
    }
    if is_short_name(name) {
        return Err(PathError::ShortName(name.to_string()));
    }
    Ok(name.to_lowercase())
}

/// `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or without
/// an extension.
fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.len() == 4 && stem.starts_with(prefix) && matches!(stem.as_bytes()[3], b'1'..=b'9')
    };
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || numbered("COM") || numbered("LPT")
}

/// Recognizes names shaped like generated 8.3 aliases (`PROGRA~1`,
/// `DOCUME~2.TXT`). A real long name with that shape is rare; rejecting it
/// only means the file is skipped.
fn is_short_name(name: &str) -> bool {
    let (base, ext) = match name.rsplit_once('.') {
        Some((base, ext)) => (base, Some(ext)),
        None => (name, None),
    };
    if ext.is_some_and(|ext| ext.is_empty() || ext.len() > 3) {
        return false;
    }
    let Some((head, digits)) = base.rsplit_once('~') else {
        return false;
    };
    !head.is_empty()
        && base.len() <= 8
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(path: &str) -> Result<NormPath, PathError> {
        NormPath::new(Path::new(path))
    }

    #[test]
    fn normalizes_case_and_verbatim_prefix() {
        let plain = norm(r"C:\Windows\System32").unwrap();
        assert_eq!(norm(r"c:\WINDOWS\system32").unwrap(), plain);
        assert_eq!(norm(r"\\?\C:\Windows\System32").unwrap(), plain);
        assert_eq!(norm("C:/Windows/System32").unwrap(), plain);
        assert_eq!(plain.to_string(), r"c:\windows\system32");
    }

    #[test]
    fn rejects_relative_and_drive_relative_paths() {
        assert_eq!(norm(r"Windows\System32"), Err(PathError::NotAbsolute));
        assert_eq!(norm(r"C:Windows"), Err(PathError::NotAbsolute));
        assert_eq!(norm(r"\Windows"), Err(PathError::NotAbsolute));
    }

    #[test]
    fn rejects_network_and_device_paths() {
        assert_eq!(norm(r"\\server\share\file"), Err(PathError::Unsupported));
        assert_eq!(
            norm(r"\\?\UNC\server\share\file"),
            Err(PathError::Unsupported)
        );
        assert_eq!(norm(r"\\.\C:\file"), Err(PathError::Unsupported));
    }

    #[test]
    fn rejects_traversal() {
        assert_eq!(norm(r"C:\Temp\..\Windows"), Err(PathError::Traversal));
        assert_eq!(norm(r"\\?\C:\Temp\..\Windows"), Err(PathError::Traversal));
    }

    #[test]
    fn rejects_names_windows_would_reinterpret() {
        assert!(matches!(
            norm(r"C:\Windows.\System32"),
            Err(PathError::Ambiguous(_))
        ));
        assert!(matches!(
            norm(r"C:\Windows \System32"),
            Err(PathError::Ambiguous(_))
        ));
        assert!(matches!(
            norm(r"C:\Temp\file.txt:stream"),
            Err(PathError::Ambiguous(_))
        ));
        assert!(matches!(
            norm(r"C:\Temp\nul.txt"),
            Err(PathError::Ambiguous(_))
        ));
        assert!(matches!(
            norm(r"C:\Temp\COM1"),
            Err(PathError::Ambiguous(_))
        ));
        assert!(norm(r"C:\Temp\COM10").is_ok());
        assert!(norm(r"C:\Temp\console.log").is_ok());
    }

    #[test]
    fn rejects_short_names() {
        assert!(matches!(
            norm(r"C:\PROGRA~1\App"),
            Err(PathError::ShortName(_))
        ));
        assert!(matches!(
            norm(r"C:\Users\GUILHE~1\x"),
            Err(PathError::ShortName(_))
        ));
        assert!(matches!(
            norm(r"C:\Temp\DOCUME~2.TXT"),
            Err(PathError::ShortName(_))
        ));
        // Common temp-file names that only look similar are fine.
        assert!(norm(r"C:\Temp\~DF3A1B.tmp").is_ok());
        assert!(norm(r"C:\Temp\~$report.docx").is_ok());
        assert!(norm(r"C:\Temp\backup~old").is_ok());
    }

    #[test]
    fn starts_with_compares_whole_components() {
        let windows = norm(r"C:\Windows").unwrap();
        assert!(norm(r"C:\Windows\Temp").unwrap().starts_with(&windows));
        assert!(norm(r"C:\Windows").unwrap().starts_with(&windows));
        assert!(!norm(r"C:\WindowsApps\x").unwrap().starts_with(&windows));
        assert!(!norm(r"D:\Windows\x").unwrap().starts_with(&windows));
    }

    #[test]
    fn join_checks_every_component() {
        let base = norm(r"C:\Windows").unwrap();
        assert_eq!(
            base.join(r"SoftwareDistribution\Download").unwrap(),
            norm(r"C:\Windows\SoftwareDistribution\Download").unwrap()
        );
        assert_eq!(base.join(r"..\Users"), Err(PathError::Traversal));
    }
}
