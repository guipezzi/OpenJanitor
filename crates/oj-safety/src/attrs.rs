//! Classifying directory entries by their Windows file attributes.

use std::fs::Metadata;

use serde::Serialize;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x4_0000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

const CLOUD_BITS: u32 =
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

/// What an entry is, as far as cleaning is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryClass {
    File,
    Directory,
    /// Junction, symlink, mount point, or any other reparse point. Never
    /// entered and never deleted.
    ReparsePoint,
    /// OneDrive / Google Drive Files On-Demand placeholder. Deleting it can
    /// delete the file in the cloud, and reading it forces a download.
    CloudPlaceholder,
}

/// Classifies raw file attributes. Cloud placeholders are checked first,
/// because they're usually reparse points too.
pub fn classify(attributes: u32) -> EntryClass {
    if attributes & CLOUD_BITS != 0 {
        EntryClass::CloudPlaceholder
    } else if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryClass::ReparsePoint
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        EntryClass::Directory
    } else {
        EntryClass::File
    }
}

/// Classifies metadata obtained *without* following reparse points
/// (`fs::symlink_metadata` or `DirEntry::metadata`).
pub fn classify_metadata(metadata: &Metadata) -> EntryClass {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        classify(metadata.file_attributes())
    }
    #[cfg(not(windows))]
    {
        if metadata.file_type().is_symlink() {
            EntryClass::ReparsePoint
        } else if metadata.is_dir() {
            EntryClass::Directory
        } else {
            EntryClass::File
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_attributes() {
        assert_eq!(classify(0x20), EntryClass::File);
        assert_eq!(classify(FILE_ATTRIBUTE_DIRECTORY), EntryClass::Directory);
        assert_eq!(
            classify(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT),
            EntryClass::ReparsePoint
        );
        assert_eq!(
            classify(FILE_ATTRIBUTE_REPARSE_POINT),
            EntryClass::ReparsePoint
        );
    }

    #[test]
    fn cloud_placeholders_win_over_reparse_points() {
        for bit in [
            FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ] {
            assert_eq!(classify(bit), EntryClass::CloudPlaceholder);
            assert_eq!(
                classify(bit | FILE_ATTRIBUTE_REPARSE_POINT),
                EntryClass::CloudPlaceholder
            );
        }
    }
}
