//! The hard deny list (PLANNING.md §4.2).
//!
//! Nothing in a rule file can change this list. The few exceptions inside
//! protected folders are hardcoded here and reviewed like any other code
//! change.

use std::path::Path;

use serde::Serialize;

use crate::path::{NormPath, PathError};
use crate::system::SystemPaths;

/// Folders inside the Windows folder whose *contents* may be cleaned. The
/// folders themselves stay protected.
const WINDOWS_EXCEPTION_FOLDERS: &[&str] = &[
    "Temp",
    "Logs",
    "Minidump",
    "LiveKernelReports",
    r"SoftwareDistribution\Download",
];

/// Single files inside the Windows folder that may be cleaned.
const WINDOWS_EXCEPTION_FILES: &[&str] = &["MEMORY.DMP"];

/// Folders inside ProgramData whose contents may be cleaned.
const PROGRAM_DATA_EXCEPTION_FOLDERS: &[&str] = &[
    r"Microsoft\Windows\WER\ReportArchive",
    r"Microsoft\Windows\WER\ReportQueue",
];

/// Folders directly inside the user profile that rules may reach into.
/// Everything else in the profile (including files like `NTUSER.DAT`) is
/// protected.
const PROFILE_EXCEPTION_FOLDERS: &[&str] = &["AppData", "Downloads"];

/// Credential and key storage under AppData.
const ROAMING_SECRETS: &[&str] = &[
    r"Microsoft\Credentials",
    r"Microsoft\Protect",
    r"Microsoft\Crypto",
    r"Microsoft\SystemCertificates",
];
const LOCAL_SECRETS: &[&str] = &[r"Microsoft\Credentials", r"Microsoft\Vault"];

/// Names protected wherever they appear in a path (lowercase).
const PROTECTED_NAMES: &[&str] = &[
    "system volume information",
    "$recycle.bin",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    ".ssh",
    ".gnupg",
    ".openjanitor",
];

/// Browser and app profile files holding personal data (lowercase). They're
/// protected wherever they appear, so cleaning a cache never takes them along.
const PROFILE_DATA_FILES: &[&str] = &[
    "cookies",
    "cookies-journal",
    "login data",
    "login data-journal",
    "login data for account",
    "history",
    "history-journal",
    "web data",
    "web data-journal",
    "bookmarks",
    "preferences",
    "secure preferences",
    "local state",
    "key3.db",
    "key4.db",
    "logins.json",
    "cert9.db",
    "cookies.sqlite",
    "places.sqlite",
    "formhistory.sqlite",
];

/// Why the deny list refused a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum DenyReason {
    #[error("invalid path: {0}")]
    InvalidPath(PathError),
    #[error("drive roots are protected")]
    DriveRoot,
    #[error("the folder {0} itself is protected; only its contents can be cleaned")]
    ProtectedFolder(String),
    #[error("{0} is protected")]
    ProtectedTree(&'static str),
    #[error("{0:?} is a protected system or personal name")]
    ProtectedName(String),
    #[error("{0:?} holds personal profile data")]
    ProfileData(String),
}

/// A protected folder and everything inside it, minus its exceptions.
#[derive(Debug, Clone)]
struct Tree {
    root: NormPath,
    label: &'static str,
    exceptions: Vec<NormPath>,
}

/// The hard deny list, built from the machine's protected locations.
#[derive(Debug, Clone)]
pub struct DenyList {
    /// Folders that are protected themselves, while their contents may be
    /// cleaned.
    exact: Vec<NormPath>,
    trees: Vec<Tree>,
}

impl DenyList {
    /// Builds the deny list. Fails if a protected location can't be
    /// normalized: an incomplete deny list is never acceptable.
    pub fn new(system: &SystemPaths) -> Result<Self, PathError> {
        let mut list = Self {
            exact: Vec::new(),
            trees: Vec::new(),
        };

        let windows = NormPath::new(&system.windows)?;
        let mut exceptions = joined(&windows, WINDOWS_EXCEPTION_FOLDERS)?;
        list.exact.extend(exceptions.iter().cloned());
        exceptions.extend(joined(&windows, WINDOWS_EXCEPTION_FILES)?);
        list.tree(windows, "the Windows folder", exceptions);

        for program_files in &system.program_files {
            list.tree(NormPath::new(program_files)?, "Program Files", Vec::new());
        }

        let program_data = NormPath::new(&system.program_data)?;
        let exceptions = joined(&program_data, PROGRAM_DATA_EXCEPTION_FOLDERS)?;
        list.exact.extend(exceptions.iter().cloned());
        list.tree(program_data, "ProgramData", exceptions);

        // Other users' profiles and the Users folder itself.
        let user_profile = NormPath::new(&system.user_profile)?;
        list.tree(
            NormPath::new(&system.users_root)?,
            "other users' profiles",
            vec![user_profile.clone()],
        );

        let exceptions = joined(&user_profile, PROFILE_EXCEPTION_FOLDERS)?;
        list.exact.extend(exceptions.iter().cloned());
        list.exact.push(user_profile.join(r"AppData\LocalLow")?);
        list.tree(user_profile, "your user profile", exceptions);

        let roaming = NormPath::new(&system.roaming_app_data)?;
        let local = NormPath::new(&system.local_app_data)?;
        for secret in joined(&roaming, ROAMING_SECRETS)?
            .into_iter()
            .chain(joined(&local, LOCAL_SECRETS)?)
        {
            list.tree(secret, "credential and key storage", Vec::new());
        }
        list.exact.push(roaming);
        list.exact.push(local);

        for folder in &system.user_folders {
            list.tree(NormPath::new(folder)?, "your personal folders", Vec::new());
        }

        for own in [&system.app_data, &system.system_app_data] {
            list.tree(NormPath::new(own)?, "OpenJanitor's own data", Vec::new());
        }

        Ok(list)
    }

    fn tree(&mut self, root: NormPath, label: &'static str, exceptions: Vec<NormPath>) {
        self.trees.push(Tree {
            root,
            label,
            exceptions,
        });
    }

    /// Checks whether `path` may be deleted or moved.
    pub fn check(&self, path: &Path) -> Result<(), DenyReason> {
        let path = NormPath::new(path).map_err(DenyReason::InvalidPath)?;
        self.check_norm(&path)
    }

    /// Same as [`DenyList::check`], for an already normalized path.
    pub fn check_norm(&self, path: &NormPath) -> Result<(), DenyReason> {
        if path.is_drive_root() {
            return Err(DenyReason::DriveRoot);
        }
        if let Some(name) = path
            .components()
            .find(|name| PROTECTED_NAMES.contains(name))
        {
            return Err(DenyReason::ProtectedName(name.to_string()));
        }
        if let Some(name) = path
            .file_name()
            .filter(|name| PROFILE_DATA_FILES.contains(name))
        {
            return Err(DenyReason::ProfileData(name.to_string()));
        }
        if self.exact.contains(path) {
            return Err(DenyReason::ProtectedFolder(path.to_string()));
        }
        // When several protected folders contain the path, report the most
        // specific one ("your personal folders" rather than "your user
        // profile").
        let denying = self
            .trees
            .iter()
            .filter(|tree| {
                path.starts_with(&tree.root) && !tree.exceptions.iter().any(|e| path.starts_with(e))
            })
            .max_by_key(|tree| tree.root.depth());
        match denying {
            Some(tree) => Err(DenyReason::ProtectedTree(tree.label)),
            None => Ok(()),
        }
    }

    /// True when nothing inside `dir` could ever pass [`DenyList::check`], so
    /// a traversal can skip the whole folder.
    pub fn denies_subtree(&self, dir: &Path) -> bool {
        let Ok(dir) = NormPath::new(dir) else {
            return true;
        };
        if dir.components().any(|name| PROTECTED_NAMES.contains(&name)) {
            return true;
        }
        self.trees.iter().any(|tree| {
            dir.starts_with(&tree.root)
                && !tree
                    .exceptions
                    .iter()
                    .any(|e| dir.starts_with(e) || e.starts_with(&dir))
        })
    }
}

fn joined(base: &NormPath, relatives: &[&str]) -> Result<Vec<NormPath>, PathError> {
    relatives
        .iter()
        .map(|relative| base.join(relative))
        .collect()
}
