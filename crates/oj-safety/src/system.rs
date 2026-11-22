//! The protected system locations the deny list is built from.

use std::path::{Path, PathBuf};

use oj_windows::{KnownFolder, known_folder, long_path};

/// Locations on this machine that the deny list protects.
///
/// Production code uses [`SystemPaths::discover`]. Tests use
/// [`SystemPaths::fake`], so they never depend on, or touch, the real system.
#[derive(Debug, Clone)]
pub struct SystemPaths {
    /// `C:\Windows`
    pub windows: PathBuf,
    /// `C:\Program Files` and `C:\Program Files (x86)`
    pub program_files: Vec<PathBuf>,
    /// `C:\ProgramData`
    pub program_data: PathBuf,
    /// `C:\Users`
    pub users_root: PathBuf,
    /// `C:\Users\<name>`
    pub user_profile: PathBuf,
    /// `C:\Users\<name>\AppData\Roaming`
    pub roaming_app_data: PathBuf,
    /// `C:\Users\<name>\AppData\Local`
    pub local_app_data: PathBuf,
    /// Desktop, Documents, Pictures, Music, Videos, and OneDrive roots.
    pub user_folders: Vec<PathBuf>,
    /// OpenJanitor's own data folder, for this user
    /// (`%LOCALAPPDATA%\OpenJanitor`).
    pub app_data: PathBuf,
    /// OpenJanitor's machine-wide data folder, which only administrators
    /// can change (`%PROGRAMDATA%\OpenJanitor`).
    pub system_app_data: PathBuf,
}

/// A protected location couldn't be found. Without it the deny list would be
/// incomplete, so OpenJanitor refuses to run.
#[derive(Debug, thiserror::Error)]
#[error("couldn't locate the {0} folder")]
pub struct DiscoverError(&'static str);

impl SystemPaths {
    /// Finds the real protected locations on this machine.
    pub fn discover() -> Result<Self, DiscoverError> {
        let get = |folder: KnownFolder, name: &'static str| {
            known_folder(folder).ok_or(DiscoverError(name))
        };

        let user_profile = get(KnownFolder::Profile, "user profile")?;
        let local_app_data = get(KnownFolder::LocalAppData, "local app data")?;

        let mut user_folders = Vec::new();
        for (folder, name) in [
            (KnownFolder::Desktop, "Desktop"),
            (KnownFolder::Documents, "Documents"),
            (KnownFolder::Pictures, "Pictures"),
            (KnownFolder::Music, "Music"),
            (KnownFolder::Videos, "Videos"),
        ] {
            user_folders.push(get(folder, name)?);
        }
        for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Some(value) = std::env::var_os(var) {
                let folder = long_path(Path::new(&value));
                if !user_folders.contains(&folder) {
                    user_folders.push(folder);
                }
            }
        }

        let mut program_files = vec![get(KnownFolder::ProgramFiles, "Program Files")?];
        if let Some(x86) = known_folder(KnownFolder::ProgramFilesX86)
            && !program_files.contains(&x86)
        {
            program_files.push(x86);
        }

        let program_data = get(KnownFolder::ProgramData, "ProgramData")?;
        Ok(Self {
            windows: get(KnownFolder::Windows, "Windows")?,
            program_files,
            system_app_data: program_data.join("OpenJanitor"),
            program_data,
            users_root: user_profile
                .parent()
                .map(Path::to_path_buf)
                .ok_or(DiscoverError("Users"))?,
            roaming_app_data: get(KnownFolder::RoamingAppData, "roaming app data")?,
            app_data: local_app_data.join("OpenJanitor"),
            local_app_data,
            user_profile,
            user_folders,
        })
    }

    /// A fake system layout rooted at `root`, for tests and fixtures.
    ///
    /// The folders aren't created; only the paths are set.
    pub fn fake(root: &Path) -> Self {
        let users_root = root.join("Users");
        let user_profile = users_root.join("tester");
        let roaming_app_data = user_profile.join(r"AppData\Roaming");
        let local_app_data = user_profile.join(r"AppData\Local");
        Self {
            windows: root.join("Windows"),
            program_files: vec![root.join("Program Files"), root.join("Program Files (x86)")],
            program_data: root.join("ProgramData"),
            system_app_data: root.join(r"ProgramData\OpenJanitor"),
            user_folders: [
                "Desktop",
                "Documents",
                "Pictures",
                "Music",
                "Videos",
                "OneDrive",
            ]
            .iter()
            .map(|name| user_profile.join(name))
            .collect(),
            app_data: local_app_data.join("OpenJanitor"),
            users_root,
            roaming_app_data,
            local_app_data,
            user_profile,
        }
    }

    /// Where files from this user's own folders go into quarantine
    /// (PLANNING.md §4.5).
    pub fn personal_quarantine(&self) -> PathBuf {
        self.app_data.join("Quarantine")
    }

    /// Where the elevated helper quarantines system files. It lives in the
    /// machine-wide data folder so that a program running as the user
    /// can't tamper with what the helper will later restore (D22).
    pub fn system_quarantine(&self) -> PathBuf {
        self.system_app_data.join("Quarantine")
    }
}
