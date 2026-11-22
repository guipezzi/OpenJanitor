//! Thin wrappers around the Windows APIs OpenJanitor needs.
//!
//! Almost everything here only reads information from the system. The one
//! exception is the raw move primitive behind quarantine, kept alone in the
//! [`file_move`] module. Only `oj-safety` may call it;
//! `scripts/check-guardrails.ps1` enforces that.
//!
//! This is the only crate in the project allowed to use `unsafe` (for FFI);
//! every unsafe block is small and explains why it's sound.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod file_move;

/// Size and identity information that `std` doesn't expose on stable Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskInfo {
    /// Bytes actually allocated on disk. Small files stored inside the
    /// NTFS file table can report 0.
    pub allocated: u64,
    /// Logical file size in bytes.
    pub len: u64,
    /// Number of hard links pointing at the file.
    pub links: u32,
    pub file_id: FileId,
}

/// Which file object a path points at: the volume's serial number plus the
/// file system's ID for the file. It stays the same when the file is renamed
/// or moved within the volume, and differs for a different file that
/// happens to have the same name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FileId {
    pub volume_serial: u64,
    pub id: u128,
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}-{:032x}", self.volume_serial, self.id)
    }
}

impl std::str::FromStr for FileId {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || format!("{text:?} is not a file ID");
        let (volume, id) = text.split_once('-').ok_or_else(invalid)?;
        if volume.len() != 16 || id.len() != 32 {
            return Err(invalid());
        }
        Ok(Self {
            volume_serial: u64::from_str_radix(volume, 16).map_err(|_| invalid())?,
            id: u128::from_str_radix(id, 16).map_err(|_| invalid())?,
        })
    }
}

/// Folders the user can relocate, so they must be resolved through the shell
/// API instead of being guessed from environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    Profile,
    Desktop,
    Documents,
    Downloads,
    Pictures,
    Music,
    Videos,
    RoamingAppData,
    LocalAppData,
    ProgramData,
    ProgramFiles,
    ProgramFilesX86,
    Windows,
}

pub use imp::{disk_info, known_folder, long_path, running_programs};

#[cfg(windows)]
mod imp {
    use super::{DiskInfo, FileId, KnownFolder};
    use std::ffi::{OsString, c_void};
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, GetLongPathNameW, OPEN_EXISTING,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData,
        FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Profile, FOLDERID_ProgramData,
        FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData, FOLDERID_Videos,
        FOLDERID_Windows, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use windows::core::{GUID, PCWSTR};

    /// A path as a NUL-terminated UTF-16 string.
    pub(crate) fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Turns a Windows error into an `io::Error` that carries the plain
    /// Win32 code, so `kind()` and `raw_os_error()` work ("not found",
    /// "already exists", "not the same device", ...).
    pub(crate) fn win32_error(error: windows::core::Error) -> io::Error {
        const FACILITY_WIN32: u32 = 0x8007_0000;
        let code = error.code().0 as u32;
        if code & 0xFFFF_0000 == FACILITY_WIN32 {
            io::Error::from_raw_os_error((code & 0xFFFF) as i32)
        } else {
            io::Error::other(error)
        }
    }

    /// Closes a handle when dropped.
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful call that hands
            // ownership to the caller, and it's closed exactly once, here.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Reads allocation size, hard link count, and file ID for a file or
    /// folder.
    ///
    /// The entry is opened for attribute access only, without following
    /// reparse points, so this never reads (or downloads) file contents.
    pub fn disk_info(path: &Path) -> io::Result<DiskInfo> {
        let name = wide(path);
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
        // call. All other arguments are plain flags or `None`.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(win32_error)?;
        let handle = OwnedHandle(handle);

        let mut info = FILE_STANDARD_INFO::default();
        // SAFETY: `info` is a valid, writable FILE_STANDARD_INFO and the size
        // passed matches its layout.
        unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileStandardInfo,
                (&raw mut info).cast::<c_void>(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        }
        .map_err(win32_error)?;

        Ok(DiskInfo {
            allocated: u64::try_from(info.AllocationSize).unwrap_or(0),
            len: u64::try_from(info.EndOfFile).unwrap_or(0),
            links: info.NumberOfLinks,
            file_id: file_id(&handle)?,
        })
    }

    /// The 128-bit ID (NTFS and ReFS), or the classic 64-bit file index on
    /// file systems that don't support it.
    fn file_id(handle: &OwnedHandle) -> io::Result<FileId> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: `info` is a valid, writable FILE_ID_INFO and the size
        // passed matches its layout.
        let wide = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileIdInfo,
                (&raw mut info).cast::<c_void>(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if wide.is_ok() {
            return Ok(FileId {
                volume_serial: info.VolumeSerialNumber,
                id: u128::from_le_bytes(info.FileId.Identifier),
            });
        }

        let mut classic = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `classic` is a valid, writable BY_HANDLE_FILE_INFORMATION.
        unsafe { GetFileInformationByHandle(handle.0, &mut classic) }.map_err(win32_error)?;
        Ok(FileId {
            volume_serial: u64::from(classic.dwVolumeSerialNumber),
            id: (u128::from(classic.nFileIndexHigh) << 32) | u128::from(classic.nFileIndexLow),
        })
    }

    /// Resolves a known folder through `SHGetKnownFolderPath`.
    pub fn known_folder(folder: KnownFolder) -> Option<PathBuf> {
        let id: GUID = match folder {
            KnownFolder::Profile => FOLDERID_Profile,
            KnownFolder::Desktop => FOLDERID_Desktop,
            KnownFolder::Documents => FOLDERID_Documents,
            KnownFolder::Downloads => FOLDERID_Downloads,
            KnownFolder::Pictures => FOLDERID_Pictures,
            KnownFolder::Music => FOLDERID_Music,
            KnownFolder::Videos => FOLDERID_Videos,
            KnownFolder::RoamingAppData => FOLDERID_RoamingAppData,
            KnownFolder::LocalAppData => FOLDERID_LocalAppData,
            KnownFolder::ProgramData => FOLDERID_ProgramData,
            KnownFolder::ProgramFiles => FOLDERID_ProgramFiles,
            KnownFolder::ProgramFilesX86 => FOLDERID_ProgramFilesX86,
            KnownFolder::Windows => FOLDERID_Windows,
        };
        // SAFETY: `id` is a valid GUID that outlives the call. On success the
        // returned buffer is freed with CoTaskMemFree below.
        let raw = unsafe { SHGetKnownFolderPath(&id, KF_FLAG_DEFAULT, None) }.ok()?;
        // SAFETY: on success `raw` points at a NUL-terminated UTF-16 string.
        let chars = unsafe { raw.as_wide() }.to_vec();
        // SAFETY: `raw` was allocated by the shell with CoTaskMemAlloc and is
        // not used after this call.
        unsafe { CoTaskMemFree(Some(raw.0 as *const c_void)) };
        Some(PathBuf::from(OsString::from_wide(&chars)))
    }

    /// The program file names (`chrome.exe`) of the processes running in
    /// this Windows session, that is, for the signed-in user. Other users'
    /// programs and services aren't included. Each name appears once per
    /// process, in no particular order.
    pub fn running_programs() -> io::Result<Vec<String>> {
        let session = session_of(std::process::id())?;
        // SAFETY: plain flags; the snapshot handle is closed by OwnedHandle.
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(win32_error)?;
        let snapshot = OwnedHandle(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut names = Vec::new();
        // SAFETY: `entry` is a valid, writable PROCESSENTRY32W with dwSize
        // set, as the API requires.
        let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while next.is_ok() {
            // A process whose session can't be read is kept: listing an app
            // as running only means its files wait for another cleanup.
            let other_session = matches!(session_of(entry.th32ProcessID), Ok(s) if s != session);
            if !other_session {
                let name = &entry.szExeFile;
                let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                names.push(String::from_utf16_lossy(&name[..len]));
            }
            // SAFETY: as above.
            next = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        match next {
            Err(e) if e.code() == ERROR_NO_MORE_FILES.to_hresult() => Ok(names),
            Err(e) => Err(win32_error(e)),
            Ok(()) => Ok(names),
        }
    }

    /// The Windows session a process runs in.
    fn session_of(process: u32) -> io::Result<u32> {
        let mut session = 0;
        // SAFETY: `session` is a valid, writable u32.
        unsafe { ProcessIdToSessionId(process, &mut session) }.map_err(win32_error)?;
        Ok(session)
    }

    /// Expands 8.3 short names (`C:\PROGRA~1`) to their long form.
    ///
    /// Returns the input unchanged if the path doesn't exist or can't be
    /// expanded.
    pub fn long_path(path: &Path) -> PathBuf {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated; passing no buffer asks for the
        // required size.
        let needed = unsafe { GetLongPathNameW(PCWSTR(name.as_ptr()), None) };
        if needed == 0 {
            return path.to_path_buf();
        }
        let mut buffer = vec![0u16; needed as usize];
        // SAFETY: `buffer` has the size the previous call asked for.
        let written = unsafe { GetLongPathNameW(PCWSTR(name.as_ptr()), Some(&mut buffer)) };
        if written == 0 || written as usize >= buffer.len() {
            return path.to_path_buf();
        }
        buffer.truncate(written as usize);
        PathBuf::from(OsString::from_wide(&buffer))
    }
}

/// Fallbacks so the workspace still compiles off Windows. OpenJanitor only
/// supports Windows; these exist for tooling, not for real use.
#[cfg(not(windows))]
mod imp {
    use super::{DiskInfo, FileId, KnownFolder};
    use std::io;
    use std::path::{Path, PathBuf};

    pub fn disk_info(path: &Path) -> io::Result<DiskInfo> {
        let len = std::fs::symlink_metadata(path)?.len();
        Ok(DiskInfo {
            allocated: len,
            len,
            links: 1,
            file_id: FileId::default(),
        })
    }

    pub fn known_folder(_folder: KnownFolder) -> Option<PathBuf> {
        None
    }

    pub fn long_path(path: &Path) -> PathBuf {
        path.to_path_buf()
    }

    pub fn running_programs() -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_test_shows_up_among_the_running_programs() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().to_lowercase();
        let running = super::running_programs().unwrap();
        assert!(
            running.iter().any(|p| p.to_lowercase() == name),
            "{name} not in {running:?}"
        );
    }
}
