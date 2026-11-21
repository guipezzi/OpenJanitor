//! Read-only wrappers around the Windows APIs OpenJanitor needs.
//!
//! This crate never deletes, moves, or modifies anything. It only reads
//! information from the system. It's the only crate in the project allowed to
//! use `unsafe` (for FFI); every unsafe block is small and explains why it's
//! sound.

#![deny(unsafe_op_in_unsafe_fn)]

/// Size information that `std` doesn't expose on stable Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskInfo {
    /// Bytes actually allocated on disk. Small files stored inside the
    /// NTFS file table can report 0.
    pub allocated: u64,
    /// Logical file size in bytes.
    pub len: u64,
    /// Number of hard links pointing at the file.
    pub links: u32,
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

pub use imp::{disk_info, known_folder, long_path};

#[cfg(windows)]
mod imp {
    use super::{DiskInfo, KnownFolder};
    use std::ffi::{OsString, c_void};
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx, GetLongPathNameW,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData,
        FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Profile, FOLDERID_ProgramData,
        FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData, FOLDERID_Videos,
        FOLDERID_Windows, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use windows::core::{GUID, PCWSTR};

    /// A path as a NUL-terminated UTF-16 string.
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Closes a handle when dropped.
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful CreateFileW call and is
            // closed exactly once, here.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Reads allocation size and hard link count for a file or folder.
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
        .map_err(io::Error::from)?;
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
        .map_err(io::Error::from)?;

        Ok(DiskInfo {
            allocated: u64::try_from(info.AllocationSize).unwrap_or(0),
            len: u64::try_from(info.EndOfFile).unwrap_or(0),
            links: info.NumberOfLinks,
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
    use super::{DiskInfo, KnownFolder};
    use std::io;
    use std::path::{Path, PathBuf};

    pub fn disk_info(path: &Path) -> io::Result<DiskInfo> {
        let len = std::fs::symlink_metadata(path)?.len();
        Ok(DiskInfo {
            allocated: len,
            len,
            links: 1,
        })
    }

    pub fn known_folder(_folder: KnownFolder) -> Option<PathBuf> {
        None
    }

    pub fn long_path(path: &Path) -> PathBuf {
        path.to_path_buf()
    }
}
