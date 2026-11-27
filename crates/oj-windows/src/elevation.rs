//! Starting the elevated helper and checking processes (PLANNING.md §4.6).
//! Nothing here deletes or changes files.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Whether this process runs with administrator rights (elevated).
pub fn is_elevated() -> io::Result<bool> {
    imp::is_elevated()
}

/// The program file a running process was started from.
pub fn process_image(pid: u32) -> io::Result<PathBuf> {
    imp::process_image(pid)
}

/// Starts `exe` with administrator rights, so Windows shows its UAC prompt.
/// Returns once the user has answered: an error with code 1223
/// (`ERROR_CANCELLED`) means they said no.
pub fn run_as_admin(exe: &Path, arguments: &str) -> io::Result<ElevatedProcess> {
    imp::run_as_admin(exe, arguments)
}

/// Whether an error from [`run_as_admin`] means the user declined.
pub fn is_declined(error: &io::Error) -> bool {
    error.raw_os_error() == Some(1223)
}

/// A process started by [`run_as_admin`].
#[derive(Debug)]
pub struct ElevatedProcess {
    #[cfg(windows)]
    handle: imp::Handle,
    id: u32,
}

impl ElevatedProcess {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Waits up to `timeout` for it to end; returns its exit code, or
    /// `None` if it's still running.
    pub fn wait(&self, timeout: Duration) -> io::Result<Option<u32>> {
        imp::wait(self, timeout)
    }
}

#[cfg(windows)]
mod imp {
    use super::ElevatedProcess;
    use std::ffi::{OsString, c_void};
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenProcess, OpenProcessToken,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::core::{PCWSTR, PWSTR};

    use crate::imp::win32_error;

    /// A process or token handle, closed when dropped.
    #[derive(Debug)]
    pub(super) struct Handle(HANDLE);

    // SAFETY: a process handle can be used and closed from any thread.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a call that hands ownership to
            // the caller, and it's closed exactly once, here.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn is_elevated() -> io::Result<bool> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(win32_error)?;
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut written = 0u32;
        // SAFETY: `elevation` is a valid, writable TOKEN_ELEVATION and the
        // size passed matches it.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&raw mut elevation).cast::<c_void>()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut written,
            )
        }
        .map_err(win32_error)?;
        Ok(elevation.TokenIsElevated != 0)
    }

    pub fn process_image(pid: u32) -> io::Result<PathBuf> {
        // SAFETY: plain arguments; the handle is closed by `Handle`.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(win32_error)?;
        let process = Handle(process);
        let mut buffer = vec![0u16; 32_768];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` holds `len` UTF-16 units, and `len` is a valid,
        // writable u32 that receives the length written.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(win32_error)?;
        buffer.truncate(len as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    pub fn run_as_admin(exe: &Path, arguments: &str) -> io::Result<ElevatedProcess> {
        let verb = wide("runas".as_ref());
        let file = wide(exe.as_os_str());
        let parameters = wide(arguments.as_ref());
        let mut info = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(parameters.as_ptr()),
            // SW_HIDE: the helper has no window to show.
            nShow: 0,
            ..Default::default()
        };
        // The shell may hand the request to COM. Undone below only if this
        // call did the initializing.
        // SAFETY: no pointers; initializes COM for this thread.
        let com =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        // SAFETY: `info` is a valid SHELLEXECUTEINFOW with cbSize set, and
        // every string it points at outlives the call. It returns after the
        // user answers the UAC prompt.
        let result = unsafe { ShellExecuteExW(&mut info) }.map_err(win32_error);
        if com.is_ok() {
            // SAFETY: balances the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
        result?;
        if info.hProcess.is_invalid() {
            return Err(io::Error::other(
                "Windows didn't say which process it started",
            ));
        }
        let handle = Handle(info.hProcess);
        // SAFETY: `handle` is a valid process handle.
        let id = unsafe { GetProcessId(handle.0) };
        Ok(ElevatedProcess { handle, id })
    }

    pub fn wait(process: &ElevatedProcess, timeout: Duration) -> io::Result<Option<u32>> {
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the handle is a valid process handle owned by `process`.
        let waited = unsafe { WaitForSingleObject(process.handle.0, millis) };
        if waited == WAIT_TIMEOUT {
            return Ok(None);
        }
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid, writable u32.
        unsafe { GetExitCodeProcess(process.handle.0, &mut code) }.map_err(win32_error)?;
        Ok(Some(code))
    }
}

/// OpenJanitor only supports Windows.
#[cfg(not(windows))]
mod imp {
    use super::ElevatedProcess;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "only supported on Windows")
    }

    pub fn is_elevated() -> io::Result<bool> {
        Ok(false)
    }

    pub fn process_image(_pid: u32) -> io::Result<PathBuf> {
        Err(unsupported())
    }

    pub fn run_as_admin(_exe: &Path, _arguments: &str) -> io::Result<ElevatedProcess> {
        Err(unsupported())
    }

    pub fn wait(_process: &ElevatedProcess, _timeout: Duration) -> io::Result<Option<u32>> {
        Err(unsupported())
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn this_process_is_found_by_its_id() {
        let image = super::process_image(std::process::id()).unwrap();
        let me = std::env::current_exe().unwrap();
        assert!(image.eq_ignore_ascii_case_path(&me), "{image:?} vs {me:?}");
    }

    #[test]
    fn elevation_can_be_read() {
        super::is_elevated().unwrap();
    }

    trait EqPath {
        fn eq_ignore_ascii_case_path(&self, other: &std::path::Path) -> bool;
    }

    impl EqPath for std::path::PathBuf {
        fn eq_ignore_ascii_case_path(&self, other: &std::path::Path) -> bool {
            let a = crate::long_path(self);
            let b = crate::long_path(other);
            a.to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy())
        }
    }
}
