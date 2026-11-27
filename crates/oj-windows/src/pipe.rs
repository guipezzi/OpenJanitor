//! The private channel between the app and the elevated helper
//! (PLANNING.md §4.6): a local named pipe with one instance.
//!
//! The helper creates it, so a pipe of that name existing already makes it
//! refuse to start. Each side checks which process is on the other end.

use std::fs::File;
use std::io;

/// The helper's end, waiting for the app.
#[derive(Debug)]
pub struct PipeServer {
    file: File,
}

impl PipeServer {
    /// Creates `\\.\pipe\<name>`: one instance only, local clients only,
    /// and openable by interactive users, administrators, and SYSTEM. Fails
    /// if a pipe of that name already exists.
    pub fn create(name: &str) -> io::Result<Self> {
        imp::create(name).map(|file| Self { file })
    }

    /// Waits for the app to connect, and returns the connection with the
    /// connected process's ID.
    pub fn accept(self) -> io::Result<(File, u32)> {
        imp::accept(&self.file)?;
        let pid = imp::client_pid(&self.file)?;
        Ok((self.file, pid))
    }
}

/// Connects to the helper's pipe, and returns the connection with the
/// helper's process ID. `ERROR_FILE_NOT_FOUND` means it isn't there yet.
///
/// The helper may only identify the app, never act as it.
pub fn connect(name: &str) -> io::Result<(File, u32)> {
    let file = imp::connect(name)?;
    let pid = imp::server_pid(&file)?;
    Ok((file, pid))
}

/// How many bytes are waiting to be read, without waiting for any. Reading
/// and writing one pipe from two threads would deadlock, so a single
/// thread checks this between writes.
pub fn available(file: &File) -> io::Result<u32> {
    imp::available(file)
}

/// A pipe name only this run knows: 128 random bits.
pub fn random_name(prefix: &str) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut bits = 0u128;
    for _ in 0..2 {
        // RandomState seeds itself from the operating system's randomness.
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(bits);
        hasher.write_u32(std::process::id());
        bits = (bits << 64) | u128::from(hasher.finish());
    }
    format!("{prefix}-{bits:032x}")
}

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
    };
    use windows::core::PCWSTR;

    use crate::imp::win32_error;

    const BUFFER: u32 = 64 * 1024;

    fn path(name: &str) -> io::Result<Vec<u16>> {
        let plain = name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if name.is_empty() || name.len() > 200 || !plain {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad pipe name"));
        }
        Ok(format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect())
    }

    /// A security descriptor made from SDDL, freed when dropped.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor was allocated by the SDDL conversion
            // with LocalAlloc, and is freed once, here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }

    pub fn create(name: &str) -> io::Result<File> {
        let path = path(name)?;
        // Protected DACL: SYSTEM and Administrators get full access;
        // interactive users (the app, unelevated) may read and write.
        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is NUL-terminated; `descriptor` receives a
        // LocalAlloc'd descriptor that `Descriptor` frees.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(win32_error)?;
        let descriptor = Descriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        // SAFETY: `path` is NUL-terminated and `attributes` points at a
        // valid descriptor; both outlive the call.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(path.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                BUFFER,
                BUFFER,
                0,
                Some(&raw const attributes),
            )
        };
        if handle.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handle is valid and owned; File closes it.
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }

    pub fn accept(file: &File) -> io::Result<()> {
        let handle = HANDLE(file.as_raw_handle());
        // SAFETY: a valid pipe handle, used synchronously.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => Ok(()),
            // The client connected before we started waiting.
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(()),
            Err(e) => Err(win32_error(e)),
        }
    }

    pub fn connect(name: &str) -> io::Result<File> {
        let path = path(name)?;
        // SAFETY: `path` is NUL-terminated. SECURITY_IDENTIFICATION lets
        // the helper see who we are, never act as us.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
        }
        .map_err(win32_error)?;
        // SAFETY: the handle is valid and owned; File closes it.
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }

    fn pid(file: &File, server: bool) -> io::Result<u32> {
        let handle = HANDLE(file.as_raw_handle());
        let mut pid = 0u32;
        // SAFETY: a valid pipe handle and a valid, writable u32.
        let result = unsafe {
            if server {
                GetNamedPipeServerProcessId(handle, &mut pid)
            } else {
                GetNamedPipeClientProcessId(handle, &mut pid)
            }
        };
        result.map_err(win32_error)?;
        Ok(pid)
    }

    pub fn client_pid(file: &File) -> io::Result<u32> {
        pid(file, false)
    }

    pub fn server_pid(file: &File) -> io::Result<u32> {
        pid(file, true)
    }

    pub fn available(file: &File) -> io::Result<u32> {
        let mut waiting = 0u32;
        // SAFETY: a valid pipe handle; no buffer is passed, so only the
        // count is written, into a valid u32. It never blocks.
        unsafe {
            PeekNamedPipe(
                HANDLE(file.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut waiting),
                None,
            )
        }
        .map_err(win32_error)?;
        Ok(waiting)
    }
}

#[cfg(not(windows))]
mod imp {
    use std::fs::File;
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "only supported on Windows")
    }

    pub fn create(_name: &str) -> io::Result<File> {
        Err(unsupported())
    }
    pub fn accept(_file: &File) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn connect(_name: &str) -> io::Result<File> {
        Err(unsupported())
    }
    pub fn client_pid(_file: &File) -> io::Result<u32> {
        Err(unsupported())
    }
    pub fn server_pid(_file: &File) -> io::Result<u32> {
        Err(unsupported())
    }
    pub fn available(_file: &File) -> io::Result<u32> {
        Err(unsupported())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::{BufRead, BufReader, Write};

    use super::*;

    #[test]
    fn both_ends_talk_and_see_each_other() {
        let name = random_name("openjanitor-test");
        let server = PipeServer::create(&name).unwrap();
        assert!(PipeServer::create(&name).is_err(), "one instance only");

        let waiter = std::thread::spawn(move || {
            let (file, client) = server.accept().unwrap();
            let mut reader = BufReader::new(&file);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(available(&file).unwrap(), 0, "nothing more waiting");
            (&file).write_all(b"pong\n").unwrap();
            (client, line)
        });
        let (file, server_pid) = loop {
            match connect(&name) {
                Ok(connected) => break connected,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        };
        (&file).write_all(b"ping\n").unwrap();
        let mut reply = String::new();
        BufReader::new(&file).read_line(&mut reply).unwrap();

        let (client_pid, line) = waiter.join().unwrap();
        assert_eq!((line.as_str(), reply.as_str()), ("ping\n", "pong\n"));
        assert_eq!(client_pid, std::process::id());
        assert_eq!(server_pid, std::process::id());
    }

    #[test]
    fn names_are_random_and_plain() {
        let a = random_name("x");
        assert_ne!(a, random_name("x"));
        assert_eq!(a.len(), 2 + 32);
        assert!(connect("bad name with spaces").is_err());
    }
}
