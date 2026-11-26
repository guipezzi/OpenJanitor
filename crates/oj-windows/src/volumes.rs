//! The drive letters on this machine and what they are (PLANNING.md §7.9).
//! Only reads.

/// What Windows says a drive letter is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// A hard disk or SSD, inside or outside the computer. External USB
    /// disks often say this too; [`Bus`] tells them apart.
    Fixed,
    /// A USB flash drive or a memory card.
    Removable,
    Network,
    /// A CD, DVD, or Blu-ray drive.
    Optical,
    RamDisk,
    Unknown,
}

/// How a drive is connected, from its storage bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    Usb,
    /// An SD or MMC card.
    Card,
    /// SATA, NVMe, and the other buses of disks inside the computer.
    Internal,
    /// A virtual disk (VHD) or a storage space.
    Virtual,
    Unknown,
}

/// A volume's name, file system, and space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeDetails {
    /// Its label, such as "Windows-SSD". Can be empty.
    pub label: String,
    /// Such as "NTFS".
    pub file_system: String,
    pub total: u64,
    pub free: u64,
}

/// Why a volume's details couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    /// Nothing is in the drive: no card, no disc.
    NoMedia,
    /// Locked (for example by BitLocker) or otherwise unreadable.
    Unreadable(String),
}

/// One drive letter, as Windows describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Such as `'C'`.
    pub letter: char,
    pub drive_type: DriveType,
    /// The volume's own name (`\\?\Volume{…}\`), which stays the same when
    /// its letter changes. `None` for letters that aren't a volume of their
    /// own, such as network drives or `subst` letters.
    pub id: Option<String>,
    /// Not read for network drives, which can take long to answer.
    pub details: Result<VolumeDetails, VolumeError>,
    pub bus: Bus,
    /// Whether reads have to seek, as on a spinning disk. `None` when
    /// Windows doesn't say.
    pub seek_penalty: Option<bool>,
}

pub use imp::volumes;

#[cfg(windows)]
mod imp {
    use super::{Bus, DriveType, VolumeDetails, VolumeError, VolumeInfo};
    use std::ffi::c_void;
    use std::mem::size_of;

    use windows::Win32::Foundation::{CloseHandle, ERROR_NOT_READY, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual, BusTypeMmc, BusTypeNvme,
        BusTypeRAID, BusTypeSCM, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces,
        BusTypeUfs, BusTypeUsb, BusTypeVirtual, CreateFileW, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives,
        GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{
        DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
        STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY,
        StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
    };
    use windows::core::PCWSTR;

    // GetDriveTypeW's answers.
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_REMOTE: u32 = 4;
    const DRIVE_CDROM: u32 = 5;
    const DRIVE_RAMDISK: u32 = 6;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn text(buffer: &[u16]) -> String {
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..len])
    }

    /// Every drive letter in use, from A to Z.
    pub fn volumes() -> Vec<VolumeInfo> {
        // SAFETY: no arguments; it returns a bit mask of the letters in use.
        let letters = unsafe { GetLogicalDrives() };
        (0..26u8)
            .filter(|bit| letters & (1 << bit) != 0)
            .map(|bit| volume(char::from(b'A' + bit)))
            .collect()
    }

    fn volume(letter: char) -> VolumeInfo {
        let root = wide(&format!("{letter}:\\"));
        // SAFETY: `root` is a NUL-terminated string that outlives the call.
        let drive_type = match unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } {
            DRIVE_FIXED => DriveType::Fixed,
            DRIVE_REMOVABLE => DriveType::Removable,
            DRIVE_REMOTE => DriveType::Network,
            DRIVE_CDROM => DriveType::Optical,
            DRIVE_RAMDISK => DriveType::RamDisk,
            _ => DriveType::Unknown,
        };
        let local = !matches!(drive_type, DriveType::Network | DriveType::Unknown);
        let (bus, seek_penalty) = if local {
            device_facts(letter)
        } else {
            (Bus::Unknown, None)
        };
        VolumeInfo {
            letter,
            drive_type,
            id: if local { volume_id(&root) } else { None },
            details: if local {
                details(&root)
            } else {
                Err(VolumeError::Unreadable("not read".into()))
            },
            bus,
            seek_penalty,
        }
    }

    fn volume_id(root: &[u16]) -> Option<String> {
        // A volume name is 49 characters plus the NUL.
        let mut name = [0u16; 64];
        // SAFETY: `root` is NUL-terminated and `name` is a writable buffer
        // whose length the binding passes along.
        unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(root.as_ptr()), &mut name) }.ok()?;
        Some(text(&name))
    }

    fn details(root: &[u16]) -> Result<VolumeDetails, VolumeError> {
        let unreadable = |e: windows::core::Error| {
            if e.code() == ERROR_NOT_READY.to_hresult() {
                VolumeError::NoMedia
            } else {
                VolumeError::Unreadable(e.message())
            }
        };
        let mut label = [0u16; 261];
        let mut file_system = [0u16; 261];
        // SAFETY: `root` is NUL-terminated; both buffers are writable and
        // the binding passes their lengths.
        unsafe {
            GetVolumeInformationW(
                PCWSTR(root.as_ptr()),
                Some(&mut label),
                None,
                None,
                None,
                Some(&mut file_system),
            )
        }
        .map_err(unreadable)?;
        let (mut total, mut free) = (0u64, 0u64);
        // SAFETY: `root` is NUL-terminated; `total` and `free` are valid,
        // writable u64s.
        unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(root.as_ptr()),
                None,
                Some(&mut total),
                Some(&mut free),
            )
        }
        .map_err(unreadable)?;
        Ok(VolumeDetails {
            label: text(&label),
            file_system: text(&file_system),
            total,
            free,
        })
    }

    /// Closes a handle when dropped.
    struct Device(HANDLE);

    impl Drop for Device {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateFileW and is closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// The bus and the seek penalty, asked of the device behind the
    /// letter. The device is opened without any access rights, which is
    /// enough to ask and needs no administrator rights.
    fn device_facts(letter: char) -> (Bus, Option<bool>) {
        let path = wide(&format!("\\\\.\\{letter}:"));
        // SAFETY: `path` is NUL-terminated and outlives the call; no access
        // is requested, so nothing can be read or written through it.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };
        let Ok(handle) = handle else {
            return (Bus::Unknown, None);
        };
        let device = Device(handle);

        let mut descriptor = [0u8; 1024];
        let bus = query(&device, StorageDeviceProperty, &mut descriptor)
            .filter(|&len| len >= size_of::<STORAGE_DEVICE_DESCRIPTOR>())
            .map_or(Bus::Unknown, |_| {
                // SAFETY: Windows filled at least a whole descriptor;
                // read_unaligned copes with the byte buffer's alignment.
                let descriptor = unsafe {
                    descriptor
                        .as_ptr()
                        .cast::<STORAGE_DEVICE_DESCRIPTOR>()
                        .read_unaligned()
                };
                let bus = descriptor.BusType;
                let internal = [
                    BusTypeScsi,
                    BusTypeAtapi,
                    BusTypeAta,
                    BusTypeFibre,
                    BusTypeRAID,
                    BusTypeSas,
                    BusTypeSata,
                    BusTypeNvme,
                    BusTypeSCM,
                    BusTypeUfs,
                ];
                if bus == BusTypeUsb {
                    Bus::Usb
                } else if [BusTypeSd, BusTypeMmc].contains(&bus) {
                    Bus::Card
                } else if [BusTypeVirtual, BusTypeFileBackedVirtual, BusTypeSpaces].contains(&bus) {
                    Bus::Virtual
                } else if internal.contains(&bus) {
                    Bus::Internal
                } else {
                    Bus::Unknown
                }
            });

        let mut penalty = [0u8; size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>()];
        let seek_penalty = query(&device, StorageDeviceSeekPenaltyProperty, &mut penalty)
            .filter(|&len| len >= size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>())
            .map(|_| {
                // SAFETY: as above, a whole descriptor was filled in.
                let descriptor = unsafe {
                    penalty
                        .as_ptr()
                        .cast::<DEVICE_SEEK_PENALTY_DESCRIPTOR>()
                        .read_unaligned()
                };
                descriptor.IncursSeekPenalty
            });
        (bus, seek_penalty)
    }

    /// Asks the device for one storage property; returns how many bytes it
    /// wrote into `out`.
    fn query(device: &Device, property: STORAGE_PROPERTY_ID, out: &mut [u8]) -> Option<usize> {
        let request = STORAGE_PROPERTY_QUERY {
            PropertyId: property,
            QueryType: PropertyStandardQuery,
            ..Default::default()
        };
        let mut written = 0u32;
        // SAFETY: `request` and `out` are valid for the sizes passed, and
        // `written` is a valid, writable u32. The call is synchronous.
        unsafe {
            DeviceIoControl(
                device.0,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some((&raw const request).cast::<c_void>()),
                size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                Some(out.as_mut_ptr().cast::<c_void>()),
                out.len() as u32,
                Some(&mut written),
                None,
            )
        }
        .ok()?;
        Some(written as usize)
    }
}

/// OpenJanitor only supports Windows; elsewhere there are no drives.
#[cfg(not(windows))]
mod imp {
    use super::VolumeInfo;

    pub fn volumes() -> Vec<VolumeInfo> {
        Vec::new()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn the_system_drive_is_a_readable_fixed_volume() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let letter = system.chars().next().unwrap().to_ascii_uppercase();
        let volumes = volumes();
        let drive = volumes
            .iter()
            .find(|v| v.letter == letter)
            .unwrap_or_else(|| panic!("{letter}: not in {volumes:?}"));

        assert_eq!(drive.drive_type, DriveType::Fixed);
        let id = drive.id.as_deref().expect("a volume ID");
        assert!(
            id.starts_with(r"\\?\Volume{") && id.ends_with(r"}\"),
            "{id}"
        );
        let details = drive.details.as_ref().expect("readable");
        assert!(
            details.total > 0 && details.free <= details.total,
            "{details:?}"
        );
        assert!(!details.file_system.is_empty());
    }
}
