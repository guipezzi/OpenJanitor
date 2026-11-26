//! The drives a scan covers (PLANNING.md §7.9, D15, and D33).
//!
//! The system drive is selected by default. The choice is remembered by
//! volume ID, not by letter, so an external drive keeps it when it comes
//! back with another letter. At least one drive is always selected: when
//! none of the remembered drives is connected, it's the system drive.

use oj_windows::volumes::{Bus, DriveType, VolumeError, VolumeInfo};
use serde::Serialize;

/// A volume ID: `\\?\Volume{` + a GUID + `}\`.
pub fn is_volume_id(id: &str) -> bool {
    let Some(guid) = id
        .strip_prefix(r"\\?\Volume{")
        .and_then(|rest| rest.strip_suffix(r"}\"))
    else {
        return false;
    };
    let groups: Vec<&str> = guid.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Media {
    Ssd,
    /// A spinning hard disk.
    Hdd,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    Internal,
    /// USB, a memory card, or another removable drive.
    External,
}

/// Whether a drive can be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriveStatus {
    Ready,
    /// Network drives aren't supported.
    Network,
    /// CD, DVD, and Blu-ray drives aren't supported.
    Optical,
    /// Not a volume of its own (such as a `subst` letter), a RAM disk, or
    /// a kind of drive Windows can't name.
    Unsupported,
    /// Locked (for example by BitLocker) or unreadable.
    Unavailable,
}

/// One drive letter, for the drive selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drive {
    /// Such as `C`.
    pub letter: char,
    /// The volume ID the choice is remembered by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Such as "Windows-SSD". Can be empty.
    pub label: String,
    pub file_system: String,
    pub total: u64,
    pub free: u64,
    pub media: Media,
    pub connection: Connection,
    pub status: DriveStatus,
    /// Windows is installed on it.
    pub system: bool,
    pub selected: bool,
}

impl Drive {
    /// Describes one volume. `None` for an empty card reader or a
    /// removable drive with nothing in it, which aren't worth listing.
    pub fn from_volume(volume: VolumeInfo, system: char) -> Option<Self> {
        let removable = volume.drive_type == DriveType::Removable;
        if removable && volume.details == Err(VolumeError::NoMedia) {
            return None;
        }
        let status = match (volume.drive_type, &volume.id, &volume.details) {
            (DriveType::Network, ..) => DriveStatus::Network,
            (DriveType::Optical, ..) => DriveStatus::Optical,
            (DriveType::RamDisk | DriveType::Unknown, ..) | (_, None, _) => {
                DriveStatus::Unsupported
            }
            (_, _, Err(_)) => DriveStatus::Unavailable,
            (DriveType::Fixed | DriveType::Removable, Some(_), Ok(_)) => DriveStatus::Ready,
        };
        let details = volume.details.ok();
        Some(Self {
            letter: volume.letter.to_ascii_uppercase(),
            id: volume.id,
            label: details
                .as_ref()
                .map(|d| d.label.clone())
                .unwrap_or_default(),
            file_system: details
                .as_ref()
                .map(|d| d.file_system.clone())
                .unwrap_or_default(),
            total: details.as_ref().map_or(0, |d| d.total),
            free: details.as_ref().map_or(0, |d| d.free),
            media: match volume.seek_penalty {
                Some(false) => Media::Ssd,
                Some(true) => Media::Hdd,
                None => Media::Unknown,
            },
            connection: if removable || matches!(volume.bus, Bus::Usb | Bus::Card) {
                Connection::External
            } else {
                Connection::Internal
            },
            status,
            system: volume.letter.eq_ignore_ascii_case(&system),
            selected: false,
        })
    }

    fn ready_id(&self) -> Option<&str> {
        (self.status == DriveStatus::Ready)
            .then_some(self.id.as_deref())
            .flatten()
    }
}

/// The drives on this machine, by letter, with none selected yet.
/// `system` is the letter Windows is installed on.
pub fn detect(system: char) -> Vec<Drive> {
    oj_windows::volumes::volumes()
        .into_iter()
        .filter_map(|volume| Drive::from_volume(volume, system))
        .collect()
}

/// Marks the selected drives: the remembered ones (`saved`) that are
/// ready, or the system drive when none is.
pub fn select(drives: &mut [Drive], saved: &[String]) {
    for drive in drives.iter_mut() {
        drive.selected = drive
            .ready_id()
            .is_some_and(|id| saved.iter().any(|s| s.eq_ignore_ascii_case(id)));
    }
    if !drives.iter().any(|d| d.selected)
        && let Some(system) = drives.iter_mut().find(|d| d.system)
    {
        system.selected = true;
    }
}

/// The letters of the selected drives, in order.
pub fn selected_letters(drives: &[Drive]) -> Vec<char> {
    drives
        .iter()
        .filter(|d| d.selected)
        .map(|d| d.letter)
        .collect()
}

/// What to remember after the user picks `chosen` (volume IDs) among the
/// drives here: those, plus the remembered drives that aren't connected
/// now, so they're still selected when they come back.
///
/// The choice must name at least one drive, and only ready ones.
pub fn remember(
    drives: &[Drive],
    saved: &[String],
    chosen: &[String],
) -> Result<Vec<String>, String> {
    if chosen.is_empty() {
        return Err("Choose at least one drive to scan.".into());
    }
    let mut remembered: Vec<String> = Vec::new();
    for id in chosen {
        let drive = drives
            .iter()
            .find(|d| {
                d.ready_id()
                    .is_some_and(|ready| ready.eq_ignore_ascii_case(id))
            })
            .ok_or_else(|| format!("{id} isn't a drive that can be scanned right now."))?;
        let id = drive.id.clone().expect("ready drives have an ID");
        if !remembered.contains(&id) {
            remembered.push(id);
        }
    }
    let here = |id: &String| {
        drives
            .iter()
            .any(|d| d.id.as_deref().is_some_and(|d| d.eq_ignore_ascii_case(id)))
    };
    for id in saved.iter().filter(|id| !here(id)) {
        if !remembered.iter().any(|r| r.eq_ignore_ascii_case(id)) {
            remembered.push(id.clone());
        }
    }
    Ok(remembered)
}

#[cfg(test)]
mod tests {
    use oj_windows::volumes::VolumeDetails;

    use super::*;

    const C: &str = r"\\?\Volume{d88dd716-bfa6-48d0-997b-aadbcb888cb8}\";
    const D: &str = r"\\?\Volume{61a9a736-71b3-4fb5-b31f-c1973df5af1f}\";
    const E: &str = r"\\?\Volume{00000000-1111-2222-3333-444444444444}\";

    fn volume(letter: char, drive_type: DriveType, id: Option<&str>, bus: Bus) -> VolumeInfo {
        VolumeInfo {
            letter,
            drive_type,
            id: id.map(str::to_owned),
            details: Ok(VolumeDetails {
                label: format!("Disk {letter}"),
                file_system: "NTFS".into(),
                total: 1_000,
                free: 400,
            }),
            bus,
            seek_penalty: Some(false),
        }
    }

    fn drives() -> Vec<Drive> {
        [
            volume('C', DriveType::Fixed, Some(C), Bus::Internal),
            // An external SSD that says it's fixed.
            volume('D', DriveType::Fixed, Some(D), Bus::Usb),
            volume('Z', DriveType::Network, None, Bus::Unknown),
        ]
        .into_iter()
        .filter_map(|v| Drive::from_volume(v, 'C'))
        .collect()
    }

    #[test]
    fn volume_ids_are_checked_strictly() {
        assert!(is_volume_id(C));
        for id in [
            "C:",
            r"\\?\Volume{d88dd716-bfa6-48d0-997b-aadbcb888cb8}",
            r"\\?\Volume{d88dd716-bfa6-48d0-997b-aadbcb888cbZ}\",
            r"\\?\Volume{d88dd716bfa648d0997baadbcb888cb8}\",
            r"\\?\Volume{d88dd716-bfa6-48d0-997b-aadbcb888cb8}\..\",
        ] {
            assert!(!is_volume_id(id), "{id}");
        }
    }

    #[test]
    fn drives_say_what_they_are() {
        let drives = drives();
        let [c, d, z] = &drives[..] else {
            panic!("{drives:?}")
        };
        assert!(c.system && !d.system);
        assert_eq!(
            (c.status, c.connection, c.media),
            (DriveStatus::Ready, Connection::Internal, Media::Ssd)
        );
        assert_eq!(
            (d.status, d.connection),
            (DriveStatus::Ready, Connection::External)
        );
        assert_eq!(z.status, DriveStatus::Network);

        let mut locked = volume('E', DriveType::Fixed, Some(E), Bus::Internal);
        locked.details = Err(VolumeError::Unreadable("locked".into()));
        assert_eq!(
            Drive::from_volume(locked, 'C').unwrap().status,
            DriveStatus::Unavailable
        );
        let subst = volume('S', DriveType::Fixed, None, Bus::Unknown);
        assert_eq!(
            Drive::from_volume(subst, 'C').unwrap().status,
            DriveStatus::Unsupported
        );
        let mut empty_reader = volume('F', DriveType::Removable, None, Bus::Card);
        empty_reader.details = Err(VolumeError::NoMedia);
        assert_eq!(Drive::from_volume(empty_reader, 'C'), None);
    }

    #[test]
    fn the_system_drive_is_selected_until_another_choice_is_saved() {
        let mut drives = drives();
        select(&mut drives, &[]);
        assert_eq!(selected_letters(&drives), ['C']);

        select(&mut drives, &[D.to_uppercase()]);
        assert_eq!(selected_letters(&drives), ['D'], "IDs match in any case");

        // Remembered drives that aren't here leave the system drive.
        select(&mut drives, &[E.to_owned()]);
        assert_eq!(selected_letters(&drives), ['C']);
    }

    #[test]
    fn unplugged_drives_keep_their_choice() {
        let drives = drives();
        let saved = vec![C.to_owned(), E.to_owned()];
        let remembered = remember(&drives, &saved, &[D.to_owned()]).unwrap();
        assert_eq!(remembered, [D, E], "C: was unchosen; E: isn't connected");

        assert!(remember(&drives, &saved, &[]).is_err(), "at least one");
        assert!(
            remember(&drives, &[], &[E.to_owned()]).is_err(),
            "not connected"
        );
        let network = remember(&drives, &[], &["Z:".to_owned()]);
        assert!(network.is_err(), "only ready drives");
    }
}
