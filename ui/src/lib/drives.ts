// The drives a scan covers (PLANNING.md section 7.9 and D33), through
// commands in src-tauri. The choice is saved in the settings, by volume ID.
import { invoke } from '@tauri-apps/api/core'

export type Media = 'ssd' | 'hdd' | 'unknown'
export type Connection = 'internal' | 'external'
/** Only `ready` drives can be scanned. */
export type DriveStatus = 'ready' | 'network' | 'optical' | 'unsupported' | 'unavailable'

/** One drive letter (oj_core::Drive). */
export interface Drive {
  /** Such as "C". */
  letter: string
  /** The volume ID the choice is remembered by. */
  id?: string
  /** Such as "Windows-SSD". Can be empty. */
  label: string
  file_system: string
  total: number
  free: number
  media: Media
  connection: Connection
  status: DriveStatus
  /** Windows is installed on it. */
  system: boolean
  selected: boolean
}

export interface DrivesOverview {
  /** By letter. */
  drives: Drive[]
}

export function drivesOverview(): Promise<DrivesOverview> {
  return invoke<DrivesOverview>('drives_overview')
}

/**
 * Saves which drives to scan, by volume ID. If that changes the selection,
 * the current results are forgotten on the Rust side.
 */
export function selectDrives(ids: string[]): Promise<DrivesOverview> {
  return invoke<DrivesOverview>('select_drives', { ids })
}

/** The selected drives' letters, such as "C,D", to tell selections apart. */
export function selectionKey(drives: readonly Drive[]): string {
  return drives
    .filter((drive) => drive.selected)
    .map((drive) => drive.letter)
    .join(',')
}
