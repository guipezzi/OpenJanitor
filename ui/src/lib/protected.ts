// The Protected list (PLANNING.md section 7.2), through commands in
// src-tauri. The UI never reads or writes the list file itself.
import { invoke } from '@tauri-apps/api/core'

import type { ScanOverview } from './scan'

export type EntryKind = 'file' | 'folder' | 'pattern' | 'rule'

export interface ProtectedEntry {
  kind: EntryKind
  /** The path, pattern, or rule id. */
  value: string
  /** What to show instead of `value`, such as a rule's name. */
  label?: string
  /** Seconds since the Unix epoch. */
  added_at: number
}

export interface ProtectedUpdate {
  entries: ProtectedEntry[]
  /** The current results with newly protected items hidden, if there are results. */
  overview: ScanOverview | null
  added: number
}

export function protectedEntries(): Promise<ProtectedEntry[]> {
  return invoke<ProtectedEntry[]>('protected_entries')
}

/** Protects a result: its rule, its folder, or its file. */
export function protectItem(scanId: number, nodeId: number): Promise<ProtectedUpdate> {
  return invoke<ProtectedUpdate>('protect_item', { scanId, nodeId })
}

export function protectPattern(pattern: string): Promise<ProtectedUpdate> {
  return invoke<ProtectedUpdate>('protect_pattern', { pattern })
}

/** Stops protecting an entry; its items come back on the next scan. */
export function unprotect(kind: EntryKind, value: string): Promise<ProtectedEntry[]> {
  return invoke<ProtectedEntry[]>('unprotect', { kind, value })
}

/** Saves a copy where the user picks. False if they cancelled. */
export function exportProtected(): Promise<boolean> {
  return invoke<boolean>('export_protected')
}

/** Adds the entries of a file the user picks. Null if they cancelled. */
export function importProtected(): Promise<ProtectedUpdate | null> {
  return invoke<ProtectedUpdate | null>('import_protected')
}
