// The History screen (PLANNING.md sections 4.8 and 7.4), through commands in
// src-tauri. Reading only.
import { invoke } from '@tauri-apps/api/core'

import type { Mode, SkipReason } from './clean'
import type { Tally } from './selection'

export type EntryKind = 'cleanup' | 'restore' | 'delete' | 'expired'

/** One cleanup, restore, or delete (oj_core::HistoryEntry). */
export interface HistoryEntry {
  id: number
  kind: EntryKind
  /** When it started, in seconds since the Unix epoch. */
  at: number
  mode: Mode
  /** Files deleted, restored, or (for a cleanup) deleted and quarantined. */
  files: number
  /** Space freed for good. */
  freed: number
  /** A cleanup's files moved to quarantine. */
  quarantined: Tally
  skipped: number
  cancelled: boolean
  /** The app stopped partway; the numbers come from its file lines. */
  interrupted: boolean
  /** File lines still kept (0 once trimmed). */
  details: number
}

export type FileResult =
  | 'deleted'
  | 'would_delete'
  | 'quarantined'
  | 'would_quarantine'
  | 'restored'
  | 'would_restore'
  | 'skipped'
  | 'replaced'
  | 'folder_removed'

export interface HistoryFile {
  path: string
  size: number
  /** For a Recycle Bin: the items in it. */
  items?: number
  result: FileResult
  /** Why it was skipped. */
  reason?: SkipReason
}

export interface HistoryFilePage {
  items: HistoryFile[]
  total: number
}

export interface HistoryOverview {
  view_id: number
  /** Newest first. */
  entries: HistoryEntry[]
  /** Everything freed for good, not counting test runs. */
  totals: { freed: number; cleanups: number; since?: number }
  unreadable_lines: number
  /** How long per-file details are kept. */
  detail_days: number
}

export function historyOverview(): Promise<HistoryOverview> {
  return invoke<HistoryOverview>('history_overview')
}

export function historyFiles(
  viewId: number,
  entryId: number,
  offset: number,
  limit: number,
): Promise<HistoryFilePage> {
  return invoke<HistoryFilePage>('history_files', { viewId, entryId, offset, limit })
}
