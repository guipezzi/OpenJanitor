// The Quarantine screen (PLANNING.md sections 4.5 and 7.3), through
// commands in src-tauri. Files are referred to by node id from the view the
// screen loaded, never by path.
import { invoke } from '@tauri-apps/api/core'

import type { Mode, SkipReason } from './clean'
import type { ChildPage, NodeView } from './scan'
import type { Choices, Tally } from './selection'

/** A quarantine folder whose manifest couldn't be read. It's left alone. */
export interface UnreadableBatch {
  batch: string
  folder: string
  error: string
}

/** What a restore or a delete did (oj_core::QuarantineReport). */
export interface QuarantineReport {
  mode: Mode
  /** Restored, or deleted for good. For deletes, `size` is the space freed. */
  done: Tally
  skipped: { reason: SkipReason; files: number }[]
  history_error?: string
}

/** What the Quarantine screen shows. */
export interface QuarantineOverview {
  view_id: number
  mode: Mode
  /** Files held, and the space deleting them would free. */
  held: Tally
  /** The next files whose time is up. `at` is in seconds since the Unix epoch. */
  next_expiry?: { at: number; files: number; size: number }
  unreadable: UnreadableBatch[]
  /** Batches (cleanups), newest first, each with its folders. */
  batches: NodeView[]
  /** Expired files deleted when the app started. */
  expired?: QuarantineReport & { at: number }
}

/** Selected files whose original place is taken again. */
export interface Conflicts {
  count: number
  /** The first few of those places. */
  samples: string[]
}

/** What to do where something is at a file's original place again. */
export type IfExists = 'replace' | 'keep_both' | 'skip'

export function quarantineOverview(): Promise<QuarantineOverview> {
  return invoke<QuarantineOverview>('quarantine_overview')
}

export function quarantineChildren(
  viewId: number,
  nodeId: number,
  offset: number,
  limit: number,
): Promise<ChildPage> {
  return invoke<ChildPage>('quarantine_children', { viewId, nodeId, offset, limit })
}

/** Which selected files would land where something already is. Changes nothing. */
export function quarantineConflicts(viewId: number, choices: Choices): Promise<Conflicts> {
  return invoke<Conflicts>('quarantine_conflicts', { viewId, choices: [...choices] })
}

export function restoreQuarantined(
  viewId: number,
  choices: Choices,
  ifExists: IfExists,
): Promise<QuarantineReport> {
  return invoke<QuarantineReport>('restore_quarantined', {
    viewId,
    choices: [...choices],
    ifExists,
  })
}

/** Deletes the selected files for good. */
export function deleteQuarantined(viewId: number, choices: Choices): Promise<QuarantineReport> {
  return invoke<QuarantineReport>('delete_quarantined', { viewId, choices: [...choices] })
}

/** Choices that select everything in the view, for "Empty quarantine now". */
export function everything(overview: QuarantineOverview): Map<number, boolean> {
  return new Map(overview.batches.map((batch) => [batch.id, true]))
}
