// Cleaning (PLANNING.md sections 4.4 and 4.5), through commands in
// src-tauri. The UI sends its selection as node ids, never paths, and runs
// a plan only by the id the confirmation showed.
import { Channel, invoke } from '@tauri-apps/api/core'

import type { Choices, Tally } from './selection'

/** `dry_run`: nothing is deleted or moved; the results say what would happen. */
export type Mode = 'dry_run' | 'live'

/** Files that go to quarantine for the same number of days. */
export interface QuarantineGroup {
  days: number
  files: number
  size: number
}

/** A cleanup plan in totals: what the confirmation shows. */
export interface CleanPlan {
  plan_id: number
  mode: Mode
  /** Deleted for good. */
  delete: Tally
  /** Moved to quarantine, shortest stay first. */
  quarantine: QuarantineGroup[]
  /** Selected, but left out: they need administrator rights. */
  needs_admin: Tally
  /** When the scan finished, in seconds since the Unix epoch. */
  scanned_at: number
  /** The results are old enough that scanning again first is worth it. */
  stale: boolean
}

/** Where a running cleanup is. */
export interface CleanProgress {
  done: number
  total: number
  /** Space freed so far. */
  freed: number
}

export type SkipReason =
  | 'denied'
  | 'protected'
  | 'missing'
  | 'changed'
  | 'not_a_regular_file'
  | 'in_use'
  | 'access_denied'
  | 'other_drive'
  | 'conflict'
  | 'not_in_quarantine'
  | 'not_empty'
  | 'outside_location'
  | 'failed'

/** What a cleanup did (oj_core::CleanReport). */
export interface CleanReport {
  mode: Mode
  /** Stopped early; `not_started` files weren't touched. */
  cancelled: boolean
  /** Deleted for good (in a dry run: would have been). */
  deleted: Tally
  /** In quarantine now. `expires_at` is in seconds since the Unix epoch. */
  quarantined: (QuarantineGroup & { expires_at: number })[]
  batch?: string
  /** Files left alone, most common reason first. */
  skipped: { reason: SkipReason; files: number }[]
  not_started: number
  folders_removed: number
  needs_admin: Tally
  history_error?: string
}

/** Files the plan will act on. */
export function plannedFiles(plan: CleanPlan): number {
  return plan.delete.files + plan.quarantine.reduce((sum, group) => sum + group.files, 0)
}

/** Builds the plan for the current selection. Changes nothing. */
export function planClean(scanId: number, choices: Choices): Promise<CleanPlan> {
  return invoke<CleanPlan>('plan_clean', { scanId, choices: [...choices] })
}

/** Runs exactly the plan the user confirmed. Afterwards, the results are gone. */
export function runClean(
  planId: number,
  onProgress: (progress: CleanProgress) => void,
): Promise<CleanReport> {
  const channel = new Channel<CleanProgress>()
  channel.onmessage = onProgress
  return invoke<CleanReport>('run_clean', { planId, onProgress: channel })
}

/** Stops the running cleanup after the file it's on. */
export function cancelClean(): Promise<void> {
  return invoke('cancel_clean')
}
