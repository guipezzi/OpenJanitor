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

/** One drive's Recycle Bin, in totals. */
export interface BinTally {
  /** The drive letter, such as "C". */
  drive: string
  /** A deleted folder counts as one item, whatever is inside. */
  items: number
  size: number
}

/** Selected files left out because their app is open. */
export interface OpenApp {
  /** Such as "Google Chrome". */
  name: string
  files: number
  size: number
}

/** A cleanup plan in totals: what the confirmation shows. */
export interface CleanPlan {
  plan_id: number
  mode: Mode
  /** Files deleted for good. */
  delete: Tally
  /** Files deleted for good by the elevated helper, after one UAC prompt. */
  elevated: Tally
  /** Recycle Bins emptied for good, each as a whole. */
  recycle_bins: BinTally[]
  /** Moved to quarantine, shortest stay first. */
  quarantine: QuarantineGroup[]
  /** Selected, but left out: they need administrator rights and would go to quarantine. */
  needs_admin: Tally
  /** Selected, but left out: their app is open. Biggest first. */
  apps_open: OpenApp[]
  /** Selected, but left out: "Always use the quarantine" is on. */
  recycle_bins_kept: BinTally[]
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
  /** Waiting for the user to answer Windows' administrator prompt. */
  admin_prompt: boolean
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
  | 'app_running'
  | 'admin_declined'
  | 'outside_rule'
  | 'failed'

/** What a cleanup did (oj_core::CleanReport). */
export interface CleanReport {
  mode: Mode
  /** Stopped early; `not_started` files weren't touched. */
  cancelled: boolean
  /** Files deleted for good (in a dry run: would have been). */
  deleted: Tally
  /** Recycle Bins emptied (in a dry run: would have been). Not in `deleted`. */
  recycle_bins: BinTally[]
  /** Recycle Bins left alone, such as one that changed since the scan. */
  recycle_bins_skipped: { drive: string; reason: SkipReason }[]
  /** In quarantine now. `expires_at` is in seconds since the Unix epoch. */
  quarantined: (QuarantineGroup & { expires_at: number })[]
  batch?: string
  /** Files left alone, most common reason first. */
  skipped: { reason: SkipReason; files: number }[]
  not_started: number
  folders_removed: number
  needs_admin: Tally
  /** Left out because their app was open. */
  apps_open: OpenApp[]
  /** Left out because "Always use the quarantine" is on. */
  recycle_bins_kept: BinTally[]
  history_error?: string
}

/** Whether the plan acts on anything: files, or a Recycle Bin. */
export function plansAnything(plan: CleanPlan): boolean {
  const files =
    plan.delete.files +
    plan.elevated.files +
    plan.quarantine.reduce((sum, group) => sum + group.files, 0)
  return files > 0 || plan.recycle_bins.length > 0
}

/** Items in the Recycle Bins a plan or a cleanup empties. */
export function binItems(bins: readonly BinTally[]): number {
  return bins.reduce((sum, bin) => sum + bin.items, 0)
}

/** Space a cleanup freed for good: deleted files plus emptied Recycle Bins. */
export function freedBy(report: CleanReport): number {
  return report.deleted.size + report.recycle_bins.reduce((sum, bin) => sum + bin.size, 0)
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
