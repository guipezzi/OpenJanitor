// The UI's only way into the scanner: the read-only `scan` command in
// src-tauri. These types mirror the JSON the Rust side sends.
import { invoke, isTauri } from '@tauri-apps/api/core'

export type Level = 'simple' | 'advanced'
export type Risk = 'low' | 'medium' | 'review'
export type RuleStatus = 'scanned' | 'not_detected' | 'no_locations'

export interface WalkStats {
  files: number
  directories: number
  skipped_reparse_points: number
  skipped_cloud_files: number
  skipped_protected: number
  unreadable: number
  unreadable_samples: string[]
}

/** What one rule found (oj_core::RuleReport). */
export interface RuleReport {
  rule_id: string
  name: string
  category: string
  level: Level
  risk: Risk
  needs_admin: boolean
  status: RuleStatus
  roots: string[]
  findings: number
  size_on_disk: number
  skipped_recent: number
  skipped_duplicates: number
  walk: WalkStats
  warnings: string[]
}

export interface ScanSummary {
  level: Level
  findings_total: number
  size_on_disk_total: number
  rules: RuleReport[]
}

/** False when the UI runs in a plain browser instead of the Tauri window. */
export function canScan(): boolean {
  return isTauri()
}

/** Runs a read-only scan. Nothing is deleted or moved. */
export function scan(level: Level): Promise<ScanSummary> {
  return invoke<ScanSummary>('scan', { level })
}
