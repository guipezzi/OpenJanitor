// The UI's only way into the scanner: read-only commands in src-tauri.
// These types mirror the JSON the Rust side sends.
import { Channel, invoke, isTauri } from '@tauri-apps/api/core'

export type Level = 'simple' | 'advanced'
export type Risk = 'low' | 'medium' | 'review'
export type RuleStatus = 'scanned' | 'not_detected' | 'no_locations' | 'protected'

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
  description: string
  category: string
  level: Level
  risk: Risk
  /** Whether "Select recommended" may pick it (only if it's also low risk). */
  recommended: boolean
  needs_admin: boolean
  status: RuleStatus
  roots: string[]
  findings: number
  size_on_disk: number
  skipped_recent: number
  skipped_duplicates: number
  /** Matching files the user protected. */
  skipped_user_protected: number
  walk: WalkStats
  warnings: string[]
}

/** Where a running scan is (oj_core::ScanProgress). */
export interface ScanProgress {
  /** Position of the rule being scanned, counting from 0. */
  rule_index: number
  rule_count: number
  rule_id: string
  rule_name: string
  files_checked: number
  findings: number
  size_on_disk: number
}

export type NodeKind = 'category' | 'rule' | 'location' | 'folder' | 'file'

/** One item of the results tree (oj_core::NodeView). */
export interface NodeView {
  id: number
  kind: NodeKind
  name: string
  rule_id?: string
  risk?: Risk
  recommended?: boolean
  needs_admin: boolean
  size_on_disk: number
  file_count: number
  /** Seconds since the Unix epoch. */
  last_modified: number
  /** For display only: commands take node ids, never paths. */
  path?: string
  evidence?: string[]
  has_children: boolean
  /** Children sent ahead of time; otherwise use scanChildren. */
  children?: NodeView[]
}

export interface ChildPage {
  items: NodeView[]
  total: number
}

export interface ScanOverview {
  scan_id: number
  level: Level
  findings_total: number
  size_on_disk_total: number
  rules: RuleReport[]
  /** Categories, biggest first, each with its rules in `children`. */
  categories: NodeView[]
}

export type ScanOutcome =
  | { status: 'completed'; overview: ScanOverview }
  | { status: 'cancelled' }

/**
 * The rule needs administrator rights and some of its folders couldn't be
 * read, so it may have missed files. (The elevated helper will read them.)
 */
export function couldNotRead(rule: RuleReport): boolean {
  return rule.needs_admin && rule.walk.unreadable > 0
}

/** False when the UI runs in a plain browser instead of the Tauri window. */
export function canScan(): boolean {
  return isTauri()
}

/** Runs a read-only scan. Nothing is deleted or moved. */
export function scan(
  level: Level,
  onProgress: (progress: ScanProgress) => void,
): Promise<ScanOutcome> {
  const channel = new Channel<ScanProgress>()
  channel.onmessage = onProgress
  return invoke<ScanOutcome>('scan', { level, onProgress: channel })
}

/** Stops the running scan; `scan` then resolves as cancelled. */
export function cancelScan(): Promise<void> {
  return invoke('cancel_scan')
}

/** One page of a results tree node's children. */
export function scanChildren(
  scanId: number,
  nodeId: number,
  offset: number,
  limit: number,
): Promise<ChildPage> {
  return invoke<ChildPage>('scan_children', { scanId, nodeId, offset, limit })
}

/** Shows a location, folder, or file from the results in File Explorer. */
export function revealInExplorer(scanId: number, nodeId: number): Promise<void> {
  return invoke('reveal_in_explorer', { scanId, nodeId })
}
