// Settings (PLANNING.md section 7.4 and D31), through commands in src-tauri.
// Scans and cleanups read the saved file themselves; the UI only shows and
// changes it.
import { invoke, isTauri } from '@tauri-apps/api/core'

import { applyTheme, type ThemeChoice } from './theme'

/** oj_core::Settings. Every value is one of the choices offered. */
export interface Settings {
  /** Files changed more recently are left out, unless a rule waits longer. */
  min_age_days: number
  /** Low-risk files go to quarantine too, for `medium_days`. */
  always_quarantine: boolean
  medium_days: number
  review_days: number
  theme: ThemeChoice
  /** The drives to scan, by volume ID; empty means the system drive. Changed on the Clean screen. */
  drives: string[]
}

export interface SettingsChoices {
  min_age_days: number[]
  medium_days: number[]
  review_days: number[]
}

export interface SettingsOverview {
  /** Missing when the file couldn't be read. */
  settings?: Settings
  /** Why the file couldn't be read. Scans and cleanups refuse until it's fixed. */
  error?: string
  choices: SettingsChoices
  defaults: Settings
}

export function settingsOverview(): Promise<SettingsOverview> {
  return invoke<SettingsOverview>('settings_overview')
}

/** Saves every setting at once; returns what was saved. */
export function saveSettings(settings: Settings): Promise<Settings> {
  return invoke<Settings>('save_settings', { settings })
}

/** Puts every setting back to its default, replacing a damaged file too. */
export function resetSettings(): Promise<Settings> {
  return invoke<Settings>('reset_settings')
}

/** At startup: shows the saved theme, or the system's if it can't be read. */
export function applySavedTheme(): void {
  applyTheme('system')
  if (!isTauri()) return
  settingsOverview().then(
    (overview) => applyTheme(overview.settings?.theme ?? 'system'),
    () => {},
  )
}
