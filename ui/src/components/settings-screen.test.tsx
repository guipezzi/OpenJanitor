import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { SettingsScreen } from './settings-screen'
import {
  resetSettings,
  saveSettings,
  settingsOverview,
  type Settings,
  type SettingsOverview,
} from '@/lib/settings'
import { applyTheme } from '@/lib/theme'

vi.mock('@/lib/settings', () => ({
  settingsOverview: vi.fn(),
  saveSettings: vi.fn(),
  resetSettings: vi.fn(),
}))

vi.mock('@/lib/theme', () => ({
  applyTheme: vi.fn(),
}))

const defaults: Settings = {
  min_age_days: 1,
  always_quarantine: false,
  medium_days: 7,
  review_days: 30,
  theme: 'system',
  drives: [],
}

function overview(settings: Partial<Settings> | null, error?: string): SettingsOverview {
  return {
    settings: settings ? { ...defaults, ...settings } : undefined,
    error,
    choices: { min_age_days: [1, 3, 7, 30], medium_days: [7, 14, 30], review_days: [30, 60, 90] },
    defaults,
  }
}

async function shown(loaded: SettingsOverview = overview({})) {
  vi.mocked(settingsOverview).mockResolvedValue(loaded)
  render(<SettingsScreen active />)
  await screen.findByText('Changes are saved as soon as you make them.')
  await waitFor(() => expect(applyTheme).toHaveBeenCalled())
}

const group = (name: string) => screen.getByRole('radiogroup', { name })
const choice = (groupName: string, label: string) => within(group(groupName)).getByRole('radio', { name: label })

describe('SettingsScreen', () => {
  beforeEach(() => {
    vi.mocked(settingsOverview).mockReset()
    vi.mocked(saveSettings).mockReset()
    vi.mocked(resetSettings).mockReset()
    vi.mocked(applyTheme).mockReset()
    vi.mocked(saveSettings).mockImplementation((settings) => Promise.resolve(settings))
  })

  it('shows the saved choices', async () => {
    await shown(overview({ min_age_days: 7, review_days: 90, theme: 'dark' }))

    expect(within(group('Minimum file age')).getAllByRole('radio').map((radio) => radio.textContent)).toEqual([
      '24 hours',
      '3 days',
      '7 days',
      '30 days',
    ])
    expect(choice('Minimum file age', '7 days')).toHaveAttribute('aria-checked', 'true')
    expect(choice('Keep medium-risk files for', '7 days')).toHaveAttribute('aria-checked', 'true')
    expect(choice('Keep files marked Review for', '90 days')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('switch', { name: 'Always use the quarantine' })).not.toBeChecked()
    expect(choice('Theme', 'Dark')).toHaveAttribute('aria-checked', 'true')
    expect(applyTheme).toHaveBeenLastCalledWith('dark')
    expect(screen.getByRole('button', { name: 'Restore defaults' })).toBeEnabled()
  })

  it('saves each change at once', async () => {
    await shown()
    expect(screen.getByRole('button', { name: 'Restore defaults' })).toBeDisabled()

    fireEvent.click(choice('Minimum file age', '3 days'))

    expect(saveSettings).toHaveBeenCalledWith({ ...defaults, min_age_days: 3 })
    expect(await screen.findByText('Saved')).toBeInTheDocument()
    expect(choice('Minimum file age', '3 days')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('button', { name: 'Restore defaults' })).toBeEnabled()
  })

  it('warns that always quarantining frees no space right away', async () => {
    await shown()
    expect(screen.queryByText(/won't free space right away/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('switch', { name: 'Always use the quarantine' }))

    expect(saveSettings).toHaveBeenCalledWith({ ...defaults, always_quarantine: true })
    expect(await screen.findByText('Saved')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Always use the quarantine' })).toBeChecked()
    expect(screen.getByText(/won't free space right away/)).toBeInTheDocument()
    expect(screen.getByText('Low-risk files are kept this long too.')).toBeInTheDocument()
  })

  it('shows a new theme right away', async () => {
    await shown()
    fireEvent.click(choice('Theme', 'Light'))

    expect(applyTheme).toHaveBeenLastCalledWith('light')
    expect(saveSettings).toHaveBeenCalledWith({ ...defaults, theme: 'light' })
    expect(await screen.findByText('Saved')).toBeInTheDocument()
  })

  it('goes back to what was saved when a change fails', async () => {
    await shown()
    vi.mocked(saveSettings).mockRejectedValueOnce('Access denied')

    fireEvent.click(choice('Keep medium-risk files for', '30 days'))

    expect(await screen.findByText("Couldn't save that change")).toBeInTheDocument()
    expect(screen.getByText('Access denied')).toBeInTheDocument()
    expect(choice('Keep medium-risk files for', '7 days')).toHaveAttribute('aria-checked', 'true')
    expect(screen.queryByText('Saved')).not.toBeInTheDocument()
  })

  it('offers only the defaults when the file is damaged', async () => {
    const error = 'Your settings (C:\\OJ\\settings.json) couldn\'t be read: the file isn\'t valid.'
    await shown(overview(null, error))

    expect(screen.getByText("Your settings couldn't be read")).toBeInTheDocument()
    expect(screen.getByText(error)).toBeInTheDocument()
    expect(screen.getByText(/Scanning and cleaning are paused/)).toBeInTheDocument()
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument()
    expect(applyTheme).toHaveBeenLastCalledWith('system')

    vi.mocked(resetSettings).mockResolvedValue(defaults)
    fireEvent.click(screen.getByRole('button', { name: 'Restore defaults' }))

    expect(await screen.findByText('Saved')).toBeInTheDocument()
    expect(resetSettings).toHaveBeenCalled()
    expect(screen.queryByText("Your settings couldn't be read")).not.toBeInTheDocument()
    expect(choice('Minimum file age', '24 hours')).toHaveAttribute('aria-checked', 'true')
  })

  it('shows why the settings could not be opened', async () => {
    vi.mocked(settingsOverview).mockRejectedValue('No app data folder')
    render(<SettingsScreen active />)

    expect(await screen.findByText("Couldn't open your settings")).toBeInTheDocument()
    expect(screen.getByText('No app data folder')).toBeInTheDocument()
  })
})
