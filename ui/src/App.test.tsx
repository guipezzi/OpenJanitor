import { act, fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import {
  cancelScan,
  canScan,
  scan,
  type RuleReport,
  type ScanOutcome,
  type ScanOverview,
} from './lib/scan'

vi.mock('./lib/scan', () => ({
  canScan: vi.fn(() => true),
  scan: vi.fn(),
  cancelScan: vi.fn(() => Promise.resolve()),
}))

function rule(overrides: Partial<RuleReport>): RuleReport {
  return {
    rule_id: 'windows.temp.user',
    name: 'User temporary files',
    category: 'temporary-files',
    level: 'simple',
    risk: 'low',
    needs_admin: false,
    status: 'scanned',
    roots: ['C:\\Users\\test\\AppData\\Local\\Temp'],
    findings: 0,
    size_on_disk: 0,
    skipped_recent: 0,
    skipped_duplicates: 0,
    walk: {
      files: 0,
      directories: 0,
      skipped_reparse_points: 0,
      skipped_cloud_files: 0,
      skipped_protected: 0,
      unreadable: 0,
      unreadable_samples: [],
    },
    warnings: [],
    ...overrides,
  }
}

const overview: ScanOverview = {
  scan_id: 1,
  categories: [],
  level: 'simple',
  findings_total: 1147,
  size_on_disk_total: 208_037_478,
  rules: [
    rule({ findings: 1100, size_on_disk: 200_000_000 }),
    rule({
      rule_id: 'windows.temp.system',
      name: 'Windows temporary files',
      needs_admin: true,
      findings: 47,
      size_on_disk: 8_037_478,
    }),
    rule({ rule_id: 'windows.crash-dumps.user', name: 'Crash dumps', status: 'no_locations' }),
  ],
}

describe('App', () => {
  beforeEach(() => {
    vi.mocked(canScan).mockReturnValue(true)
    vi.mocked(scan).mockReset()
    vi.mocked(cancelScan).mockClear()
  })

  it('starts idle and promises not to delete anything', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'OpenJanitor' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan' })).toBeEnabled()
    expect(screen.getByText(/Nothing is deleted or moved/)).toBeInTheDocument()
    expect(scan).not.toHaveBeenCalled()
  })

  it('runs a simple scan and shows what each rule found', async () => {
    vi.mocked(scan).mockResolvedValue({ status: 'completed', overview })
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(await screen.findByText('198.4 MB')).toBeInTheDocument()
    expect(scan).toHaveBeenCalledWith('simple', expect.any(Function))
    expect(screen.getByText('can be freed from 1,147 files')).toBeInTheDocument()
    expect(screen.getByText('User temporary files')).toBeInTheDocument()
    expect(screen.getByText('Not found on this PC')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'Needs administrator rights' })).toBeInTheDocument()
    expect(screen.getByText(/Nothing was deleted/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeEnabled()
  })

  it('shows progress while scanning and can cancel', async () => {
    let finish: (outcome: ScanOutcome) => void = () => {}
    vi.mocked(scan).mockImplementation((_level, onProgress) => {
      onProgress({
        rule_index: 0,
        rule_count: 4,
        rule_id: 'windows.temp.user',
        rule_name: 'User temporary files',
        files_checked: 1234,
        findings: 10,
        size_on_disk: 1536 * 1024,
      })
      return new Promise((resolve) => {
        finish = resolve
      })
    })
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(await screen.findByText('Checking User temporary files')).toBeInTheDocument()
    expect(screen.getByText('Step 1 of 4 · 1,234 files checked')).toBeInTheDocument()
    expect(screen.getByText('Found so far: 1.5 MB')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Scanning/ })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(cancelScan).toHaveBeenCalled()
    expect(await screen.findByRole('button', { name: 'Cancelling…' })).toBeDisabled()

    await act(async () => finish({ status: 'cancelled' }))
    expect(screen.getByText('Scan cancelled. Nothing was changed.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan' })).toBeEnabled()
  })

  it('shows the error when the scan fails', async () => {
    vi.mocked(scan).mockRejectedValue('Access denied')
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(await screen.findByText("The scan couldn't finish")).toBeInTheDocument()
    expect(screen.getByText('Access denied')).toBeInTheDocument()
  })

  it('explains that scanning needs the desktop app', () => {
    vi.mocked(canScan).mockReturnValue(false)
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(screen.getByText(/Scanning works in the desktop app/)).toBeInTheDocument()
    expect(scan).not.toHaveBeenCalled()
  })
})
