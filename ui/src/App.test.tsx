import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import { canScan, scan, type RuleReport, type ScanSummary } from './lib/scan'

vi.mock('./lib/scan', () => ({
  canScan: vi.fn(() => true),
  scan: vi.fn(),
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

const summary: ScanSummary = {
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
  })

  it('starts idle and promises not to delete anything', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'OpenJanitor' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan' })).toBeEnabled()
    expect(screen.getByText(/Nothing is deleted or moved/)).toBeInTheDocument()
    expect(scan).not.toHaveBeenCalled()
  })

  it('runs a simple scan and shows what each rule found', async () => {
    vi.mocked(scan).mockResolvedValue(summary)
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(await screen.findByText('198.4 MB')).toBeInTheDocument()
    expect(scan).toHaveBeenCalledWith('simple')
    expect(screen.getByText('can be freed from 1,147 files')).toBeInTheDocument()
    expect(screen.getByText('User temporary files')).toBeInTheDocument()
    expect(screen.getByText('Not found on this PC')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'Needs administrator rights' })).toBeInTheDocument()
    expect(screen.getByText(/Nothing was deleted/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeEnabled()
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
