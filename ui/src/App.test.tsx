import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import {
  protectedEntries,
  protectItem,
  protectPattern,
  unprotect,
  type ProtectedEntry,
} from './lib/protected'
import {
  cancelScan,
  canScan,
  revealInExplorer,
  scan,
  scanChildren,
  type NodeView,
  type RuleReport,
  type ScanOutcome,
  type ScanOverview,
} from './lib/scan'

vi.mock('./lib/protected', () => ({
  protectedEntries: vi.fn(),
  protectItem: vi.fn(),
  protectPattern: vi.fn(),
  unprotect: vi.fn(),
  exportProtected: vi.fn(),
  importProtected: vi.fn(),
}))

vi.mock('./lib/scan', async (importOriginal) => ({
  // Keep the plain helpers; replace the commands.
  ...(await importOriginal<typeof import('./lib/scan')>()),
  canScan: vi.fn(() => true),
  scan: vi.fn(),
  cancelScan: vi.fn(() => Promise.resolve()),
  scanChildren: vi.fn(),
  revealInExplorer: vi.fn(() => Promise.resolve()),
}))

function rule(overrides: Partial<RuleReport>): RuleReport {
  return {
    rule_id: 'windows.temp.user',
    name: 'User temporary files',
    description: "Files programs create while running. They're recreated when needed.",
    category: 'temporary-files',
    level: 'simple',
    risk: 'low',
    recommended: true,
    needs_admin: false,
    status: 'scanned',
    roots: ['C:\\Users\\test\\AppData\\Local\\Temp'],
    findings: 0,
    size_on_disk: 0,
    skipped_recent: 0,
    skipped_duplicates: 0,
    skipped_user_protected: 0,
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

function node(id: number, kind: NodeView['kind'], name: string, files: number, size: number, extra: Partial<NodeView> = {}): NodeView {
  return {
    id,
    kind,
    name,
    needs_admin: false,
    size_on_disk: size,
    file_count: files,
    last_modified: 1_763_740_800,
    has_children: kind !== 'file',
    ...extra,
  }
}

const TEMP = 'C:\\Users\\test\\AppData\\Local\\Temp'
const userTemp = node(2, 'rule', 'User temporary files', 1100, 200_000_000, {
  rule_id: 'windows.temp.user',
  risk: 'low',
})
const systemTemp = node(3, 'rule', 'Windows temporary files', 47, 8_037_478, {
  rule_id: 'windows.temp.system',
  risk: 'low',
  needs_admin: true,
})
const dumps = node(5, 'rule', 'Crash dumps', 10, 1_048_576, {
  rule_id: 'windows.crash-dumps.user',
  risk: 'medium',
})

const overview: ScanOverview = {
  scan_id: 1,
  level: 'simple',
  findings_total: 1157,
  size_on_disk_total: 209_086_054,
  rules: [
    rule({ findings: 1100, size_on_disk: 200_000_000 }),
    rule({
      rule_id: 'windows.temp.system',
      name: 'Windows temporary files',
      needs_admin: true,
      findings: 47,
      size_on_disk: 8_037_478,
    }),
    rule({ rule_id: 'windows.crash-dumps.user', name: 'Crash dumps', category: 'crash-reports', risk: 'medium', findings: 10 }),
    rule({ rule_id: 'windows.thumbnail-cache', name: 'Thumbnail cache', status: 'no_locations' }),
    rule({
      rule_id: 'windows.crash-dumps.system',
      name: 'System crash dumps',
      category: 'crash-reports',
      needs_admin: true,
      walk: { ...rule({}).walk, unreadable: 2 },
    }),
  ],
  categories: [
    node(1, 'category', 'temporary-files', 1147, 208_037_478, {
      needs_admin: true,
      children: [userTemp, systemTemp],
    }),
    node(4, 'category', 'crash-reports', 10, 1_048_576, { children: [dumps] }),
  ],
}

const setupFolder = node(10, 'folder', 'setup', 2, 300, {
  rule_id: 'windows.temp.user',
  risk: 'low',
  path: `${TEMP}\\setup`,
})
const oldFile = node(11, 'file', 'old.tmp', 1, 100, {
  rule_id: 'windows.temp.user',
  risk: 'low',
  path: `${TEMP}\\old.tmp`,
  evidence: [`Found in ${TEMP} by rule windows.temp.user`, 'Last modified 3 days ago'],
})

async function scanned() {
  vi.mocked(scan).mockResolvedValue({ status: 'completed', overview })
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
  await screen.findByText('199.4 MB')
}

/** The selection summary at the bottom. */
const footer = () => screen.getByText(/files? selected ·/)

describe('App', () => {
  beforeEach(() => {
    vi.mocked(canScan).mockReturnValue(true)
    vi.mocked(scan).mockReset()
    vi.mocked(cancelScan).mockClear()
    vi.mocked(revealInExplorer).mockClear()
    vi.mocked(scanChildren).mockReset()
    vi.mocked(scanChildren).mockResolvedValue({ items: [setupFolder, oldFile], total: 2 })
  })

  it('starts idle and promises not to delete anything', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'OpenJanitor' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan' })).toBeEnabled()
    expect(screen.getByText(/Nothing is deleted or moved/)).toBeInTheDocument()
    expect(scan).not.toHaveBeenCalled()
  })

  it('shows the results as a tree, with nothing selected', async () => {
    await scanned()

    expect(scan).toHaveBeenCalledWith('simple', expect.any(Function))
    expect(screen.getByText('can be freed from 1,157 files')).toBeInTheDocument()
    expect(screen.getByText('Temporary files')).toBeInTheDocument()
    expect(screen.getByText('Crash and error reports')).toBeInTheDocument()
    expect(screen.getByText('User temporary files')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'Needs administrator rights' })).toBeInTheDocument()
    expect(screen.getByText('Also checked, nothing to clean: Thumbnail cache')).toBeInTheDocument()
    expect(
      screen.getByText(/Couldn't fully check without administrator rights: System crash dumps\./),
    ).toBeInTheDocument()
    expect(screen.getByText('Nothing selected')).toBeInTheDocument()
    for (const box of screen.getAllByRole('checkbox')) {
      expect(box).toHaveAttribute('aria-checked', 'false')
    }
  })

  it('selects the low-risk rules when asked, and clears them', async () => {
    await scanned()

    fireEvent.click(screen.getByRole('button', { name: 'Select recommended' }))
    expect(footer()).toHaveTextContent('1,147 files selected · 198.4 MB')
    expect(screen.getByRole('checkbox', { name: 'Select Temporary files' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('checkbox', { name: 'Select Crash dumps' })).toHaveAttribute('aria-checked', 'false')

    fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
    expect(screen.getByText('Nothing selected')).toBeInTheDocument()
  })

  it('loads a rule on demand and shows partial selection', async () => {
    await scanned()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select User temporary files' }))
    expect(footer()).toHaveTextContent('1,100 files selected')

    fireEvent.click(screen.getByRole('button', { name: 'Expand User temporary files' }))
    expect(await screen.findByText('setup')).toBeInTheDocument()
    expect(scanChildren).toHaveBeenCalledWith(1, 2, 0, 200)

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select setup' }))
    expect(footer()).toHaveTextContent('1,098 files selected')
    expect(screen.getByRole('checkbox', { name: 'Select User temporary files' })).toHaveAttribute('aria-checked', 'mixed')
    expect(screen.getByRole('checkbox', { name: 'Select old.tmp' })).toHaveAttribute('aria-checked', 'true')
  })

  it('explains an item and opens it in Explorer', async () => {
    await scanned()
    fireEvent.click(screen.getByRole('button', { name: 'Expand User temporary files' }))
    fireEvent.click(await screen.findByText('old.tmp'))

    const details = screen.getByRole('complementary', { name: 'Details' })
    expect(within(details).getByText('File')).toBeInTheDocument()
    expect(within(details).getByText(/Files programs create while running/)).toBeInTheDocument()
    expect(within(details).getByText('Last modified 3 days ago')).toBeInTheDocument()
    expect(within(details).getByText(`${TEMP}\\old.tmp`)).toBeInTheDocument()

    fireEvent.click(within(details).getByRole('button', { name: 'Open in Explorer' }))
    expect(revealInExplorer).toHaveBeenCalledWith(1, 11)
  })

  it('protects an item from its details and keeps the selection', async () => {
    const withoutOldFile: ScanOverview = { ...overview, findings_total: 1156 }
    vi.mocked(protectItem).mockResolvedValue({ entries: [], overview: withoutOldFile, added: 1 })
    await scanned()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Windows temporary files' }))
    fireEvent.click(screen.getByRole('button', { name: 'Expand User temporary files' }))
    fireEvent.click(await screen.findByText('old.tmp'))

    const details = screen.getByRole('complementary', { name: 'Details' })
    fireEvent.click(within(details).getByRole('button', { name: 'Protect' }))

    expect(await screen.findByText(/Protected "old.tmp"/)).toBeInTheDocument()
    expect(protectItem).toHaveBeenCalledWith(1, 11)
    expect(screen.getByText('can be freed from 1,156 files')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Select Windows temporary files' })).toHaveAttribute(
      'aria-checked',
      'true',
    )
    expect(screen.getByText(/Select an item to see/)).toBeInTheDocument()
  })

  it('lists rules that were not scanned because they are protected', async () => {
    vi.mocked(scan).mockResolvedValue({
      status: 'completed',
      overview: {
        ...overview,
        rules: [
          ...overview.rules,
          rule({ rule_id: 'app.slack.cache', name: 'Slack cache', status: 'protected' }),
        ],
      },
    })
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(
      await screen.findByText('Not scanned, because you protected them: Slack cache'),
    ).toBeInTheDocument()
    expect(screen.getByText('Also checked, nothing to clean: Thumbnail cache')).toBeInTheDocument()
  })

  it('manages the Protected list on its own screen', async () => {
    const folder: ProtectedEntry = {
      kind: 'folder',
      value: 'C:\\Users\\test\\AppData\\Local\\Temp\\keep',
      added_at: 1_763_740_800,
    }
    const pattern: ProtectedEntry = { kind: 'pattern', value: '*.psd', added_at: 1_763_740_900 }
    vi.mocked(protectedEntries).mockResolvedValue([folder])
    vi.mocked(protectPattern).mockResolvedValue({
      entries: [folder, pattern],
      overview: null,
      added: 1,
    })
    vi.mocked(unprotect).mockResolvedValue([pattern])
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Protected' }))

    expect(await screen.findByText(folder.value)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Protect files matching a pattern'), {
      target: { value: '*.psd' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('*.psd')).toBeInTheDocument()
    expect(protectPattern).toHaveBeenCalledWith('*.psd')

    fireEvent.click(screen.getByRole('button', { name: `Stop protecting ${folder.value}` }))
    await waitFor(() => expect(screen.queryByText(folder.value)).not.toBeInTheDocument())
    expect(unprotect).toHaveBeenCalledWith('folder', folder.value)
    expect(screen.getByRole('status')).toHaveTextContent('show up again on the next scan')
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
