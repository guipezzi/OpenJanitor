import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import {
  cancelClean,
  planClean,
  runClean,
  type CleanPlan,
  type CleanProgress,
  type CleanReport,
} from './lib/clean'
import { drivesOverview, selectDrives, type Drive } from './lib/drives'
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
  openRecycleBin,
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

vi.mock('./lib/drives', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./lib/drives')>()),
  drivesOverview: vi.fn(),
  selectDrives: vi.fn(),
}))

vi.mock('./lib/clean', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./lib/clean')>()),
  planClean: vi.fn(),
  runClean: vi.fn(),
  cancelClean: vi.fn(() => Promise.resolve()),
}))

vi.mock('./lib/scan', async (importOriginal) => ({
  // Keep the plain helpers; replace the commands.
  ...(await importOriginal<typeof import('./lib/scan')>()),
  canScan: vi.fn(() => true),
  scan: vi.fn(),
  cancelScan: vi.fn(() => Promise.resolve()),
  scanChildren: vi.fn(),
  revealInExplorer: vi.fn(() => Promise.resolve()),
  openRecycleBin: vi.fn(() => Promise.resolve()),
}))

const systemDrive: Drive = {
  letter: 'C',
  id: '\\\\?\\Volume{d88dd716-bfa6-48d0-997b-aadbcb888cb8}\\',
  label: 'Windows-SSD',
  file_system: 'NTFS',
  total: 509_722_226_688,
  free: 50_792_275_968,
  media: 'ssd',
  connection: 'internal',
  status: 'ready',
  system: true,
  selected: true,
}
const externalDrive: Drive = {
  ...systemDrive,
  letter: 'D',
  id: '\\\\?\\Volume{61a9a736-71b3-4fb5-b31f-c1973df5af1f}\\',
  label: 'SSD Externo',
  connection: 'external',
  system: false,
  selected: false,
}

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

const plan: CleanPlan = {
  plan_id: 7,
  mode: 'live',
  delete: { files: 1100, size: 200_000_000 },
  quarantine: [{ days: 7, files: 10, size: 1_048_576 }],
  needs_admin: { files: 47, size: 8_037_478 },
  apps_open: [],
  recycle_bins: [],
  recycle_bins_kept: [],
  scanned_at: Math.floor(Date.now() / 1000),
  stale: false,
}

const cleaned: CleanReport = {
  mode: 'live',
  cancelled: false,
  deleted: { files: 1097, size: 199_000_000 },
  recycle_bins: [],
  recycle_bins_skipped: [],
  quarantined: [{ days: 7, files: 10, size: 1_048_576, expires_at: 1_764_345_600 }],
  batch: '20251121-160000',
  skipped: [{ reason: 'in_use', files: 3 }],
  not_started: 0,
  folders_removed: 4,
  needs_admin: { files: 47, size: 8_037_478 },
  apps_open: [],
  recycle_bins_kept: [],
}

/** The Recycle Bin on C:, as plans and reports show it. */
const fullBin = { drive: 'C', items: 42, size: 1_500_000_000 }

/** Scans, selects the recommended items, and opens the confirmation. */
async function reviewing(withPlan: CleanPlan) {
  vi.mocked(planClean).mockResolvedValue(withPlan)
  await scanned()
  fireEvent.click(screen.getByRole('button', { name: 'Select recommended' }))
  fireEvent.click(screen.getByRole('button', { name: 'Clean…' }))
  return screen.findByRole('alertdialog', { name: 'Review this cleanup' })
}

describe('App', () => {
  beforeEach(() => {
    vi.mocked(canScan).mockReturnValue(true)
    vi.mocked(scan).mockReset()
    vi.mocked(cancelScan).mockClear()
    vi.mocked(revealInExplorer).mockClear()
    vi.mocked(scanChildren).mockReset()
    vi.mocked(scanChildren).mockResolvedValue({ items: [setupFolder, oldFile], total: 2 })
    vi.mocked(planClean).mockReset()
    vi.mocked(runClean).mockReset()
    vi.mocked(cancelClean).mockClear()
    vi.mocked(drivesOverview).mockResolvedValue({ drives: [systemDrive, externalDrive] })
    vi.mocked(selectDrives).mockReset()
  })

  it("doesn't call it tidy when the Windows drive wasn't scanned", async () => {
    vi.mocked(scan).mockResolvedValue({
      status: 'completed',
      overview: {
        ...overview,
        findings_total: 0,
        size_on_disk_total: 0,
        rules: [rule({ status: 'not_selected' })],
        categories: [],
      },
    })
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    expect(await screen.findByText(/Nothing to clean on the selected drives/)).toBeInTheDocument()
    expect(screen.queryByText(/already tidy/)).not.toBeInTheDocument()
  })

  it('clears the results when the drives to scan change', async () => {
    await scanned()
    const drives = screen.getByRole('region', { name: 'Drives to scan' })
    expect(within(drives).getByText('Windows-SSD (C:)')).toBeInTheDocument()

    vi.mocked(selectDrives).mockResolvedValue({
      drives: [systemDrive, { ...externalDrive, selected: true }],
    })
    fireEvent.click(within(drives).getByRole('checkbox', { name: /SSD Externo \(D:\)/ }))

    expect(await screen.findByText(/The drives to scan changed/)).toBeInTheDocument()
    expect(selectDrives).toHaveBeenCalledWith([systemDrive.id, externalDrive.id])
    expect(screen.queryByRole('group', { name: 'Scan results' })).not.toBeInTheDocument()
    expect(within(drives).getByText(/only empties the Recycle Bin/)).toBeInTheDocument()
  })

  it('reviews a cleanup, then runs exactly that plan', async () => {
    const dialog = await reviewing(plan)

    expect(planClean).toHaveBeenCalledWith(
      1,
      new Map([
        [2, true],
        [3, true],
      ]),
    )
    expect(within(dialog).getByText('Deleted permanently')).toBeInTheDocument()
    expect(within(dialog).getByText('· 1,100 files · 190.7 MB')).toBeInTheDocument()
    expect(within(dialog).getByText('Moved to quarantine for 7 days')).toBeInTheDocument()
    expect(within(dialog).getByText('· 10 files · 1.0 MB')).toBeInTheDocument()
    expect(within(dialog).getByText('Left out')).toBeInTheDocument()
    expect(within(dialog).getByText(/need administrator rights/)).toBeInTheDocument()
    expect(within(dialog).queryByText(/Test mode/)).not.toBeInTheDocument()
    expect(within(dialog).queryByText(/These results are from/)).not.toBeInTheDocument()

    // Nothing runs until the box is ticked.
    const confirm = within(dialog).getByRole('button', { name: 'Delete and quarantine' })
    expect(confirm).toBeDisabled()
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: 'I understand that 1,100 files will be permanently deleted.',
      }),
    )
    expect(confirm).toBeEnabled()

    vi.mocked(runClean).mockResolvedValue(cleaned)
    fireEvent.click(confirm)

    const summary = await screen.findByRole('region', { name: 'Cleanup finished' })
    expect(runClean).toHaveBeenCalledWith(7, expect.any(Function))
    expect(within(summary).getByText('189.8 MB')).toBeInTheDocument()
    expect(within(summary).getByText('freed now')).toBeInTheDocument()
    expect(within(summary).getByText('1,097 files deleted permanently')).toBeInTheDocument()
    expect(
      within(summary).getByText(/10 files in quarantine \(1\.0 MB\), restorable until Nov 2[89], 2025/),
    ).toBeInTheDocument()
    expect(within(summary).getByText('Removed 4 folders the cleanup left empty.')).toBeInTheDocument()
    expect(within(summary).getByText('3 files were left alone')).toBeInTheDocument()
    expect(within(summary).getByText('In use by another program: 3')).toBeInTheDocument()
    expect(within(summary).getByText(/Close the programs using them/)).toBeInTheDocument()
    expect(
      within(summary).getByText('47 files that need administrator rights were left out.'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('tree')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeEnabled()
  })

  it('empties the Recycle Bin only after the tick, and says so', async () => {
    const dialog = await reviewing({ ...plan, recycle_bins: [fullBin] })

    expect(within(dialog).getByText('Recycle Bin emptied for good')).toBeInTheDocument()
    expect(within(dialog).getByText('· Drive C: · 42 items · 1.4 GB')).toBeInTheDocument()
    expect(within(dialog).getByText(/however recently it was deleted/)).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Delete and quarantine' })
    expect(confirm).toBeDisabled()
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: 'I understand that 1,100 files and the 42 items in the Recycle Bin will be permanently deleted.',
      }),
    )

    vi.mocked(runClean).mockResolvedValue({ ...cleaned, recycle_bins: [fullBin] })
    fireEvent.click(confirm)
    const summary = await screen.findByRole('region', { name: 'Cleanup finished' })
    expect(within(summary).getByText('1.6 GB')).toBeInTheDocument()
    expect(
      within(summary).getByText('Emptied the Recycle Bin on drive C: (42 items, 1.4 GB).'),
    ).toBeInTheDocument()
    expect(within(summary).getByText('1,097 files deleted permanently')).toBeInTheDocument()
  })

  it('can empty just the Recycle Bin, and says when it was left alone', async () => {
    const onlyBin: CleanPlan = {
      ...plan,
      delete: { files: 0, size: 0 },
      quarantine: [],
      recycle_bins: [fullBin],
    }
    const dialog = await reviewing(onlyBin)
    expect(within(dialog).queryByText('Deleted permanently')).not.toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Delete permanently' })
    expect(confirm).toBeDisabled()
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: 'I understand that the 42 items in the Recycle Bin will be permanently deleted.',
      }),
    )

    vi.mocked(runClean).mockResolvedValue({
      ...cleaned,
      deleted: { files: 0, size: 0 },
      quarantined: [],
      skipped: [],
      recycle_bins_skipped: [{ drive: 'C', reason: 'changed' }],
    })
    fireEvent.click(confirm)
    const summary = await screen.findByRole('region', { name: 'Cleanup finished' })
    expect(
      within(summary).getByText(
        'Left the Recycle Bin on drive C: alone (Changed since the scan). Scan again to empty it.',
      ),
    ).toBeInTheDocument()
  })

  it('leaves the Recycle Bin out when everything goes to quarantine', async () => {
    const careful: CleanPlan = {
      ...plan,
      delete: { files: 0, size: 0 },
      quarantine: [{ days: 7, files: 1110, size: 201_048_576 }],
      recycle_bins_kept: [fullBin],
    }
    const dialog = await reviewing(careful)
    expect(within(dialog).getByText(/the Recycle Bin can’t be moved to quarantine/)).toBeInTheDocument()
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument()

    vi.mocked(runClean).mockResolvedValue({ ...cleaned, recycle_bins_kept: [fullBin] })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Move to quarantine' }))
    const summary = await screen.findByRole('region', { name: 'Cleanup finished' })
    expect(
      within(summary).getByText(
        'Left the Recycle Bin on drive C: out, because “Always use the quarantine” is on.',
      ),
    ).toBeInTheDocument()
  })

  it('shows the Recycle Bin in items and opens it instead of Explorer', async () => {
    const bin = { rule_id: 'windows.recycle-bin', risk: 'low' as const, builtin: 'recycle-bin' }
    const binRule = node(21, 'rule', 'Recycle Bin', 42, 1_500_000_000, { ...bin, recommended: false })
    const drive = node(22, 'recycle_bin', 'C:', 42, 1_500_000_000, {
      ...bin,
      last_modified: 0,
      has_children: false,
      path: 'C:\\$Recycle.Bin',
      evidence: ['Windows counts 42 items in the Recycle Bin on drive C:'],
    })
    vi.mocked(scan).mockResolvedValue({
      status: 'completed',
      overview: {
        ...overview,
        rules: [
          ...overview.rules,
          rule({
            rule_id: 'windows.recycle-bin',
            name: 'Recycle Bin',
            category: 'recycle-bin',
            recommended: false,
            builtin: 'recycle-bin',
            description: 'Files and folders you deleted.',
            findings: 1,
          }),
        ],
        categories: [
          ...overview.categories,
          node(20, 'category', 'recycle-bin', 42, 1_500_000_000, {
            builtin: 'recycle-bin',
            children: [binRule],
          }),
        ],
      },
    })
    vi.mocked(scanChildren).mockResolvedValue({ items: [drive], total: 1 })
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))

    expect(await screen.findByText('can be freed from 1,199 files')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Select recommended' }))
    // Never preselected: the category and its rule share the name.
    for (const box of screen.getAllByRole('checkbox', { name: 'Select Recycle Bin' })) {
      expect(box).toHaveAttribute('aria-checked', 'false')
    }
    fireEvent.click(screen.getByRole('button', { name: 'Expand Recycle Bin' }))
    fireEvent.click(await screen.findByText('Drive C:'))
    expect(screen.getAllByText('42 items').length).toBeGreaterThan(0)

    const details = screen.getByRole('complementary', { name: 'Details' })
    expect(within(details).getByText('Items')).toBeInTheDocument()
    expect(within(details).queryByText('Last modified')).not.toBeInTheDocument()
    expect(within(details).queryByRole('button', { name: 'Open in Explorer' })).not.toBeInTheDocument()
    expect(within(details).queryByRole('button', { name: 'Protect' })).not.toBeInTheDocument()
    fireEvent.click(within(details).getByRole('button', { name: 'Open the Recycle Bin' }))
    expect(openRecycleBin).toHaveBeenCalled()
    expect(revealInExplorer).not.toHaveBeenCalled()
  })

  it('needs no extra tick when everything goes to quarantine, and can be cancelled', async () => {
    const dialog = await reviewing({ ...plan, delete: { files: 0, size: 0 } })

    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Move to quarantine' })).toBeEnabled()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
    expect(runClean).not.toHaveBeenCalled()
    expect(footer()).toHaveTextContent('1,147 files selected')
  })

  it('asks to close open apps, then checks again', async () => {
    const chrome = { name: 'Google Chrome', files: 7647, size: 441_000_000 }
    const dialog = await reviewing({ ...plan, apps_open: [chrome] })

    expect(within(dialog).getByText('Close this app to clean its cache')).toBeInTheDocument()
    expect(within(dialog).getByText('Google Chrome · 7,647 files · 420.6 MB')).toBeInTheDocument()
    expect(within(dialog).getByText(/its cache is left out/)).toBeInTheDocument()

    // The user closed Chrome.
    vi.mocked(planClean).mockResolvedValue({ ...plan, plan_id: 8 })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Check again' }))

    await waitFor(() =>
      expect(screen.queryByText('Close this app to clean its cache')).not.toBeInTheDocument(),
    )
    expect(planClean).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('alertdialog', { name: 'Review this cleanup' })).toBeInTheDocument()
  })

  it('says which apps were left out because they were open', async () => {
    const dialog = await reviewing(plan)
    vi.mocked(runClean).mockResolvedValue({
      ...cleaned,
      apps_open: [
        { name: 'Google Chrome', files: 7647, size: 441_000_000 },
        { name: 'Discord', files: 120, size: 9_000_000 },
      ],
      skipped: [{ reason: 'app_running', files: 2 }],
    })
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete and quarantine' }))

    const summary = await screen.findByRole('region', { name: 'Cleanup finished' })
    expect(
      within(summary).getByText('Left out because they were open: Google Chrome and Discord.'),
    ).toBeInTheDocument()
    expect(
      within(summary).getByText('Its app was opened during the cleanup: 2'),
    ).toBeInTheDocument()
  })

  it('suggests scanning again when the results are old', async () => {
    const twoHoursAgo = Math.floor(Date.now() / 1000) - 2 * 3600
    const dialog = await reviewing({ ...plan, scanned_at: twoHoursAgo, stale: true })

    expect(within(dialog).getByText('These results are from 2 hours ago')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Scan again' }))

    await waitFor(() => expect(scan).toHaveBeenCalledTimes(2))
    expect(runClean).not.toHaveBeenCalled()
  })

  it("says when it's only a test run", async () => {
    const dialog = await reviewing({ ...plan, mode: 'dry_run' })
    expect(within(dialog).getByText(/Test mode: nothing will be deleted or moved/)).toBeInTheDocument()

    vi.mocked(runClean).mockResolvedValue({ ...cleaned, mode: 'dry_run', batch: undefined })
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete and quarantine' }))

    const summary = await screen.findByRole('region', { name: 'Test run finished' })
    expect(within(summary).getByText('would be freed')).toBeInTheDocument()
    expect(within(summary).getByText('1,097 files would be deleted permanently')).toBeInTheDocument()
    expect(within(summary).getByText(/Test mode: nothing was deleted or moved/)).toBeInTheDocument()
  })

  it('shows progress while cleaning and can stop', async () => {
    let finish: (report: CleanReport) => void = () => {}
    vi.mocked(runClean).mockImplementation((_planId, onProgress: (p: CleanProgress) => void) => {
      onProgress({ done: 1, total: 3, freed: 1_048_576 })
      return new Promise((resolve) => {
        finish = resolve
      })
    })
    const dialog = await reviewing({ ...plan, quarantine: [] })
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }))

    expect(await screen.findByText('Cleaning…')).toBeInTheDocument()
    expect(screen.getByText('1 of 3 files')).toBeInTheDocument()
    expect(screen.getByText('Freed so far: 1.0 MB')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan again' })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
    expect(cancelClean).toHaveBeenCalled()
    expect(await screen.findByRole('button', { name: 'Stopping…' })).toBeDisabled()

    await act(async () =>
      finish({
        ...cleaned,
        cancelled: true,
        deleted: { files: 1, size: 1_048_576 },
        quarantined: [],
        skipped: [],
        not_started: 2,
      }),
    )
    const summary = screen.getByRole('region', { name: 'Cleanup stopped' })
    expect(
      within(summary).getByText("2 files weren't touched, because you stopped the cleanup."),
    ).toBeInTheDocument()
  })

  it('shows why a cleanup could not be prepared or run', async () => {
    vi.mocked(planClean).mockRejectedValue('Your Protected list could not be read')
    await scanned()
    fireEvent.click(screen.getByRole('button', { name: 'Select recommended' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clean…' }))
    expect(
      await screen.findByText("Couldn't prepare the cleanup: Your Protected list could not be read"),
    ).toBeInTheDocument()

    vi.mocked(planClean).mockResolvedValue({ ...plan, quarantine: [] })
    vi.mocked(runClean).mockRejectedValue('This cleanup is out of date. Review it again.')
    fireEvent.click(screen.getByRole('button', { name: 'Clean…' }))
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }))

    expect(await screen.findByText("The cleanup couldn't run")).toBeInTheDocument()
    expect(screen.getByText('This cleanup is out of date. Review it again.')).toBeInTheDocument()
  })

  it('keeps the Clean button off while nothing is selected', async () => {
    await scanned()
    expect(screen.getByRole('button', { name: 'Clean…' })).toBeDisabled()
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
    const tree = screen.getByRole('group', { name: 'Scan results' })
    for (const box of within(tree).getAllByRole('checkbox')) {
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
    const withoutOldFile: ScanOverview = {
      ...overview,
      findings_total: 1156,
      categories: [{ ...overview.categories[0], file_count: 1146 }, overview.categories[1]],
    }
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
    // Other screens stay mounted with their own status lines.
    const statuses = screen.getAllByRole('status').map((status) => status.textContent)
    expect(statuses.some((text) => text?.includes('show up again on the next scan'))).toBe(true)
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
