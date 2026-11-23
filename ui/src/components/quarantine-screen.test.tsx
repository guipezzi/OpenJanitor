import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { QuarantineScreen } from './quarantine-screen'
import {
  deleteQuarantined,
  quarantineChildren,
  quarantineConflicts,
  quarantineOverview,
  restoreQuarantined,
  type QuarantineOverview,
  type QuarantineReport,
} from '@/lib/quarantine'
import type { NodeView } from '@/lib/scan'

vi.mock('@/lib/quarantine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/quarantine')>()),
  quarantineOverview: vi.fn(),
  quarantineChildren: vi.fn(),
  quarantineConflicts: vi.fn(),
  restoreQuarantined: vi.fn(),
  deleteQuarantined: vi.fn(),
}))

const LOGS = 'C:\\Users\\test\\AppData\\Local\\Logs\\app'
const CREATED = 1_763_740_800
const EXPIRES = CREATED + 7 * 86_400

function node(id: number, kind: NodeView['kind'], name: string, files: number, extra: Partial<NodeView> = {}): NodeView {
  return {
    id,
    kind,
    name,
    needs_admin: false,
    size_on_disk: files * 8192,
    file_count: files,
    last_modified: 0,
    quarantined_at: CREATED,
    expires_at: EXPIRES,
    has_children: kind !== 'file',
    ...extra,
  }
}

const folder = node(1, 'folder', LOGS, 3, { path: LOGS })
const batch = node(0, 'batch', '20251121-160000', 3, { children: [folder] })

const overview: QuarantineOverview = {
  view_id: 5,
  mode: 'live',
  held: { files: 3, size: 3 * 8192 },
  next_expiry: { at: EXPIRES, files: 3, size: 3 * 8192 },
  unreadable: [],
  batches: [batch],
}

const report = (done: number, extra: Partial<QuarantineReport> = {}): QuarantineReport => ({
  mode: 'live',
  done: { files: done, size: done * 8192 },
  skipped: [],
  ...extra,
})

async function shown(with_: QuarantineOverview = overview) {
  vi.mocked(quarantineOverview).mockResolvedValue(with_)
  render(<QuarantineScreen active />)
  await screen.findByText(/in quarantine ·/)
}

const selectAll = () =>
  fireEvent.click(screen.getByRole('checkbox', { name: /^Select Cleanup on/ }))

describe('QuarantineScreen', () => {
  beforeEach(() => {
    vi.mocked(quarantineOverview).mockReset()
    vi.mocked(quarantineChildren).mockReset()
    vi.mocked(quarantineConflicts).mockReset()
    vi.mocked(restoreQuarantined).mockReset()
    vi.mocked(deleteQuarantined).mockReset()
    vi.mocked(quarantineChildren).mockResolvedValue({
      items: [node(2, 'file', 'a.log', 1, { path: `${LOGS}\\a.log` })],
      total: 1,
    })
  })

  it('shows what is held and when it goes', async () => {
    await shown()

    // The total, then the cleanup and its folder in the tree.
    expect(screen.getAllByText('24.0 KB')).toHaveLength(3)
    expect(screen.getByText('in quarantine · 3 files')).toBeInTheDocument()
    expect(screen.getByText(/3 files \(24\.0 KB\) will be deleted for good on Nov 2\d, 2025\./)).toBeInTheDocument()
    expect(screen.getByText(/^Cleanup on Nov 2\d, 2025/)).toBeInTheDocument()
    // A long folder path keeps its last part in view.
    expect(screen.getByTitle(LOGS)).toHaveTextContent(LOGS)
    expect(screen.getByText('app')).toBeInTheDocument()
    expect(screen.getAllByText(/^until Nov 2\d, 2025$/).length).toBeGreaterThan(0)
    expect(screen.getByText('Nothing selected')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled()
  })

  it('restores right away when nothing is in the way', async () => {
    await shown()
    vi.mocked(quarantineConflicts).mockResolvedValue({ count: 0, samples: [] })
    vi.mocked(restoreQuarantined).mockResolvedValue(report(3))

    selectAll()
    expect(screen.getByText('3 files selected · 24.0 KB')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))

    expect(await screen.findByText('Restored 3 files to where they came from.')).toBeInTheDocument()
    expect(restoreQuarantined).toHaveBeenCalledWith(5, new Map([[0, true]]), 'skip')
    expect(quarantineOverview).toHaveBeenCalledTimes(2)
  })

  it('asks once what to do about conflicts', async () => {
    await shown()
    vi.mocked(quarantineConflicts).mockResolvedValue({ count: 7, samples: [`${LOGS}\\a.log`] })
    vi.mocked(restoreQuarantined).mockResolvedValue(
      report(2, { skipped: [{ reason: 'changed', files: 1 }] }),
    )

    selectAll()
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    const dialog = await screen.findByRole('alertdialog', {
      name: '7 files have something in their place',
    })
    expect(within(dialog).getByText(`${LOGS}\\a.log`)).toBeInTheDocument()
    expect(within(dialog).getByText('and 6 more')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep both' }))

    expect(
      await screen.findByText(
        'Restored 2 files to where they came from. 1 file was left alone: Changed since the scan (1).',
      ),
    ).toBeInTheDocument()
    expect(restoreQuarantined).toHaveBeenCalledWith(5, new Map([[0, true]]), 'keep_both')
  })

  it('deletes for good only after the tick', async () => {
    await shown()
    vi.mocked(deleteQuarantined).mockResolvedValue(report(3))

    selectAll()
    fireEvent.click(screen.getByRole('button', { name: 'Delete now…' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Delete for good?' })
    const confirm = within(dialog).getByRole('button', { name: 'Delete permanently' })
    expect(confirm).toBeDisabled()
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: 'I understand that 3 files will be permanently deleted.',
      }),
    )
    fireEvent.click(confirm)

    expect(await screen.findByText('Deleted 3 files for good, freeing 24.0 KB.')).toBeInTheDocument()
    expect(deleteQuarantined).toHaveBeenCalledWith(5, new Map([[0, true]]))
  })

  it('empties everything at once', async () => {
    await shown()
    vi.mocked(deleteQuarantined).mockResolvedValue(report(3))

    fireEvent.click(screen.getByRole('button', { name: 'Empty quarantine now…' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Empty the quarantine?' })
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }))

    await waitFor(() => expect(deleteQuarantined).toHaveBeenCalledWith(5, new Map([[0, true]])))
  })

  it('says when it is empty, what expired, and what it could not read', async () => {
    await shown({
      ...overview,
      mode: 'dry_run',
      held: { files: 0, size: 0 },
      next_expiry: undefined,
      batches: [],
      unreadable: [{ batch: '20200101-000000', folder: 'C:\\Q\\20200101-000000', error: 'bad' }],
      expired: { at: CREATED, mode: 'live', done: { files: 2, size: 16_384 }, skipped: [] },
    })

    expect(screen.getByText(/Nothing is in quarantine/)).toBeInTheDocument()
    expect(screen.getByText(/2 files were deleted for good because their time in quarantine was up \(16\.0 KB freed\)/)).toBeInTheDocument()
    expect(
      screen.getByText("Couldn't read 1 quarantine folder, so it's left alone: C:\\Q\\20200101-000000"),
    ).toBeInTheDocument()
    expect(screen.getByText(/Test mode: nothing will be restored or deleted/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Empty quarantine now…' })).toBeDisabled()
  })

  it('shows why the quarantine could not be read', async () => {
    vi.mocked(quarantineOverview).mockRejectedValue('Access denied')
    render(<QuarantineScreen active />)

    expect(await screen.findByText("Couldn't read the quarantine")).toBeInTheDocument()
    expect(screen.getByText('Access denied')).toBeInTheDocument()
  })
})
