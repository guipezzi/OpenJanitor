import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { HistoryScreen } from './history-screen'
import { historyFiles, historyOverview, type HistoryEntry, type HistoryOverview } from '@/lib/history'

vi.mock('@/lib/history', () => ({
  historyOverview: vi.fn(),
  historyFiles: vi.fn(),
}))

const DAY = 86_400
const AT = 1_763_740_800

function entry(id: number, overrides: Partial<HistoryEntry>): HistoryEntry {
  return {
    id,
    kind: 'cleanup',
    at: AT - id * DAY,
    mode: 'live',
    files: 0,
    freed: 0,
    quarantined: { files: 0, size: 0 },
    skipped: 0,
    cancelled: false,
    interrupted: false,
    details: 0,
    ...overrides,
  }
}

const overview: HistoryOverview = {
  view_id: 3,
  entries: [
    entry(0, { kind: 'restore', files: 2, details: 2 }),
    entry(1, {
      files: 1_100,
      freed: 200_000_000,
      quarantined: { files: 10, size: 1_048_576 },
      skipped: 3,
      cancelled: true,
      details: 1_113,
    }),
    entry(2, { mode: 'dry_run', files: 5, freed: 5_000 }),
    entry(3, { kind: 'expired', files: 4, freed: 4_096, interrupted: true }),
  ],
  totals: { freed: 200_004_096, cleanups: 1, since: AT - DAY },
  unreadable_lines: 2,
  detail_days: 90,
}

async function shown(with_: HistoryOverview = overview) {
  vi.mocked(historyOverview).mockResolvedValue(with_)
  render(<HistoryScreen active />)
  await screen.findByText('freed in all')
}

describe('HistoryScreen', () => {
  beforeEach(() => {
    vi.mocked(historyOverview).mockReset()
    vi.mocked(historyFiles).mockReset()
  })

  it('shows the total and every entry, newest first', async () => {
    await shown()

    expect(screen.getByText('190.7 MB')).toBeInTheDocument()
    expect(screen.getByText(/^by 1 cleanup since Nov 2\d, 2025$/)).toBeInTheDocument()
    expect(screen.getByText(/kept for 90 days/)).toBeInTheDocument()
    expect(screen.getByText("2 lines of the history couldn't be read. They're left as they are.")).toBeInTheDocument()

    const list = screen.getByRole('list', { name: 'History entries' })
    const rows = within(list).getAllByRole('button')
    expect(rows.map((row) => row.getAttribute('aria-label')?.split(',')[0])).toEqual([
      'Show the files of Restored from quarantine',
      'Show the files of Cleanup',
      'Show the files of Cleanup',
      'Show the files of Expired in quarantine',
    ])
    expect(within(list).getByText('2 files')).toBeInTheDocument()
    expect(
      within(list).getByText('Freed 190.7 MB · 1,100 files · 10 files to quarantine · 3 left alone'),
    ).toBeInTheDocument()
    expect(within(list).getByText('Stopped')).toBeInTheDocument()
    expect(within(list).getByText('Would free 4.9 KB · 5 files')).toBeInTheDocument()
    expect(within(list).getByText('Test run')).toBeInTheDocument()
    expect(within(list).getByText('Interrupted')).toBeInTheDocument()
  })

  it("loads an entry's files when it's opened", async () => {
    await shown()
    vi.mocked(historyFiles)
      .mockResolvedValueOnce({
        items: [
          { path: 'C:\\T\\a.tmp', size: 8192, result: 'deleted' },
          { path: 'C:\\T\\b.tmp', size: 4096, result: 'skipped', reason: 'in_use' },
          { path: 'C:\\T\\old', size: 0, result: 'folder_removed' },
        ],
        total: 1_113,
      })
      .mockResolvedValueOnce({ items: [], total: 1_113 })

    const cleanup = screen.getAllByRole('button', { name: /^Show the files of Cleanup/ })[0]
    fireEvent.click(cleanup)

    // The file name stays in view; the full path is on hover.
    expect(await screen.findByTitle('C:\\T\\a.tmp')).toHaveTextContent('C:\\T\\a.tmp')
    expect(screen.getByText('a.tmp')).toBeInTheDocument()
    expect(historyFiles).toHaveBeenCalledWith(3, 1, 0, 200)
    expect(screen.getByText('Deleted')).toBeInTheDocument()
    expect(screen.getByText('Left alone: In use by another program')).toBeInTheDocument()
    expect(screen.getByText('Empty folder removed')).toBeInTheDocument()
    expect(cleanup).toHaveAttribute('aria-expanded', 'true')

    fireEvent.click(screen.getByRole('button', { name: 'Show 200 more' }))
    expect(historyFiles).toHaveBeenLastCalledWith(3, 1, 3, 200)
  })

  it('says when an entry has no file details left', async () => {
    await shown()
    fireEvent.click(screen.getByRole('button', { name: /^Show the files of Expired/ }))

    expect(screen.getByText(/details for this entry are gone; they're kept for 90 days/)).toBeInTheDocument()
    expect(historyFiles).not.toHaveBeenCalled()
  })

  it('is empty before anything happened', async () => {
    await shown({
      ...overview,
      entries: [],
      totals: { freed: 0, cleanups: 0 },
      unreadable_lines: 0,
    })

    expect(screen.getByText('Nothing freed yet. Test runs don\'t count.')).toBeInTheDocument()
    expect(screen.getByText(/Nothing yet. Cleanups, restores, and deletions show up here./)).toBeInTheDocument()
  })

  it('shows why the history could not be read', async () => {
    vi.mocked(historyOverview).mockRejectedValue('Access denied')
    render(<HistoryScreen active />)

    expect(await screen.findByText("Couldn't read the history")).toBeInTheDocument()
    expect(screen.getByText('Access denied')).toBeInTheDocument()
  })
})
