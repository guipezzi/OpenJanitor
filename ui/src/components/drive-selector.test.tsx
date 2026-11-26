import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { DriveSelector } from './drive-selector'
import { drivesOverview, selectDrives, type Drive } from '@/lib/drives'

vi.mock('@/lib/drives', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/drives')>()),
  drivesOverview: vi.fn(),
  selectDrives: vi.fn(),
}))

const C: Drive = {
  letter: 'C',
  id: 'volume-c',
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
const D: Drive = {
  ...C,
  letter: 'D',
  id: 'volume-d',
  label: '',
  total: 2_000_397_791_232,
  free: 1_948_897_361_920,
  media: 'hdd',
  connection: 'external',
  system: false,
  selected: false,
}
const Z: Drive = { ...C, letter: 'Z', id: undefined, label: '', status: 'network', system: false, selected: false }

const box = (name: RegExp) => screen.getByRole('checkbox', { name })

async function shown(drives: Drive[], props: Partial<Parameters<typeof DriveSelector>[0]> = {}) {
  vi.mocked(drivesOverview).mockResolvedValue({ drives })
  const onChange = vi.fn()
  render(<DriveSelector active disabled={false} onChange={onChange} {...props} />)
  await screen.findByRole('region', { name: 'Drives to scan' })
  return onChange
}

describe('DriveSelector', () => {
  beforeEach(() => {
    vi.mocked(drivesOverview).mockReset()
    vi.mocked(selectDrives).mockReset()
  })

  it('describes each drive and keeps the last one selected', async () => {
    await shown([C, D, Z])

    expect(screen.getByText('Windows-SSD (C:)')).toBeInTheDocument()
    expect(screen.getByText('Windows')).toBeInTheDocument()
    expect(screen.getByText(/SSD · Internal · NTFS/)).toBeInTheDocument()
    expect(screen.getByText('47.3 GB free of 474.7 GB')).toBeInTheDocument()
    expect(screen.getByText('Local disk (D:)')).toBeInTheDocument()
    expect(screen.getByText(/Hard disk · External · NTFS/)).toBeInTheDocument()
    expect(screen.getByText("Network drives aren't supported.")).toBeInTheDocument()

    expect(box(/Windows-SSD \(C:\)/)).toBeDisabled()
    expect(box(/Local disk \(Z:\)/)).toBeDisabled()
    expect(box(/Local disk \(D:\)/)).toBeEnabled()
    expect(screen.queryByText(/only empties the Recycle Bin/)).not.toBeInTheDocument()
  })

  it('saves a new choice and says when the results no longer match', async () => {
    const onChange = await shown([C, D])
    vi.mocked(selectDrives).mockResolvedValue({ drives: [C, { ...D, selected: true }] })

    fireEvent.click(box(/Local disk \(D:\)/))

    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(1))
    expect(selectDrives).toHaveBeenCalledWith(['volume-c', 'volume-d'])
    expect(box(/Local disk \(D:\)/)).toBeChecked()
    expect(box(/Windows-SSD \(C:\)/)).toBeEnabled()
    expect(screen.getByText(/only empties the Recycle Bin for now/)).toBeInTheDocument()

    // Unselecting the system drive leaves the other one.
    vi.mocked(selectDrives).mockResolvedValue({ drives: [{ ...C, selected: false }, { ...D, selected: true }] })
    fireEvent.click(box(/Windows-SSD \(C:\)/))
    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(2))
    expect(selectDrives).toHaveBeenLastCalledWith(['volume-d'])
  })

  it('shows why a choice could not be saved, and waits while busy', async () => {
    const onChange = await shown([C, D])
    vi.mocked(selectDrives).mockRejectedValue('A scan is already running.')
    fireEvent.click(box(/Local disk \(D:\)/))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      "Couldn't update the drives: A scan is already running.",
    )
    expect(onChange).not.toHaveBeenCalled()
  })

  it('disables every drive while scanning or cleaning', async () => {
    await shown([C, D], { disabled: true })
    const list = screen.getByRole('list')
    for (const checkbox of within(list).getAllByRole('checkbox')) {
      expect(checkbox).toBeDisabled()
    }
    expect(screen.getByRole('button', { name: 'Check the drives again' })).toBeDisabled()
  })
})
