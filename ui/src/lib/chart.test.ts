import { describe, expect, it } from 'vitest'

import { categoryColor, donutSlices, formatShare } from './chart'
import type { NodeView } from './scan'

function category(id: number, name: string, size: number): NodeView {
  return {
    id,
    kind: 'category',
    name,
    needs_admin: false,
    size_on_disk: size,
    file_count: 1,
    last_modified: 0,
    has_children: true,
  }
}

const names = [
  'browser-caches',
  'graphics-caches',
  'temporary-files',
  'app-caches',
  'recycle-bin',
  'crash-reports',
  'logs',
  'system-caches',
]

describe('donutSlices', () => {
  it('gives each category a slice, biggest first, while they fit', () => {
    const slices = donutSlices([
      category(1, 'logs', 10),
      category(2, 'browser-caches', 300),
      category(3, 'recycle-bin', 0),
    ])
    expect(slices.map((s) => [s.id, s.size])).toEqual([
      [2, 300],
      [1, 10],
    ])
  })

  it('folds the smallest into "Other" past six, never one alone', () => {
    const seven = names.slice(0, 7).map((name, i) => category(i + 1, name, 100 - i))
    expect(donutSlices(seven)).toHaveLength(7)
    expect(donutSlices(seven).every((s) => s.id !== null)).toBe(true)

    const eight = names.map((name, i) => category(i + 1, name, 100 - i))
    const slices = donutSlices(eight)
    expect(slices).toHaveLength(7)
    expect(slices[6]).toEqual({ id: null, category: null, size: 94 + 93, color: '--series-other' })
  })

  it('keeps a category in its own color whatever its rank', () => {
    expect(categoryColor('browser-caches')).toBe('--series-1')
    expect(categoryColor('recycle-bin')).toBe('--series-5')
    expect(categoryColor('something-new')).toBe('--series-other')
    expect(new Set(names.map(categoryColor)).size).toBe(8)

    const small = donutSlices([category(1, 'browser-caches', 1), category(2, 'logs', 50)])
    expect(small.find((s) => s.id === 1)?.color).toBe('--series-1')
  })
})

describe('formatShare', () => {
  it('rounds to whole percents and says when a share is a sliver', () => {
    expect(formatShare(84, 100, 'en')).toBe('84%')
    expect(formatShare(1, 1000, 'en')).toBe('<1%')
    expect(formatShare(0, 100, 'en')).toBe('0%')
    expect(formatShare(5, 0, 'en')).toBe('')
  })
})
