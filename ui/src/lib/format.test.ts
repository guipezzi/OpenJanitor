import { describe, expect, it } from 'vitest'

import { formatBytes, formatCount, formatDate } from './format'

describe('formatBytes', () => {
  it('shows small sizes in bytes', () => {
    expect(formatBytes(0, 'en')).toBe('0 B')
    expect(formatBytes(1023, 'en')).toBe('1,023 B')
  })

  it('uses 1024-based units like File Explorer', () => {
    expect(formatBytes(1024, 'en')).toBe('1.0 KB')
    expect(formatBytes(1536, 'en')).toBe('1.5 KB')
    expect(formatBytes(208_037_478, 'en')).toBe('198.4 MB')
    expect(formatBytes(5 * 1024 ** 3, 'en')).toBe('5.0 GB')
  })

  it('stops at terabytes', () => {
    expect(formatBytes(2048 * 1024 ** 4, 'en')).toBe('2,048.0 TB')
  })

  it('follows the locale', () => {
    expect(formatBytes(1536, 'pt-BR')).toBe('1,5 KB')
  })
})

describe('formatDate', () => {
  it('shows a Unix timestamp as a local date and time', () => {
    expect(formatDate(1_763_740_800, 'en', 'UTC')).toBe('Nov 21, 2025, 4:00 PM')
    expect(formatDate(1_763_740_800, 'pt-BR', 'UTC')).toBe('21 de nov. de 2025, 16:00')
  })
})

describe('formatCount', () => {
  it('groups digits for the locale', () => {
    expect(formatCount(1147, 'en')).toBe('1,147')
    expect(formatCount(1147, 'pt-BR')).toBe('1.147')
  })
})
