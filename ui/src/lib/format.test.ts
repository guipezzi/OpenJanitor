import { describe, expect, it } from 'vitest'

import { formatAge, formatBytes, formatCount, formatDate, formatDay } from './format'

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

describe('formatDay', () => {
  it('shows only the date', () => {
    expect(formatDay(1_763_740_800, 'en', 'UTC')).toBe('Nov 21, 2025')
  })
})

describe('formatAge', () => {
  const now = 1_763_740_800
  it('picks minutes, hours, or days', () => {
    expect(formatAge(now - 30, now, 'en')).toBe('now')
    expect(formatAge(now - 90, now, 'en')).toBe('1 minute ago')
    expect(formatAge(now - 5 * 60, now, 'en')).toBe('5 minutes ago')
    expect(formatAge(now - 2 * 3600, now, 'en')).toBe('2 hours ago')
    expect(formatAge(now - 3 * 86_400, now, 'en')).toBe('3 days ago')
    expect(formatAge(now - 2 * 3600, now, 'pt-BR')).toBe('há 2 horas')
  })

  it('never says "in the future"', () => {
    expect(formatAge(now + 60, now, 'en')).toBe('now')
  })
})

describe('formatCount', () => {
  it('groups digits for the locale', () => {
    expect(formatCount(1147, 'en')).toBe('1,147')
    expect(formatCount(1147, 'pt-BR')).toBe('1.147')
  })
})
