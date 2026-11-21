import { describe, expect, it } from 'vitest'

import { formatBytes, formatCount } from './format'

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

describe('formatCount', () => {
  it('groups digits for the locale', () => {
    expect(formatCount(1147, 'en')).toBe('1,147')
    expect(formatCount(1147, 'pt-BR')).toBe('1.147')
  })
})
