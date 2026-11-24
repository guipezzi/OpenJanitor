import { afterEach, describe, expect, it, vi } from 'vitest'

import { applyTheme } from './theme'

/** A stand-in for Windows' light or dark setting. */
function fakeSystem(dark: boolean) {
  const listeners = new Set<() => void>()
  const media = {
    get matches() {
      return dark
    },
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
  }
  vi.stubGlobal('matchMedia', () => media)
  return {
    listeners,
    switchTo(next: boolean) {
      dark = next
      listeners.forEach((listener) => listener())
    },
  }
}

describe('applyTheme', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('follows Windows for "system", including later changes', () => {
    const system = fakeSystem(false)
    const root = document.createElement('div')

    applyTheme('system', root)
    expect(root).not.toHaveClass('dark')
    system.switchTo(true)
    expect(root).toHaveClass('dark')
  })

  it('stops following Windows once a theme is chosen', () => {
    const system = fakeSystem(true)
    const root = document.createElement('div')

    applyTheme('system', root)
    expect(root).toHaveClass('dark')
    applyTheme('light', root)
    expect(root).not.toHaveClass('dark')
    expect(system.listeners.size).toBe(0)
    system.switchTo(true)
    expect(root).not.toHaveClass('dark')

    applyTheme('dark', root)
    expect(root).toHaveClass('dark')
  })
})
