// What the charts show (PLANNING.md section 7.8): the cleanable space by
// category, folded to a few slices, each in its category's own color.
import { useEffect, useState } from 'react'

import type { NodeView } from './scan'

/** At most this many categories get a slice of their own; the rest are "Other". */
export const MAX_SLICES = 6

/**
 * One fixed color slot per category (CSS variables in index.css). A color
 * follows its category, never its rank, so it stays put when sizes change.
 */
const SLOTS: Record<string, number> = {
  'browser-caches': 1,
  'graphics-caches': 2,
  'temporary-files': 3,
  'app-caches': 4,
  'recycle-bin': 5,
  'crash-reports': 6,
  logs: 7,
  'system-caches': 8,
}

/** The CSS variable holding a category's color. */
export function categoryColor(category: string): string {
  const slot = SLOTS[category]
  return slot ? `--series-${slot}` : '--series-other'
}

export interface Slice {
  /** The category's node, to select it in the tree; null for "Other". */
  id: number | null
  /** The category id ("browser-caches"), or null for "Other". */
  category: string | null
  size: number
  /** CSS variable name, such as "--series-1". */
  color: string
}

/**
 * Slices for the categories that hold anything, biggest first: every one of
 * them if they fit, otherwise the biggest MAX_SLICES and an "Other" slice for
 * the rest (never an "Other" of a single category).
 */
export function donutSlices(categories: readonly NodeView[]): Slice[] {
  const sized = categories
    .filter((category) => category.size_on_disk > 0)
    .sort((a, b) => b.size_on_disk - a.size_on_disk)
  const slice = (category: NodeView): Slice => ({
    id: category.id,
    category: category.name,
    size: category.size_on_disk,
    color: categoryColor(category.name),
  })
  if (sized.length <= MAX_SLICES + 1) return sized.map(slice)
  const rest = sized.slice(MAX_SLICES).reduce((sum, category) => sum + category.size_on_disk, 0)
  return [
    ...sized.slice(0, MAX_SLICES).map(slice),
    { id: null, category: null, size: rest, color: '--series-other' },
  ]
}

/** A share of the whole as a percentage, with "<1%" for slivers. */
export function formatShare(part: number, whole: number, locale: string): string {
  if (whole <= 0) return ''
  const share = part / whole
  const percent = new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 0 })
  return share > 0 && share < 0.01 ? `<${percent.format(0.01)}` : percent.format(share)
}

/** A CSS variable's value on the page, such as "#2a78d6". */
export function cssColor(variable: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(variable).trim()
}

/** Changes whenever the light or dark theme changes, so charts repaint. */
export function useThemeVersion(): number {
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const observer = new MutationObserver(() => setVersion((count) => count + 1))
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])
  return version
}
