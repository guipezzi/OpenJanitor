// Loading the results tree one level and one page at a time.
import { useCallback, useMemo, useState } from 'react'

import { scanChildren, type NodeView, type ScanOverview } from './scan'
import type { LoadedChildren } from './selection'

/** How many children to fetch per request. */
export const PAGE_SIZE = 200

export interface Page {
  items: NodeView[]
  /** How many children the node has in all. */
  total: number
  loading: boolean
  error: string | null
}

/** One line of the visible tree. */
export type Row =
  | { type: 'node'; node: NodeView; depth: number }
  | { type: 'more'; parent: NodeView; depth: number; remaining: number }
  | { type: 'loading'; parent: NodeView; depth: number }
  | { type: 'error'; parent: NodeView; depth: number; error: string }

const EMPTY: Page = { items: [], total: 0, loading: false, error: null }

function initialPages(overview: ScanOverview): Map<number, Page> {
  return new Map(
    overview.categories.map((category) => {
      const rules = category.children ?? []
      return [category.id, { ...EMPTY, items: rules, total: rules.length }]
    }),
  )
}

/**
 * Tree state for one scan. Mount it with `key={overview.scan_id}` so a new
 * scan starts fresh. Categories start expanded, showing their rules.
 */
export function useResultsTree(overview: ScanOverview) {
  const [pages, setPages] = useState(() => initialPages(overview))
  const [expanded, setExpanded] = useState(
    () => new Set(overview.categories.map((category) => category.id)),
  )

  // A new overview for the same scan (after protecting something): node ids
  // are the same, but totals and children changed, so start over from the
  // categories. The caller keeps its selection.
  const [source, setSource] = useState(overview)
  if (source !== overview) {
    setSource(overview)
    setPages(initialPages(overview))
    setExpanded(new Set(overview.categories.map((category) => category.id)))
  }

  const load = useCallback(
    async (id: number, offset: number) => {
      const update = (change: (page: Page) => Page) =>
        setPages((previous) => new Map(previous).set(id, change(previous.get(id) ?? EMPTY)))
      update((page) => ({ ...page, loading: true, error: null }))
      try {
        const result = await scanChildren(overview.scan_id, id, offset, PAGE_SIZE)
        update((page) => ({
          items: [...page.items, ...result.items],
          total: result.total,
          loading: false,
          error: null,
        }))
      } catch (cause) {
        update((page) => ({ ...page, loading: false, error: String(cause) }))
      }
    },
    [overview.scan_id],
  )

  const toggleExpanded = (node: NodeView) => {
    const next = new Set(expanded)
    if (next.has(node.id)) {
      next.delete(node.id)
    } else {
      next.add(node.id)
      const page = pages.get(node.id)
      if (!page || (page.items.length === 0 && page.error)) void load(node.id, 0)
    }
    setExpanded(next)
  }

  const loadMore = (node: NodeView) => {
    const page = pages.get(node.id)
    if (page && !page.loading) void load(node.id, page.items.length)
  }

  const loaded: LoadedChildren = useMemo(
    () => new Map([...pages].map(([id, page]) => [id, page.items])),
    [pages],
  )

  const rows = useMemo(() => {
    const out: Row[] = []
    const walk = (nodes: readonly NodeView[], depth: number) => {
      for (const node of nodes) {
        out.push({ type: 'node', node, depth })
        if (!expanded.has(node.id)) continue
        const page = pages.get(node.id)
        if (!page) continue
        walk(page.items, depth + 1)
        if (page.loading) {
          out.push({ type: 'loading', parent: node, depth: depth + 1 })
        } else if (page.error) {
          out.push({ type: 'error', parent: node, depth: depth + 1, error: page.error })
        } else if (page.items.length < page.total) {
          out.push({
            type: 'more',
            parent: node,
            depth: depth + 1,
            remaining: page.total - page.items.length,
          })
        }
      }
    }
    walk(overview.categories, 0)
    return out
  }, [overview.categories, pages, expanded])

  return { rows, loaded, expanded, toggleExpanded, loadMore }
}
