import {
  ChevronRight,
  File,
  Folder,
  FolderOpen,
  Layers,
  ListChecks,
  LoaderCircle,
  MapPin,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { RiskBadge } from '@/components/risk-badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { formatBytes } from '@/lib/format'
import { useNodeLabel } from '@/lib/labels'
import type { NodeKind, NodeView } from '@/lib/scan'
import { checkState, type CheckState, type Tally } from '@/lib/selection'
import { PAGE_SIZE, type Row } from '@/lib/use-results-tree'
import { cn } from '@/lib/utils'

const INDENT = 20

interface ResultsTreeProps {
  rows: Row[]
  expanded: ReadonlySet<number>
  tallies: ReadonlyMap<number, Tally>
  focusedId: number | null
  onToggleExpanded: (node: NodeView) => void
  onToggleSelected: (node: NodeView, current: CheckState) => void
  onFocus: (node: NodeView) => void
  onLoadMore: (node: NodeView) => void
}

function KindIcon({ kind, open }: { kind: NodeKind; open: boolean }) {
  const className = 'size-4 shrink-0 text-muted-foreground'
  switch (kind) {
    case 'category':
      return <Layers className={className} />
    case 'rule':
      return <ListChecks className={className} />
    case 'location':
      return <MapPin className={className} />
    case 'folder':
      return open ? <FolderOpen className={className} /> : <Folder className={className} />
    case 'file':
      return <File className={className} />
  }
}

export function ResultsTree({
  rows,
  expanded,
  tallies,
  focusedId,
  onToggleExpanded,
  onToggleSelected,
  onFocus,
  onLoadMore,
}: ResultsTreeProps) {
  const { t, i18n } = useTranslation()
  const label = useNodeLabel()
  const locale = i18n.language

  return (
    <div className="rounded-xl border bg-card p-1.5" aria-label={t('results.label')} role="group">
      {rows.map((row) => {
        const indent = { paddingLeft: row.depth * INDENT + 8 }
        if (row.type !== 'node') {
          const key = `${row.type}-${row.parent.id}`
          return (
            <div key={key} className="py-1.5 pr-2 text-sm text-muted-foreground" style={indent}>
              {row.type === 'loading' && (
                <span className="flex items-center gap-2 pl-7">
                  <LoaderCircle className="size-4 animate-spin" />
                  {t('results.loading')}
                </span>
              )}
              {row.type === 'error' && (
                <span className="flex items-center gap-2 pl-7 text-destructive">
                  <TriangleAlert className="size-4" />
                  {t('results.loadError', { error: row.error })}
                </span>
              )}
              {row.type === 'more' && (
                <Button variant="link" size="sm" className="ml-5" onClick={() => onLoadMore(row.parent)}>
                  {t('results.showMore', { count: Math.min(row.remaining, PAGE_SIZE) })}
                </Button>
              )}
            </div>
          )
        }

        const { node } = row
        const name = label(node)
        const isOpen = expanded.has(node.id)
        const state = checkState(node, tallies.get(node.id))
        return (
          <div
            key={node.id}
            data-focused={focusedId === node.id}
            className={cn(
              'flex items-center gap-2 rounded-md py-1 pr-2 hover:bg-muted/60',
              'data-[focused=true]:bg-muted',
              node.kind === 'category' && 'font-medium',
            )}
            style={indent}
          >
            {node.has_children ? (
              <Button
                variant="ghost"
                size="icon-xs"
                aria-expanded={isOpen}
                aria-label={t(isOpen ? 'results.collapse' : 'results.expand', { name })}
                onClick={() => onToggleExpanded(node)}
              >
                <ChevronRight className={cn('transition-transform', isOpen && 'rotate-90')} />
              </Button>
            ) : (
              <span className="size-6 shrink-0" />
            )}
            <Checkbox
              checked={state}
              onCheckedChange={() => onToggleSelected(node, state)}
              aria-label={t('results.select', { name })}
            />
            <button
              type="button"
              className="flex min-w-0 flex-1 items-center gap-2 rounded-sm py-0.5 text-left text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
              onClick={() => onFocus(node)}
            >
              <KindIcon kind={node.kind} open={isOpen} />
              <span className="truncate">{name}</span>
              {node.kind === 'rule' && node.risk && <RiskBadge risk={node.risk} />}
              {node.kind === 'rule' && node.needs_admin && (
                <ShieldAlert
                  className="size-4 shrink-0 text-amber-600 dark:text-amber-400"
                  role="img"
                  aria-label={t('results.needsAdmin')}
                >
                  <title>{t('results.needsAdmin')}</title>
                </ShieldAlert>
              )}
            </button>
            <span className="hidden w-20 shrink-0 text-right text-xs text-muted-foreground tabular-nums sm:block">
              {node.kind !== 'file' && t('results.files', { count: node.file_count })}
            </span>
            <span className="w-20 shrink-0 text-right text-sm tabular-nums">
              {formatBytes(node.size_on_disk, locale)}
            </span>
          </div>
        )
      })}
    </div>
  )
}
