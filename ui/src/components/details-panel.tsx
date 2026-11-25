import { FolderSearch, Shield, ShieldAlert, Trash2, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { RiskBadge } from '@/components/risk-badge'
import { Button } from '@/components/ui/button'
import { formatBytes, formatCount, formatDate } from '@/lib/format'
import { useNodeLabel } from '@/lib/labels'
import { couldNotRead, isRecycleBin, type NodeView, type RuleReport } from '@/lib/scan'
import { isRecommended } from '@/lib/selection'
import { cn } from '@/lib/utils'

interface DetailsPanelProps {
  node: NodeView | null
  rule: RuleReport | undefined
  onReveal: (node: NodeView) => Promise<void>
  /** Opens the Recycle Bin in File Explorer. */
  onOpenRecycleBin: () => Promise<void>
  /** Protects the rule, folder, or file (not a whole category). */
  onProtect: (node: NodeView) => void
  className?: string
}

/** Why an item was found (PLANNING.md section 7.1). */
export function DetailsPanel({
  node,
  rule,
  onReveal,
  onOpenRecycleBin,
  onProtect,
  className,
}: DetailsPanelProps) {
  const { t, i18n } = useTranslation()
  const label = useNodeLabel()
  const locale = i18n.language
  const [revealError, setRevealError] = useState<{ id: number; message: string } | null>(null)

  if (!node) {
    return (
      <aside
        aria-label={t('details.label')}
        className={cn('rounded-xl border border-dashed p-5 text-sm text-muted-foreground', className)}
      >
        {t('details.empty')}
      </aside>
    )
  }

  const open = async (action: () => Promise<void>) => {
    setRevealError(null)
    try {
      await action()
    } catch (cause) {
      setRevealError({ id: node.id, message: String(cause) })
    }
  }
  // The Recycle Bin is counted in items, has no dates, and is protected
  // only as a whole rule.
  const bin = isRecycleBin(node)

  return (
    <aside
      aria-label={t('details.label')}
      className={cn('space-y-4 rounded-xl border bg-card p-5', className)}
    >
      <div className="space-y-1">
        <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {t(`details.kind.${node.kind}`)}
        </p>
        <h3 className="font-semibold break-all">{label(node)}</h3>
        {node.risk && (
          <div className="pt-1">
            <RiskBadge risk={node.risk} />
          </div>
        )}
      </div>

      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
        <dt className="text-muted-foreground">{t('details.size')}</dt>
        <dd className="tabular-nums">{formatBytes(node.size_on_disk, locale)}</dd>
        {node.kind !== 'file' && (
          <>
            <dt className="text-muted-foreground">{t(bin ? 'details.items' : 'details.files')}</dt>
            <dd className="tabular-nums">{formatCount(node.file_count, locale)}</dd>
          </>
        )}
        {!bin && (
          <>
            <dt className="text-muted-foreground">
              {t(node.kind === 'file' ? 'details.modified' : 'details.newest')}
            </dt>
            <dd>{formatDate(node.last_modified, locale)}</dd>
          </>
        )}
        {rule && node.kind !== 'rule' && (
          <>
            <dt className="text-muted-foreground">{t('details.rule')}</dt>
            <dd>{rule.name}</dd>
          </>
        )}
        {node.path && (
          <>
            <dt className="text-muted-foreground">{t('details.location')}</dt>
            <dd className="font-mono text-xs break-all">{node.path}</dd>
          </>
        )}
      </dl>

      {rule && (
        <section className="space-y-2 text-sm">
          <h4 className="font-medium">{t('details.why')}</h4>
          <p className="text-muted-foreground">{rule.description}</p>
          {node.evidence && node.evidence.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
              {node.evidence.map((line) => (
                // Words stay whole; only a long path breaks where it must.
                <li key={line} className="wrap-anywhere">
                  {line}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {node.needs_admin && (
        <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          {t('details.adminNote')}
        </p>
      )}
      {node.kind === 'rule' && rule && couldNotRead(rule) && (
        <p className="text-sm text-muted-foreground">{t('details.partlyRead')}</p>
      )}
      {node.kind === 'rule' && node.risk === 'low' && !isRecommended(node) && (
        <p className="text-sm text-muted-foreground">{t('details.notRecommended')}</p>
      )}

      <div className="flex flex-wrap gap-2">
        {bin ? (
          <Button variant="outline" onClick={() => void open(onOpenRecycleBin)}>
            <Trash2 />
            {t('details.openRecycleBin')}
          </Button>
        ) : (
          node.path && (
            <Button variant="outline" onClick={() => void open(() => onReveal(node))}>
              <FolderSearch />
              {t('details.openInExplorer')}
            </Button>
          )
        )}
        {node.kind !== 'category' && node.kind !== 'recycle_bin' && (
          <Button variant="outline" onClick={() => onProtect(node)} title={t('details.protectHint')}>
            <Shield />
            {t('details.protect')}
          </Button>
        )}
      </div>
      {revealError?.id === node.id && (
        <p className="flex gap-2 text-sm text-destructive">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          {revealError.message}
        </p>
      )}
    </aside>
  )
}
