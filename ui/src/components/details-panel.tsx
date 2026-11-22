import { FolderSearch, ShieldAlert, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { RiskBadge } from '@/components/risk-badge'
import { Button } from '@/components/ui/button'
import { formatBytes, formatCount, formatDate } from '@/lib/format'
import { useNodeLabel } from '@/lib/labels'
import type { NodeView, RuleReport } from '@/lib/scan'
import { cn } from '@/lib/utils'

interface DetailsPanelProps {
  node: NodeView | null
  rule: RuleReport | undefined
  onReveal: (node: NodeView) => Promise<void>
  className?: string
}

/** Why an item was found (PLANNING.md section 7.1). */
export function DetailsPanel({ node, rule, onReveal, className }: DetailsPanelProps) {
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

  const reveal = async () => {
    setRevealError(null)
    try {
      await onReveal(node)
    } catch (cause) {
      setRevealError({ id: node.id, message: String(cause) })
    }
  }

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
            <dt className="text-muted-foreground">{t('details.files')}</dt>
            <dd className="tabular-nums">{formatCount(node.file_count, locale)}</dd>
          </>
        )}
        <dt className="text-muted-foreground">
          {t(node.kind === 'file' ? 'details.modified' : 'details.newest')}
        </dt>
        <dd>{formatDate(node.last_modified, locale)}</dd>
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
                <li key={line} className="break-all">
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

      {node.path && (
        <Button variant="outline" onClick={reveal}>
          <FolderSearch />
          {t('details.openInExplorer')}
        </Button>
      )}
      {revealError?.id === node.id && (
        <p className="flex gap-2 text-sm text-destructive">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          {revealError.message}
        </p>
      )}
    </aside>
  )
}
