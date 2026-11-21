import { ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { formatBytes, formatCount } from '@/lib/format'
import type { RuleReport, Risk } from '@/lib/scan'
import { cn } from '@/lib/utils'

const RISK_STYLES: Record<Risk, string> = {
  low: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
  medium: 'bg-amber-500/10 text-amber-700 dark:text-amber-400',
  review: 'bg-rose-500/10 text-rose-700 dark:text-rose-400',
}

/** Rules that found something come first, biggest first. */
function byRelevance(a: RuleReport, b: RuleReport): number {
  const aScanned = a.status === 'scanned' ? 0 : 1
  const bScanned = b.status === 'scanned' ? 0 : 1
  return aScanned - bScanned || b.size_on_disk - a.size_on_disk || a.name.localeCompare(b.name)
}

export function ResultsTable({ rules }: { rules: RuleReport[] }) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const sorted = [...rules].sort(byRelevance)

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('results.item')}</TableHead>
          <TableHead>{t('results.risk')}</TableHead>
          <TableHead className="text-right">{t('results.files')}</TableHead>
          <TableHead className="text-right">{t('results.size')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sorted.map((rule) => {
          const scanned = rule.status === 'scanned'
          return (
            <TableRow key={rule.rule_id} className={cn(!scanned && 'text-muted-foreground')}>
              <TableCell>
                <div className="flex items-center gap-2 font-medium">
                  {rule.name}
                  {rule.needs_admin && (
                    <ShieldAlert
                      className="size-4 text-amber-600 dark:text-amber-400"
                      role="img"
                      aria-label={t('results.needsAdmin')}
                    >
                      <title>{t('results.needsAdmin')}</title>
                    </ShieldAlert>
                  )}
                </div>
                {!scanned && (
                  <div className="text-xs">
                    {rule.status === 'not_detected'
                      ? t('results.notDetected')
                      : t('results.noLocations')}
                  </div>
                )}
              </TableCell>
              <TableCell>
                <Badge className={RISK_STYLES[rule.risk]}>{t(`risk.${rule.risk}`)}</Badge>
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {scanned ? formatCount(rule.findings, locale) : '—'}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {scanned ? formatBytes(rule.size_on_disk, locale) : '—'}
              </TableCell>
            </TableRow>
          )
        })}
      </TableBody>
    </Table>
  )
}
