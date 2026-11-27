import { ShieldCheck, Sparkles } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { CleanableChart } from '@/components/cleanable-chart'
import { donutSlices } from '@/lib/chart'
import { formatBytes } from '@/lib/format'
import type { ScanOverview } from '@/lib/scan'

interface ScanSummaryProps {
  overview: ScanOverview
  /** Shows the chart; picking a category in it selects it in the tree. */
  onPickCategory?: (id: number) => void
}

/** How much a scan found, and (with results to show) where it is. */
export function ScanSummary({ overview, onPickCategory }: ScanSummaryProps) {
  const { t, i18n } = useTranslation()
  const slices = useMemo(() => donutSlices(overview.categories), [overview.categories])
  // Files, plus the Recycle Bin's items.
  const files = overview.categories.reduce((sum, category) => sum + category.file_count, 0)
  const chart = onPickCategory && slices.length > 0

  return (
    <div className="flex flex-wrap items-center gap-x-8 gap-y-4 rounded-xl border bg-card p-5">
      {!chart && <Sparkles className="size-8 shrink-0 text-primary" />}
      <div className="min-w-48 flex-1 space-y-1">
        <p className="text-3xl font-semibold">{formatBytes(overview.size_on_disk_total, i18n.language)}</p>
        <p className="text-sm text-muted-foreground">{t('scan.summary', { count: files })}</p>
        <p className="flex items-center gap-1.5 pt-1 text-xs text-muted-foreground">
          <ShieldCheck className="size-3.5 shrink-0" />
          {t('scan.nothingDeleted')}
        </p>
      </div>
      {chart && (
        <div className="w-full lg:w-auto lg:min-w-[30rem]">
          <CleanableChart slices={slices} onPick={onPickCategory} />
        </div>
      )}
    </div>
  )
}
