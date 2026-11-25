import {
  BrushCleaning,
  ChevronRight,
  Clock,
  History as HistoryIcon,
  LoaderCircle,
  RotateCcw,
  Trash,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { PathText } from '@/components/path-text'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatBytes, formatDate, formatDay } from '@/lib/format'
import {
  historyFiles,
  historyOverview,
  type EntryKind,
  type HistoryEntry,
  type HistoryFile,
  type HistoryOverview,
} from '@/lib/history'
import { cn } from '@/lib/utils'

const PAGE = 200

const KIND_ICONS: Record<EntryKind, LucideIcon> = {
  cleanup: BrushCleaning,
  restore: RotateCcw,
  delete: Trash,
  expired: Clock,
}

interface HistoryScreenProps {
  /** Reload whenever the screen is shown. */
  active: boolean
}

/** The History screen (PLANNING.md section 7.4). */
export function HistoryScreen({ active }: HistoryScreenProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const [overview, setOverview] = useState<HistoryOverview | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!active) return
    let current = true
    historyOverview().then(
      (loaded) => {
        if (!current) return
        setOverview(loaded)
        setError(null)
      },
      (cause) => current && setError(String(cause)),
    )
    return () => {
      current = false
    }
  }, [active])

  const totals = overview?.totals
  return (
    <div className="space-y-6 pb-6">
      <header>
        <h2 className="text-xl font-semibold">{t('history.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('history.description')}</p>
      </header>

      {error && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('history.loadError')}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {overview && totals && (
        <>
          <div className="flex items-center gap-4 rounded-xl border bg-card p-5">
            <HistoryIcon className="size-8 shrink-0 text-primary" />
            <div className="min-w-0 flex-1">
              <p className="text-3xl font-semibold tabular-nums">
                {formatBytes(totals.freed, locale)}{' '}
                <span className="text-base font-normal text-muted-foreground">
                  {t('history.totalFreed')}
                </span>
              </p>
              <p className="text-sm text-muted-foreground">
                {totals.cleanups > 0 && totals.since !== undefined
                  ? t('history.since', {
                      count: totals.cleanups,
                      date: formatDay(totals.since, locale),
                    })
                  : t('history.nothingFreed')}
              </p>
            </div>
            <p className="hidden max-w-64 text-xs text-muted-foreground md:block">
              {t('history.detailsKept', { days: overview.detail_days })}
            </p>
          </div>

          {overview.unreadable_lines > 0 && (
            <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400" role="alert">
              <TriangleAlert className="mt-0.5 size-4 shrink-0" />
              {t('history.unreadable', { count: overview.unreadable_lines })}
            </p>
          )}

          {overview.entries.length === 0 ? (
            <p className="rounded-xl border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
              {t('history.empty')}
            </p>
          ) : (
            <ul className="divide-y rounded-xl border bg-card" aria-label={t('history.label')}>
              {overview.entries.map((entry) => (
                <Entry
                  key={`${overview.view_id}-${entry.id}`}
                  viewId={overview.view_id}
                  entry={entry}
                  detailDays={overview.detail_days}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}

interface EntryProps {
  viewId: number
  entry: HistoryEntry
  detailDays: number
}

/** One cleanup, restore, or delete; its files load when it's opened. */
function Entry({ viewId, entry, detailDays }: EntryProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const [open, setOpen] = useState(false)
  const [files, setFiles] = useState<HistoryFile[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const Icon = KIND_ICONS[entry.kind]
  const title = t(`history.kind.${entry.kind}`)
  const name = `${title}, ${formatDate(entry.at, locale)}`
  const dry = entry.mode === 'dry_run'

  const load = async (offset: number) => {
    setLoading(true)
    setError(null)
    try {
      const page = await historyFiles(viewId, entry.id, offset, PAGE)
      setFiles((previous) => [...previous, ...page.items])
      setTotal(page.total)
    } catch (cause) {
      setError(String(cause))
    } finally {
      setLoading(false)
    }
  }

  const toggle = () => {
    const next = !open
    setOpen(next)
    if (next && files.length === 0 && entry.details > 0) void load(0)
  }

  const size = formatBytes(entry.freed, locale)
  const parts: string[] = []
  if (entry.kind !== 'restore') {
    parts.push(dry ? t('history.wouldFree', { size }) : t('history.freed', { size }))
  }
  parts.push(t('history.files', { count: entry.files }))
  if (entry.quarantined.files > 0) {
    parts.push(t('history.quarantined', { count: entry.quarantined.files }))
  }
  if (entry.skipped > 0) parts.push(t('history.skipped', { count: entry.skipped }))

  return (
    <li>
      <button
        type="button"
        aria-expanded={open}
        aria-label={t(open ? 'history.hide' : 'history.show', { name })}
        onClick={toggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        <ChevronRight
          className={cn('size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-90')}
        />
        <Icon className="size-4 shrink-0 text-primary" />
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
            {title}
            <span className="font-normal text-muted-foreground">{formatDate(entry.at, locale)}</span>
            {dry && <Badge variant="outline">{t('history.testRun')}</Badge>}
            {entry.cancelled && <Badge variant="outline">{t('history.stopped')}</Badge>}
            {entry.interrupted && (
              <Badge variant="outline" title={t('history.interruptedHint')}>
                {t('history.interrupted')}
              </Badge>
            )}
          </p>
          <p className="text-xs text-muted-foreground tabular-nums">{parts.join(' · ')}</p>
        </div>
      </button>

      {open && (
        <div className="space-y-1 px-4 pb-3 pl-15 text-sm">
          {entry.details === 0 && (
            <p className="text-xs text-muted-foreground">{t('history.noDetails', { days: detailDays })}</p>
          )}
          {files.length > 0 && (
            <ul className="space-y-0.5">
              {files.map((file, index) => (
                <li key={index} className="flex items-center gap-3 text-xs">
                  <span className="w-36 shrink-0 text-muted-foreground">
                    {file.result === 'skipped' && file.reason
                      ? `${t('history.result.skipped')}: ${t(`clean.reason.${file.reason}`)}`
                      : t(`history.result.${file.result}`)}
                  </span>
                  <PathText path={file.path} className="flex-1 font-mono" />
                  {file.items !== undefined && (
                    <span className="shrink-0 text-muted-foreground tabular-nums">
                      {t('history.items', { count: file.items })}
                    </span>
                  )}
                  <span className="w-20 shrink-0 text-right tabular-nums">
                    {file.result !== 'folder_removed' && formatBytes(file.size, locale)}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {loading && (
            <p className="flex items-center gap-2 text-xs text-muted-foreground">
              <LoaderCircle className="size-3 animate-spin" />
              {t('history.loading')}
            </p>
          )}
          {error && <p className="text-xs text-destructive">{t('history.filesError', { error })}</p>}
          {!loading && files.length < total && (
            <Button variant="link" size="sm" className="px-0" onClick={() => void load(files.length)}>
              {t('history.showMore', { count: Math.min(total - files.length, PAGE) })}
            </Button>
          )}
        </div>
      )}
    </li>
  )
}
