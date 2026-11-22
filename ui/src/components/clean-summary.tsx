import {
  AppWindow,
  Archive,
  CircleCheck,
  CircleStop,
  FolderMinus,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { TestModeNote } from '@/components/test-mode-note'
import type { CleanReport } from '@/lib/clean'
import { formatBytes, formatDay } from '@/lib/format'

/** What a cleanup did (PLANNING.md section 7.1). */
export function CleanSummary({ report }: { report: CleanReport }) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const dryRun = report.mode === 'dry_run'
  const title = dryRun
    ? t('clean.testDoneTitle')
    : report.cancelled
      ? t('clean.stoppedTitle')
      : t('clean.doneTitle')
  const skipped = report.skipped.reduce((sum, count) => sum + count.files, 0)
  const inUse = report.skipped.some((count) => count.reason === 'in_use')

  return (
    <section aria-label={title} className="space-y-5 rounded-xl border bg-card p-5">
      <div className="flex items-center gap-4">
        <CircleCheck className="size-8 shrink-0 text-primary" />
        <div>
          <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
          <p className="text-3xl font-semibold tabular-nums">
            {formatBytes(report.deleted.size, locale)}{' '}
            <span className="text-base font-normal text-muted-foreground">
              {dryRun ? t('clean.wouldFree') : t('clean.freedNow')}
            </span>
          </p>
          <p className="text-sm text-muted-foreground">
            {dryRun
              ? t('clean.wouldDeleteFiles', { count: report.deleted.files })
              : t('clean.deletedFiles', { count: report.deleted.files })}
          </p>
        </div>
      </div>

      {dryRun && <TestModeNote>{t('clean.testDoneNote')}</TestModeNote>}

      <ul className="space-y-2 text-sm">
        {report.quarantined.map((group) => (
          <Line key={group.days} icon={<Archive className="text-primary" />}>
            {t('clean.quarantined', {
              count: group.files,
              size: formatBytes(group.size, locale),
              date: formatDay(group.expires_at, locale),
            })}
          </Line>
        ))}
        {report.quarantined.length > 0 && (
          <li className="pl-6 text-xs text-muted-foreground">{t('clean.quarantineSpace')}</li>
        )}
        {report.folders_removed > 0 && (
          <Line icon={<FolderMinus className="text-muted-foreground" />}>
            {t('clean.foldersRemoved', { count: report.folders_removed })}
          </Line>
        )}
        {report.not_started > 0 && (
          <Line icon={<CircleStop className="text-muted-foreground" />}>
            {t('clean.notStarted', { count: report.not_started })}
          </Line>
        )}
        {report.needs_admin.files > 0 && (
          <Line icon={<ShieldAlert className="text-muted-foreground" />}>
            {t('clean.adminLeftOut', { count: report.needs_admin.files })}
          </Line>
        )}
        {report.apps_open.length > 0 && (
          <Line icon={<AppWindow className="text-muted-foreground" />}>
            {t('clean.appsLeftOut', {
              apps: new Intl.ListFormat(locale, { type: 'conjunction' }).format(
                report.apps_open.map((app) => app.name),
              ),
            })}
          </Line>
        )}
      </ul>

      {skipped > 0 && (
        <div className="space-y-1 text-sm">
          <p className="font-medium">{t('clean.skippedTitle', { count: skipped })}</p>
          <ul className="space-y-0.5 text-muted-foreground tabular-nums">
            {report.skipped.map((count) => (
              <li key={count.reason}>
                {t('clean.skippedLine', {
                  reason: t(`clean.reason.${count.reason}`),
                  count: count.files,
                })}
              </li>
            ))}
          </ul>
          {inUse && <p className="text-xs text-muted-foreground">{t('clean.inUseHint')}</p>}
        </div>
      )}

      {report.history_error && (
        <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400" role="alert">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          {t('clean.historyError', { error: report.history_error })}
        </p>
      )}

      <p className="text-xs text-muted-foreground">{t('clean.resultsGone')}</p>
    </section>
  )
}

function Line({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <li className="flex gap-2 [&>svg]:mt-0.5 [&>svg]:size-4 [&>svg]:shrink-0">
      {icon}
      <span>{children}</span>
    </li>
  )
}
