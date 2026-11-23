import { Archive, CircleCheck, Clock, RotateCcw, Trash, TriangleAlert } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ConflictDialog, DeleteDialog } from '@/components/quarantine-dialogs'
import { ResultsTree } from '@/components/results-tree'
import { TestModeNote } from '@/components/test-mode-note'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { formatBytes, formatDate, formatDay } from '@/lib/format'
import {
  deleteQuarantined,
  everything,
  quarantineChildren,
  quarantineConflicts,
  quarantineOverview,
  restoreQuarantined,
  type Conflicts,
  type IfExists,
  type QuarantineOverview,
  type QuarantineReport,
} from '@/lib/quarantine'
import { tallyAll, toggle, type Choices, type Tally } from '@/lib/selection'
import { useTree, type LoadChildren } from '@/lib/use-results-tree'

interface QuarantineScreenProps {
  /** Reload whenever the screen is shown. */
  active: boolean
}

/** The Quarantine screen (PLANNING.md section 7.3). */
export function QuarantineScreen({ active }: QuarantineScreenProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const [overview, setOverview] = useState<QuarantineOverview | null>(null)
  const [error, setError] = useState<{ title: string; message: string } | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const [emptying, setEmptying] = useState(false)

  const reload = useCallback(async () => {
    try {
      setOverview(await quarantineOverview())
    } catch (cause) {
      setError({ title: t('quarantine.loadError'), message: String(cause) })
    }
  }, [t])

  useEffect(() => {
    if (!active) return
    let current = true
    quarantineOverview().then(
      (loaded) => current && setOverview(loaded),
      (cause) =>
        current && setError({ title: t('quarantine.loadError'), message: String(cause) }),
    )
    return () => {
      current = false
    }
  }, [active, t])

  /** Runs a restore or a delete, says what happened, and reloads. */
  const run = async (action: () => Promise<QuarantineReport>, verb: 'restore' | 'delete') => {
    setError(null)
    setResult(null)
    try {
      const report = await action()
      setResult(describe(report, verb))
    } catch (cause) {
      setError({ title: t('quarantine.actionError'), message: String(cause) })
    }
    await reload()
  }

  const describe = (report: QuarantineReport, verb: 'restore' | 'delete') => {
    const dry = report.mode === 'dry_run'
    const count = report.done.files
    const size = formatBytes(report.done.size, locale)
    const parts = [
      verb === 'restore'
        ? t(dry ? 'quarantine.wouldRestore' : 'quarantine.restored', { count })
        : t(dry ? 'quarantine.wouldDelete' : 'quarantine.deleted', { count, size }),
    ]
    const skipped = report.skipped.reduce((sum, s) => sum + s.files, 0)
    if (skipped > 0) {
      const reasons = new Intl.ListFormat(locale, { type: 'conjunction' }).format(
        report.skipped.map((s) => `${t(`clean.reason.${s.reason}`)} (${s.files})`),
      )
      parts.push(t('quarantine.skipped', { count: skipped, reasons }))
    }
    if (report.history_error) parts.push(t('clean.historyError', { error: report.history_error }))
    return parts.join(' ')
  }

  const held = overview?.held
  return (
    <div className="space-y-6 pb-6">
      <header className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-semibold">{t('quarantine.title')}</h2>
          <p className="text-sm text-muted-foreground">{t('quarantine.description')}</p>
        </div>
        <Button variant="outline" onClick={() => setEmptying(true)} disabled={!held?.files}>
          <Trash />
          {t('quarantine.emptyNow')}
        </Button>
      </header>

      {error && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{error.title}</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}
      {result && (
        <p className="flex gap-2 text-sm text-muted-foreground" role="status">
          <CircleCheck className="mt-0.5 size-4 shrink-0 text-primary" />
          {result}
        </p>
      )}

      {overview && (
        <>
          {overview.mode === 'dry_run' && <TestModeNote>{t('quarantine.testMode')}</TestModeNote>}
          {overview.expired && overview.expired.done.files > 0 && (
            <p className="flex gap-2 text-sm text-muted-foreground">
              <Clock className="mt-0.5 size-4 shrink-0" />
              {overview.expired.mode === 'dry_run'
                ? t('quarantine.expiredTest', { count: overview.expired.done.files })
                : t('quarantine.expired', {
                    count: overview.expired.done.files,
                    size: formatBytes(overview.expired.done.size, locale),
                    date: formatDate(overview.expired.at, locale),
                  })}
            </p>
          )}
          {overview.unreadable.length > 0 && (
            <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400" role="alert">
              <TriangleAlert className="mt-0.5 size-4 shrink-0" />
              {t('quarantine.unreadable', {
                count: overview.unreadable.length,
                folders: overview.unreadable.map((u) => u.folder).join(', '),
              })}
            </p>
          )}

          <div className="flex items-center gap-4 rounded-xl border bg-card p-5">
            <Archive className="size-8 shrink-0 text-primary" />
            <div className="min-w-0 flex-1">
              <p className="text-3xl font-semibold tabular-nums">
                {formatBytes(overview.held.size, locale)}
              </p>
              <p className="text-sm text-muted-foreground">
                {t('quarantine.held', { count: overview.held.files })}
              </p>
            </div>
            {overview.next_expiry && (
              <div className="hidden max-w-72 space-y-1 text-xs text-muted-foreground md:block">
                <p>
                  {t('quarantine.nextExpiry', {
                    count: overview.next_expiry.files,
                    size: formatBytes(overview.next_expiry.size, locale),
                    date: formatDay(overview.next_expiry.at, locale),
                  })}
                </p>
                <p>{t('quarantine.spaceNote')}</p>
              </div>
            )}
          </div>

          {overview.batches.length === 0 ? (
            <p className="rounded-xl border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
              {t('quarantine.empty')}
            </p>
          ) : (
            <Browser
              key={overview.view_id}
              overview={overview}
              onRestore={(choices, ifExists) =>
                run(() => restoreQuarantined(overview.view_id, choices, ifExists), 'restore')
              }
              onDelete={(choices) =>
                run(() => deleteQuarantined(overview.view_id, choices), 'delete')
              }
              onError={(message) => setError({ title: t('quarantine.actionError'), message })}
            />
          )}

          <DeleteDialog
            files={emptying ? overview.held : null}
            everything
            mode={overview.mode}
            onCancel={() => setEmptying(false)}
            onConfirm={() => {
              setEmptying(false)
              void run(() => deleteQuarantined(overview.view_id, everything(overview)), 'delete')
            }}
          />
        </>
      )}
    </div>
  )
}

interface BrowserProps {
  overview: QuarantineOverview
  onRestore: (choices: Choices, ifExists: IfExists) => Promise<void>
  onDelete: (choices: Choices) => Promise<void>
  onError: (message: string) => void
}

/** The tree, what's selected, and the actions on it. One per view. */
function Browser({ overview, onRestore, onDelete, onError }: BrowserProps) {
  const { t, i18n } = useTranslation()
  const viewId = overview.view_id
  const loadChildren: LoadChildren = useCallback(
    (nodeId, offset, limit) => quarantineChildren(viewId, nodeId, offset, limit),
    [viewId],
  )
  const tree = useTree(overview.batches, loadChildren)
  const [choices, setChoices] = useState<Choices>(() => new Map())
  const [busy, setBusy] = useState(false)
  const [conflicts, setConflicts] = useState<Conflicts | null>(null)
  const [deleting, setDeleting] = useState<Tally | null>(null)
  const { byNode, total } = useMemo(
    () => tallyAll(overview.batches, choices, tree.loaded),
    [overview.batches, choices, tree.loaded],
  )

  const busyWhile = async (work: () => Promise<void>) => {
    setBusy(true)
    try {
      await work()
    } finally {
      setBusy(false)
    }
  }

  // Conflicts are asked about once, for all the selected files.
  const restore = () =>
    busyWhile(async () => {
      let found: Conflicts
      try {
        found = await quarantineConflicts(viewId, choices)
      } catch (cause) {
        onError(String(cause))
        return
      }
      if (found.count > 0) {
        setConflicts(found)
      } else {
        await onRestore(choices, 'skip')
      }
    })

  return (
    <div className="flex flex-col space-y-4">
      <ResultsTree
        label={t('quarantine.label')}
        showExpiry
        rows={tree.rows}
        expanded={tree.expanded}
        tallies={byNode}
        focusedId={null}
        onToggleExpanded={tree.toggleExpanded}
        onToggleSelected={(node, current) => setChoices(toggle(node, current, choices, tree.loaded))}
        onFocus={(node) => node.has_children && tree.toggleExpanded(node)}
        onLoadMore={tree.loadMore}
      />

      <div className="sticky bottom-0 -mx-6 flex flex-wrap items-center gap-x-4 gap-y-2 border-t bg-background/95 px-6 py-3 backdrop-blur">
        <p className="text-sm font-medium tabular-nums" aria-live="polite">
          {total.files > 0
            ? t('quarantine.selected', {
                count: total.files,
                size: formatBytes(total.size, i18n.language),
              })
            : t('quarantine.nothingSelected')}
        </p>
        <div className="ml-auto flex gap-2">
          <Button variant="outline" onClick={() => setDeleting(total)} disabled={!total.files || busy}>
            <Trash />
            {t('quarantine.deleteNow')}
          </Button>
          <Button onClick={() => void restore()} disabled={!total.files || busy}>
            <RotateCcw />
            {t('quarantine.restore')}
          </Button>
        </div>
      </div>

      <ConflictDialog
        conflicts={conflicts}
        onCancel={() => setConflicts(null)}
        onChoose={(ifExists) => {
          setConflicts(null)
          void busyWhile(() => onRestore(choices, ifExists))
        }}
      />
      <DeleteDialog
        files={deleting}
        everything={false}
        mode={overview.mode}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          setDeleting(null)
          void busyWhile(() => onDelete(choices))
        }}
      />
    </div>
  )
}
