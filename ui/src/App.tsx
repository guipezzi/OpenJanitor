import { LoaderCircle, Search, ShieldCheck, Sparkles, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { AppSidebar, type Screen } from '@/components/app-sidebar'
import { CleanProgressPanel } from '@/components/clean-progress'
import { CleanSummary } from '@/components/clean-summary'
import { HistoryScreen } from '@/components/history-screen'
import { ProtectedScreen } from '@/components/protected-screen'
import { QuarantineScreen } from '@/components/quarantine-screen'
import { ResultsView } from '@/components/results-view'
import { SettingsScreen } from '@/components/settings-screen'
import { ScanProgressPanel } from '@/components/scan-progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  cancelClean,
  runClean,
  type CleanPlan,
  type CleanProgress,
  type CleanReport,
} from '@/lib/clean'
import { formatBytes } from '@/lib/format'
import {
  cancelScan,
  canScan,
  scan,
  type ScanOverview,
  type ScanProgress,
} from '@/lib/scan'
import { cn } from '@/lib/utils'

interface Failure {
  /** What couldn't finish, for the title. */
  during: 'scan' | 'clean'
  message: string
}

export default function App() {
  const { t, i18n } = useTranslation()
  const [screen, setScreen] = useState<Screen>('clean')
  const [overview, setOverview] = useState<ScanOverview | null>(null)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [cancelling, setCancelling] = useState(false)
  const [cleaning, setCleaning] = useState<CleanPlan | null>(null)
  const [cleanProgress, setCleanProgress] = useState<CleanProgress | null>(null)
  const [stopping, setStopping] = useState(false)
  const [report, setReport] = useState<CleanReport | null>(null)
  const [error, setError] = useState<Failure | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const busy = scanning || cleaning !== null

  async function runScan() {
    setError(null)
    setNotice(null)
    if (!canScan()) {
      setError({ during: 'scan', message: t('scan.notInApp') })
      return
    }
    // A new scan replaces the old results on the Rust side too.
    setOverview(null)
    setReport(null)
    setProgress(null)
    setScanning(true)
    try {
      const outcome = await scan('simple', setProgress)
      if (outcome.status === 'completed') {
        setOverview(outcome.overview)
      } else {
        setNotice(t('scan.cancelled'))
      }
    } catch (cause) {
      setError({ during: 'scan', message: String(cause) })
    } finally {
      setScanning(false)
      setCancelling(false)
      setProgress(null)
    }
  }

  async function stopScan() {
    setCancelling(true)
    try {
      await cancelScan()
    } catch (cause) {
      setError({ during: 'scan', message: String(cause) })
    }
  }

  async function clean(plan: CleanPlan) {
    setError(null)
    setNotice(null)
    // Cleaning makes the results out of date; the Rust side forgets them too.
    setOverview(null)
    setCleanProgress(null)
    setCleaning(plan)
    try {
      setReport(await runClean(plan.plan_id, setCleanProgress))
    } catch (cause) {
      setError({ during: 'clean', message: String(cause) })
    } finally {
      setCleaning(null)
      setStopping(false)
      setCleanProgress(null)
    }
  }

  async function stopClean() {
    setStopping(true)
    try {
      await cancelClean()
    } catch (cause) {
      setError({ during: 'clean', message: String(cause) })
    }
  }

  let content
  if (scanning) {
    content = <ScanProgressPanel progress={progress} cancelling={cancelling} onCancel={stopScan} />
  } else if (cleaning) {
    content = (
      <CleanProgressPanel
        progress={cleanProgress}
        mode={cleaning.mode}
        stopping={stopping}
        onStop={stopClean}
      />
    )
  } else if (report) {
    content = <CleanSummary report={report} />
  } else if (overview) {
    content = (
      <>
        <div className="flex items-center gap-4 rounded-xl border bg-card p-5">
          <Sparkles className="size-8 shrink-0 text-primary" />
          <div className="flex-1">
            <p className="text-3xl font-semibold tabular-nums">
              {formatBytes(overview.size_on_disk_total, i18n.language)}
            </p>
            <p className="text-sm text-muted-foreground">
              {t('scan.summary', { count: overview.findings_total })}
            </p>
          </div>
          <p className="hidden max-w-56 items-center gap-2 text-xs text-muted-foreground md:flex">
            <ShieldCheck className="size-4 shrink-0" />
            {t('scan.nothingDeleted')}
          </p>
        </div>
        {overview.categories.length > 0 ? (
          <ResultsView
            key={overview.scan_id}
            overview={overview}
            onOverviewChange={setOverview}
            onClean={(plan) => void clean(plan)}
            onScanAgain={() => void runScan()}
          />
        ) : (
          <p className="pb-6 text-sm text-muted-foreground">{t('scan.nothingFound')}</p>
        )}
      </>
    )
  } else if (!error) {
    content = (
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed bg-card py-12 text-center text-sm text-muted-foreground">
        <ShieldCheck className="size-10 text-primary" />
        {notice ?? t('scan.idle')}
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-muted/40">
      <AppSidebar screen={screen} onNavigate={setScreen} />
      <main className="min-w-0 flex-1 overflow-y-auto">
        {/* Screens stay mounted when hidden, so results and selections survive a visit elsewhere. */}
        <div
          className={cn(
            'mx-auto min-h-full max-w-6xl flex-col space-y-6 px-6 pt-6',
            screen === 'clean' ? 'flex' : 'hidden',
          )}
        >
          <header className="flex flex-wrap items-start gap-4">
            <div className="min-w-0 flex-1">
              <h2 className="text-xl font-semibold">{t('scan.title')}</h2>
              <p className="text-sm text-muted-foreground">{t('scan.description')}</p>
            </div>
            <Button size="lg" onClick={runScan} disabled={busy}>
              {scanning ? <LoaderCircle className="animate-spin" /> : <Search />}
              {scanning
                ? t('scan.scanning')
                : overview || cleaning || report
                  ? t('scan.again')
                  : t('scan.start')}
            </Button>
          </header>

          {error && (
            <Alert variant="destructive">
              <TriangleAlert />
              <AlertTitle>{error.during === 'scan' ? t('scan.error') : t('clean.error')}</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}

          {content}
        </div>
        <div className={cn('mx-auto max-w-6xl px-6 pt-6', screen !== 'quarantine' && 'hidden')}>
          <QuarantineScreen active={screen === 'quarantine'} />
        </div>
        <div className={cn('mx-auto max-w-5xl px-6 pt-6', screen !== 'history' && 'hidden')}>
          <HistoryScreen active={screen === 'history'} />
        </div>
        <div className={cn('mx-auto max-w-4xl px-6 pt-6', screen !== 'protected' && 'hidden')}>
          <ProtectedScreen active={screen === 'protected'} onOverviewChange={setOverview} />
        </div>
        <div className={cn('mx-auto max-w-3xl px-6 pt-6', screen !== 'settings' && 'hidden')}>
          <SettingsScreen active={screen === 'settings'} />
        </div>
      </main>
    </div>
  )
}
