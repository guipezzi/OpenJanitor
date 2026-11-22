import { useTranslation } from 'react-i18next'

import { TestModeNote } from '@/components/test-mode-note'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import type { CleanProgress, Mode } from '@/lib/clean'
import { formatBytes } from '@/lib/format'

interface CleanProgressPanelProps {
  /** Null until the first update arrives. */
  progress: CleanProgress | null
  mode: Mode
  stopping: boolean
  onStop: () => void
}

export function CleanProgressPanel({ progress, mode, stopping, onStop }: CleanProgressPanelProps) {
  const { t, i18n } = useTranslation()
  const percent =
    progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0
  const size = formatBytes(progress?.freed ?? 0, i18n.language)

  return (
    <div className="space-y-4 rounded-xl border bg-card p-5">
      {mode === 'dry_run' && <TestModeNote>{t('clean.testMode')}</TestModeNote>}
      <div className="flex items-center gap-4">
        <div className="min-w-0 flex-1 space-y-1" aria-live="polite">
          <p className="text-sm font-medium">{t('clean.running')}</p>
          {progress && (
            <p className="text-xs text-muted-foreground tabular-nums">
              {t('clean.progress', { done: progress.done, total: progress.total })}
            </p>
          )}
        </div>
        <Button variant="outline" onClick={onStop} disabled={stopping}>
          {stopping ? t('clean.stopping') : t('clean.stop')}
        </Button>
      </div>
      <Progress value={percent} aria-label={t('clean.progressLabel')} />
      {progress && progress.freed > 0 && (
        <p className="text-sm text-muted-foreground tabular-nums">
          {mode === 'dry_run' ? t('clean.wouldFreeSoFar', { size }) : t('clean.freedSoFar', { size })}
        </p>
      )}
      <p className="text-xs text-muted-foreground">{t('clean.stopHint')}</p>
    </div>
  )
}
