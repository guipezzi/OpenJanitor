import { useTranslation } from 'react-i18next'

import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { formatBytes } from '@/lib/format'
import type { ScanProgress } from '@/lib/scan'

interface ScanProgressPanelProps {
  /** Null until the first update arrives. */
  progress: ScanProgress | null
  cancelling: boolean
  onCancel: () => void
}

export function ScanProgressPanel({ progress, cancelling, onCancel }: ScanProgressPanelProps) {
  const { t, i18n } = useTranslation()
  const percent = progress ? Math.round((progress.rule_index / progress.rule_count) * 100) : 0

  return (
    <div className="space-y-4 rounded-xl border p-5">
      <div className="flex items-center gap-4">
        <div className="min-w-0 flex-1 space-y-1" aria-live="polite">
          <p className="truncate text-sm font-medium">
            {progress ? t('scan.checking', { rule: progress.rule_name }) : t('scan.starting')}
          </p>
          {progress && (
            <p className="text-xs text-muted-foreground tabular-nums">
              {t('scan.stepDetail', {
                current: progress.rule_index + 1,
                total: progress.rule_count,
                count: progress.files_checked,
              })}
            </p>
          )}
        </div>
        <Button variant="outline" onClick={onCancel} disabled={cancelling}>
          {cancelling ? t('scan.cancelling') : t('scan.cancel')}
        </Button>
      </div>
      <Progress value={percent} aria-label={t('scan.progressLabel')} />
      {progress && progress.findings > 0 && (
        <p className="text-sm text-muted-foreground tabular-nums">
          {t('scan.foundSoFar', { size: formatBytes(progress.size_on_disk, i18n.language) })}
        </p>
      )}
    </div>
  )
}
