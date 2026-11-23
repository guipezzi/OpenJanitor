import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { TestModeNote } from '@/components/test-mode-note'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import type { Mode } from '@/lib/clean'
import { formatBytes } from '@/lib/format'
import type { Conflicts, IfExists } from '@/lib/quarantine'
import type { Tally } from '@/lib/selection'

interface DeleteDialogProps {
  /** What would be deleted; the dialog is open while there's something. */
  files: Tally | null
  /** "Empty quarantine now" rather than "Delete now". */
  everything: boolean
  mode: Mode
  onCancel: () => void
  onConfirm: () => void
}

/**
 * Confirms deleting quarantined files for good, with the same tick as a
 * cleanup that deletes files (D27).
 */
export function DeleteDialog({ files, everything, mode, onCancel, onConfirm }: DeleteDialogProps) {
  return (
    <AlertDialog open={files !== null} onOpenChange={(open) => !open && onCancel()}>
      {files && (
        <DeleteReview files={files} everything={everything} mode={mode} onConfirm={onConfirm} />
      )}
    </AlertDialog>
  )
}

function DeleteReview({
  files,
  everything,
  mode,
  onConfirm,
}: Omit<DeleteDialogProps, 'files' | 'onCancel'> & { files: Tally }) {
  const { t, i18n } = useTranslation()
  const [understood, setUnderstood] = useState(false)
  return (
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>
          {everything ? t('quarantine.emptyTitle') : t('quarantine.deleteTitle')}
        </AlertDialogTitle>
        <AlertDialogDescription>{t('quarantine.deleteBody')}</AlertDialogDescription>
      </AlertDialogHeader>
      {mode === 'dry_run' && <TestModeNote>{t('quarantine.testMode')}</TestModeNote>}
      <p className="text-sm font-medium tabular-nums">
        {t('quarantine.deleteFiles', {
          count: files.files,
          size: formatBytes(files.size, i18n.language),
        })}
      </p>
      <label className="flex items-start gap-2 rounded-lg border p-3 text-sm font-medium">
        <Checkbox
          className="mt-0.5"
          checked={understood}
          onCheckedChange={(checked) => setUnderstood(checked === true)}
        />
        {t('quarantine.understand', { count: files.files })}
      </label>
      <AlertDialogFooter>
        <AlertDialogCancel>{t('quarantine.cancel')}</AlertDialogCancel>
        <AlertDialogAction
          disabled={!understood}
          onClick={onConfirm}
          className="bg-destructive text-white hover:bg-destructive/90"
        >
          {t('quarantine.confirmDelete')}
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  )
}

interface ConflictDialogProps {
  /** The dialog is open while there are conflicts to settle. */
  conflicts: Conflicts | null
  onCancel: () => void
  onChoose: (ifExists: IfExists) => void
}

/** Asks once what to do where restored files would land on something (D23). */
export function ConflictDialog({ conflicts, onCancel, onChoose }: ConflictDialogProps) {
  const { t } = useTranslation()
  const more = conflicts ? conflicts.count - conflicts.samples.length : 0
  const choices: { value: IfExists; label: string; hint: string }[] = [
    { value: 'replace', label: t('quarantine.replace'), hint: t('quarantine.replaceHint') },
    { value: 'keep_both', label: t('quarantine.keepBoth'), hint: t('quarantine.keepBothHint') },
    { value: 'skip', label: t('quarantine.skip'), hint: t('quarantine.skipHint') },
  ]
  return (
    <AlertDialog open={conflicts !== null} onOpenChange={(open) => !open && onCancel()}>
      {conflicts && (
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('quarantine.conflictTitle', { count: conflicts.count })}
            </AlertDialogTitle>
            <AlertDialogDescription>{t('quarantine.conflictBody')}</AlertDialogDescription>
          </AlertDialogHeader>
          <ul className="space-y-0.5 font-mono text-xs text-muted-foreground">
            {conflicts.samples.map((path) => (
              <li key={path} className="truncate" title={path}>
                {path}
              </li>
            ))}
            {more > 0 && <li>{t('quarantine.conflictMore', { count: more })}</li>}
          </ul>
          <ul className="space-y-2">
            {choices.map((choice) => (
              <li key={choice.value} className="flex items-center gap-3">
                <Button
                  className="w-28 shrink-0"
                  variant={choice.value === 'replace' ? 'default' : 'outline'}
                  onClick={() => onChoose(choice.value)}
                >
                  {choice.label}
                </Button>
                <span className="text-xs text-muted-foreground">{choice.hint}</span>
              </li>
            ))}
          </ul>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('quarantine.cancel')}</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      )}
    </AlertDialog>
  )
}
