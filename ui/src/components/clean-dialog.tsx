import {
  AppWindow,
  Archive,
  Clock,
  ShieldAlert,
  ShieldCheck,
  Trash,
  Trash2,
  TrashOff,
  type LucideIcon,
} from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { TestModeNote } from '@/components/test-mode-note'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { binItems, plansAnything, type BinTally, type CleanPlan } from '@/lib/clean'
import { formatAge, formatBytes, formatDay } from '@/lib/format'
import type { Tally } from '@/lib/selection'
import { cn } from '@/lib/utils'

const DAY = 24 * 60 * 60

interface CleanDialogProps {
  /** The plan to confirm; the dialog is open while there is one. */
  plan: CleanPlan | null
  onCancel: () => void
  onConfirm: (plan: CleanPlan) => void
  onScanAgain: () => void
  /** Builds the plan again, after the user closed an app. */
  onRecheck: () => void
  rechecking: boolean
}

/**
 * The confirmation before a cleanup (PLANNING.md section 7.1): what will be
 * deleted, what will go to quarantine, and what's left out. Confirming runs
 * exactly this plan.
 */
export function CleanDialog({ plan, onCancel, ...rest }: CleanDialogProps) {
  return (
    <AlertDialog open={plan !== null} onOpenChange={(open) => !open && onCancel()}>
      {/* A new plan starts with the box unticked. */}
      {plan && <Review key={plan.plan_id} plan={plan} {...rest} />}
    </AlertDialog>
  )
}

type ReviewProps = Omit<CleanDialogProps, 'plan' | 'onCancel'> & { plan: CleanPlan }

function Review({ plan, onConfirm, onScanAgain, onRecheck, rechecking }: ReviewProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const [understood, setUnderstood] = useState(false)
  const [now] = useState(() => Date.now() / 1000)
  // Files deleted for good, by the app and by the elevated helper.
  const deletedFiles = plan.delete.files + plan.elevated.files
  const deletingFiles = deletedFiles > 0
  const emptying = plan.recycle_bins.length > 0
  const deleting = deletingFiles || emptying
  const quarantining = plan.quarantine.length > 0
  const ready = plansAnything(plan) && (!deleting || understood)
  const confirm = deleting && quarantining ? 'confirmBoth' : deleting ? 'confirmDelete' : 'confirmQuarantine'
  const tally = ({ files, size }: Tally) =>
    t('clean.files', { count: files, size: formatBytes(size, locale) })
  const bin = ({ drive, items, size }: BinTally) =>
    `${t('results.binDrive', { drive: `${drive}:` })} · ${t('clean.items', {
      count: items,
      size: formatBytes(size, locale),
    })}`
  const items = binItems(plan.recycle_bins)
  const understand =
    deletingFiles && emptying
      ? t('clean.understandBoth', {
          files: t('clean.fileCount', { count: deletedFiles }),
          items: t('clean.itemCount', { count: items }),
        })
      : emptying
        ? t('clean.understandBin', { count: items })
        : t('clean.understand', { count: deletedFiles })

  return (
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>{t('clean.title')}</AlertDialogTitle>
        <AlertDialogDescription>{t('clean.description')}</AlertDialogDescription>
      </AlertDialogHeader>

      {plan.mode === 'dry_run' && <TestModeNote>{t('clean.testMode')}</TestModeNote>}
      {plan.stale && (
        <Alert>
          <Clock />
          <AlertTitle>
            {t('clean.staleTitle', { age: formatAge(plan.scanned_at, now, locale) })}
          </AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t('clean.staleBody')}</p>
            <Button variant="outline" size="sm" onClick={onScanAgain}>
              {t('clean.scanAgain')}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {plan.apps_open.length > 0 && (
        <Alert className="border-amber-500/40 bg-amber-500/10">
          <AppWindow className="text-amber-700 dark:text-amber-400" />
          <AlertTitle>{t('clean.appsOpenTitle', { count: plan.apps_open.length })}</AlertTitle>
          <AlertDescription className="space-y-2">
            <ul className="font-medium text-foreground tabular-nums">
              {plan.apps_open.map((app) => (
                <li key={app.name}>
                  {t('clean.appsOpenLine', { name: app.name, files: tally(app) })}
                </li>
              ))}
            </ul>
            <p>{t('clean.appsOpenBody')}</p>
            <Button variant="outline" size="sm" onClick={onRecheck} disabled={rechecking}>
              {rechecking ? t('clean.checking') : t('clean.checkAgain')}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <ul className="space-y-3">
        {plan.delete.files > 0 && (
          <Group
            icon={Trash}
            title={t('clean.deleteTitle')}
            detail={tally(plan.delete)}
            hint={t('clean.deleteHint')}
            iconClass="text-destructive"
          />
        )}
        {plan.elevated.files > 0 && (
          <Group
            icon={ShieldCheck}
            title={t('clean.elevatedTitle')}
            detail={tally(plan.elevated)}
            hint={t('clean.elevatedHint')}
            iconClass="text-destructive"
          />
        )}
        {plan.recycle_bins.map((each) => (
          <Group
            key={each.drive}
            icon={Trash2}
            title={t('clean.binTitle')}
            detail={bin(each)}
            hint={t('clean.binHint')}
            iconClass="text-destructive"
          />
        ))}
        {plan.quarantine.map((group) => (
          <Group
            key={group.days}
            icon={Archive}
            title={t('clean.quarantineTitle', { count: group.days })}
            detail={tally(group)}
            hint={t('clean.quarantineHint', {
              date: formatDay(now + group.days * DAY, locale),
            })}
            iconClass="text-primary"
          />
        ))}
        {plan.needs_admin.files > 0 && (
          <Group
            icon={ShieldAlert}
            title={t('clean.adminTitle')}
            detail={tally(plan.needs_admin)}
            hint={t('clean.adminHint')}
            iconClass="text-muted-foreground"
          />
        )}
        {plan.recycle_bins_kept.map((each) => (
          <Group
            key={`kept-${each.drive}`}
            icon={TrashOff}
            title={t('clean.binKeptTitle')}
            detail={bin(each)}
            hint={t('clean.binKeptHint')}
            iconClass="text-muted-foreground"
          />
        ))}
      </ul>
      {!plansAnything(plan) && (
        <p className="text-sm text-muted-foreground">{t('clean.nothingToClean')}</p>
      )}

      {deleting && (
        <label className="flex items-start gap-2 rounded-lg border p-3 text-sm font-medium">
          <Checkbox
            className="mt-0.5"
            checked={understood}
            onCheckedChange={(checked) => setUnderstood(checked === true)}
          />
          {understand}
        </label>
      )}

      <AlertDialogFooter>
        <AlertDialogCancel>{t('clean.cancel')}</AlertDialogCancel>
        <AlertDialogAction
          disabled={!ready}
          onClick={() => onConfirm(plan)}
          className={cn(deleting && 'bg-destructive text-white hover:bg-destructive/90')}
        >
          {t(`clean.${confirm}`)}
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  )
}

interface GroupProps {
  icon: LucideIcon
  title: string
  detail: string
  hint: string
  iconClass: string
}

function Group({ icon: Icon, title, detail, hint, iconClass }: GroupProps) {
  return (
    <li className="flex gap-3">
      <Icon className={cn('mt-0.5 size-5 shrink-0', iconClass)} />
      <div className="min-w-0">
        <p className="text-sm font-medium">
          {title} <span className="font-normal text-muted-foreground tabular-nums">· {detail}</span>
        </p>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </div>
    </li>
  )
}
