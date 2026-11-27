import { Disc3, HardDrive, Lock, Network, RefreshCw, Usb, type LucideIcon } from 'lucide-react'
import { useEffect, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { drivesOverview, selectDrives, selectionKey, type Drive } from '@/lib/drives'
import { formatBytes } from '@/lib/format'
import type { DriveTally } from '@/lib/scan'
import { cn } from '@/lib/utils'

interface DriveSelectorProps {
  /** Reload whenever the Clean screen is shown, in case a drive was plugged in. */
  active: boolean
  /** Changes after each scan and cleanup, to show fresh free space. */
  version?: number
  /** What the current results could free on each drive. */
  cleanable?: readonly DriveTally[]
  /** While scanning or cleaning, the choice can't change. */
  disabled: boolean
  /** The selection changed, so the Rust side forgot the results. */
  onChange: () => void
}

/** Which drives a scan covers (PLANNING.md section 7.9 and D33). */
export function DriveSelector({ active, version = 0, cleanable, disabled, onChange }: DriveSelectorProps) {
  const { t } = useTranslation()
  const titleId = useId()
  const [drives, setDrives] = useState<Drive[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Bumped by the refresh button.
  const [checks, setChecks] = useState(0)

  useEffect(() => {
    if (!active) return
    let current = true
    drivesOverview().then(
      (overview) => {
        if (!current) return
        setDrives(overview.drives)
        setError(null)
      },
      (cause) => current && setError(String(cause)),
    )
    return () => {
      current = false
    }
  }, [active, checks, version])

  if (!drives && !error) return null

  const selected = drives?.filter((drive) => drive.selected) ?? []
  const toggle = async (drive: Drive) => {
    if (!drives || !drive.id) return
    const ids = drive.selected
      ? selected.filter((other) => other.id !== drive.id).flatMap((other) => other.id ?? [])
      : [...selected.flatMap((other) => other.id ?? []), drive.id]
    setSaving(true)
    setError(null)
    try {
      const overview = await selectDrives(ids)
      const changed = selectionKey(overview.drives) !== selectionKey(drives)
      setDrives(overview.drives)
      if (changed) onChange()
    } catch (cause) {
      setError(String(cause))
    } finally {
      setSaving(false)
    }
  }

  const otherDrives = selected.some((drive) => !drive.system)

  return (
    <section aria-labelledby={titleId} className="space-y-2">
      <div className="flex items-center gap-1">
        <h3 id={titleId} className="text-sm font-medium">
          {t('drives.title')}
        </h3>
        <Button
          variant="ghost"
          size="icon-xs"
          aria-label={t('drives.refresh')}
          title={t('drives.refresh')}
          onClick={() => setChecks((count) => count + 1)}
          disabled={disabled || saving}
        >
          <RefreshCw />
        </Button>
      </div>
      {drives && (
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {drives.map((drive) => (
            <DriveCard
              key={drive.letter}
              drive={drive}
              cleanable={cleanable?.find((tally) => tally.drive === drive.letter)?.size ?? 0}
              // The last selected drive stays selected: a scan needs one.
              locked={drive.selected && selected.length === 1}
              disabled={disabled || saving}
              onToggle={() => void toggle(drive)}
            />
          ))}
        </ul>
      )}
      {otherDrives && <p className="text-xs text-muted-foreground">{t('drives.otherDrivesNote')}</p>}
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {t('drives.error', { error })}
        </p>
      )}
    </section>
  )
}

interface DriveCardProps {
  drive: Drive
  /** What the current results could free on it. */
  cleanable: number
  locked: boolean
  disabled: boolean
  onToggle: () => void
}

function DriveCard({ drive, cleanable, locked, disabled, onToggle }: DriveCardProps) {
  const { t, i18n } = useTranslation()
  const id = useId()
  const ready = drive.status === 'ready'
  const name = t('drives.name', {
    label: drive.label || t('drives.unnamed'),
    letter: drive.letter,
  })
  const icon: LucideIcon =
    drive.status === 'network'
      ? Network
      : drive.status === 'optical'
        ? Disc3
        : drive.status === 'unavailable'
          ? Lock
          : drive.connection === 'external'
            ? Usb
            : HardDrive
  const Icon = icon
  return (
    <li
      className={cn(
        'flex items-start gap-3 rounded-lg border bg-card p-3',
        drive.selected && 'border-primary/60',
        !ready && 'opacity-60',
      )}
    >
      <Checkbox
        id={id}
        className="mt-0.5"
        checked={drive.selected}
        disabled={!ready || locked || disabled}
        onCheckedChange={onToggle}
        aria-describedby={`${id}-detail`}
        title={locked ? t('drives.lastOne') : undefined}
      />
      <div className="min-w-0 flex-1 space-y-1">
        <label htmlFor={id} className="flex items-center gap-1.5 text-sm font-medium">
          <Icon className="size-4 shrink-0 text-muted-foreground" />
          <span className="truncate">{name}</span>
          {drive.system && (
            <span className="shrink-0 rounded-sm bg-muted px-1.5 text-xs font-normal text-muted-foreground">
              {t('drives.system')}
            </span>
          )}
        </label>
        <p id={`${id}-detail`} className="text-xs text-muted-foreground">
          {ready
            ? [
                t(`drives.media.${drive.media}`),
                t(`drives.connection.${drive.connection}`),
                drive.file_system,
                formatBytes(drive.total, i18n.language),
              ]
                .filter(Boolean)
                .join(' · ')
            : t(`drives.status.${drive.status}`)}
        </p>
        {ready && drive.total > 0 && <DriveUsage drive={drive} name={name} cleanable={cleanable} />}
      </div>
    </li>
  )
}

/**
 * How full a drive is (PLANNING.md section 7.8): a thin segmented bar of
 * what the last scan can free, the rest of the used space, and the free
 * space, with a legend that gives each amount.
 */
function DriveUsage({ drive, name, cleanable }: { drive: Drive; name: string; cleanable: number }) {
  const { t, i18n } = useTranslation()
  const size = (bytes: number) => formatBytes(bytes, i18n.language)
  const used = Math.max(0, drive.total - drive.free)
  const freeable = Math.min(cleanable, used)
  const parts = [
    {
      key: 'cleanable',
      bytes: freeable,
      color: 'bg-primary',
      label: t('drives.usage.cleanable', { size: size(freeable) }),
    },
    {
      key: 'used',
      bytes: used - freeable,
      color: 'bg-muted-foreground/55',
      label:
        freeable > 0
          ? t('drives.usage.otherUsed', { size: size(used - freeable) })
          : t('drives.usage.used', { size: size(used) }),
    },
    {
      key: 'free',
      bytes: drive.free,
      color: 'bg-foreground/10',
      label: t('drives.usage.free', { size: size(drive.free) }),
    },
  ].filter((part) => part.bytes > 0)

  return (
    <div className="space-y-1">
      {/* The legend says the same in words. */}
      <div aria-hidden className="flex h-2 gap-0.5 overflow-hidden rounded-full">
        {parts.map((part) => (
          <div
            key={part.key}
            className={part.color}
            // A sliver still shows: a few pixels at least.
            style={{ flexGrow: part.bytes, flexBasis: 0, minWidth: 3 }}
          />
        ))}
      </div>
      <ul
        aria-label={t('drives.usage.label', { name })}
        className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted-foreground tabular-nums"
      >
        {parts.map((part) => (
          <li key={part.key} className="flex items-center gap-1.5">
            <span className={cn('size-2 shrink-0 rounded-full', part.color)} />
            {part.label}
          </li>
        ))}
      </ul>
    </div>
  )
}
