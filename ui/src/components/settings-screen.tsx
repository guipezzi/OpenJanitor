import { Archive, BrushCleaning, Check, Palette, RotateCcw, TriangleAlert, type LucideIcon } from 'lucide-react'
import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { ChoiceGroup, type Choice } from '@/components/choice-group'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import {
  resetSettings,
  saveSettings,
  settingsOverview,
  type Settings,
  type SettingsOverview,
} from '@/lib/settings'
import { applyTheme, type ThemeChoice } from '@/lib/theme'

const THEMES: ThemeChoice[] = ['system', 'light', 'dark']

interface SettingsScreenProps {
  /** Reload whenever the screen is shown. */
  active: boolean
}

/** The Settings screen (PLANNING.md section 7.4 and D31). Every change saves at once. */
export function SettingsScreen({ active }: SettingsScreenProps) {
  const { t } = useTranslation()
  const [overview, setOverview] = useState<SettingsOverview | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  // The last settings known to be on disk, and the latest save: an older
  // save's answer never overwrites a newer choice.
  const confirmed = useRef<Settings | null>(null)
  const latest = useRef(0)

  useEffect(() => {
    if (!active) return
    let current = true
    settingsOverview().then(
      (loaded) => {
        if (!current) return
        confirmed.current = loaded.settings ?? null
        setOverview(loaded)
        setSettings(loaded.settings ?? null)
        setLoadError(null)
        setSaved(false)
      },
      (cause) => current && setLoadError(String(cause)),
    )
    return () => {
      current = false
    }
  }, [active])

  // A damaged file falls back to the system theme; nothing else does.
  const theme = settings?.theme
  useEffect(() => {
    if (overview) applyTheme(theme ?? 'system')
  }, [overview, theme])

  const save = (action: () => Promise<Settings>, optimistic?: Settings) => {
    const id = ++latest.current
    if (optimistic) setSettings(optimistic)
    setSaved(false)
    setSaveError(null)
    action().then(
      (result) => {
        confirmed.current = result
        if (id !== latest.current) return
        setSettings(result)
        setOverview((previous) => previous && { ...previous, settings: result, error: undefined })
        setSaved(true)
      },
      (cause) => {
        if (id !== latest.current) return
        setSettings(confirmed.current)
        setSaveError(String(cause))
      },
    )
  }

  const change = (patch: Partial<Settings>) => {
    if (!settings) return
    const next = { ...settings, ...patch }
    save(() => saveSettings(next), next)
  }
  const restore = () => save(resetSettings)

  const days = (count: number) => t('settings.days', { count })
  const minAge = (count: number) => (count === 1 ? t('settings.hours', { count: 24 }) : days(count))
  const options = (values: number[], label: (count: number) => string): Choice<string>[] =>
    values.map((value) => ({ value: String(value), label: label(value) }))
  const isDefault =
    settings !== null &&
    overview !== null &&
    (Object.keys(overview.defaults) as (keyof Settings)[]).every(
      (key) => settings[key] === overview.defaults[key],
    )

  return (
    <div className="space-y-6 pb-6">
      <header className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-semibold">{t('settings.title')}</h2>
          <p className="text-sm text-muted-foreground">{t('settings.description')}</p>
        </div>
        <p role="status" className="flex h-7 items-center gap-1 text-sm text-muted-foreground">
          {saved && (
            <>
              <Check className="size-4 text-primary" />
              {t('settings.saved')}
            </>
          )}
        </p>
      </header>

      {loadError && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('settings.loadError')}</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      {saveError && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('settings.saveError')}</AlertTitle>
          <AlertDescription>{saveError}</AlertDescription>
        </Alert>
      )}

      {overview?.error && !settings && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('settings.damaged')}</AlertTitle>
          <AlertDescription>
            <p>{overview.error}</p>
            <p>{t('settings.damagedHint')}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={restore}>
              <RotateCcw />
              {t('settings.restore')}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {overview && settings && (
        <>
          <Section icon={BrushCleaning} title={t('settings.cleaning.title')}>
            <Field label={t('settings.cleaning.minAge')} hint={t('settings.cleaning.minAgeHint')}>
              {(id) => (
                <ChoiceGroup
                  labelledBy={id}
                  value={String(settings.min_age_days)}
                  choices={options(overview.choices.min_age_days, minAge)}
                  onChange={(value) => change({ min_age_days: Number(value) })}
                />
              )}
            </Field>
            <Note>{t('settings.cleaning.applies')}</Note>
          </Section>

          <Section icon={Archive} title={t('settings.quarantine.title')}>
            <AlwaysQuarantine
              checked={settings.always_quarantine}
              onChange={(always_quarantine) => change({ always_quarantine })}
            />
            <Field
              label={t('settings.quarantine.medium')}
              hint={settings.always_quarantine ? t('settings.quarantine.mediumAlso') : undefined}
            >
              {(id) => (
                <ChoiceGroup
                  labelledBy={id}
                  value={String(settings.medium_days)}
                  choices={options(overview.choices.medium_days, days)}
                  onChange={(value) => change({ medium_days: Number(value) })}
                />
              )}
            </Field>
            <Field label={t('settings.quarantine.review')}>
              {(id) => (
                <ChoiceGroup
                  labelledBy={id}
                  value={String(settings.review_days)}
                  choices={options(overview.choices.review_days, days)}
                  onChange={(value) => change({ review_days: Number(value) })}
                />
              )}
            </Field>
            <Note>{t('settings.quarantine.applies')}</Note>
          </Section>

          <Section icon={Palette} title={t('settings.appearance.title')}>
            <Field label={t('settings.appearance.theme')} hint={t('settings.appearance.themeHint')}>
              {(id) => (
                <ChoiceGroup
                  labelledBy={id}
                  value={settings.theme}
                  choices={THEMES.map((value) => ({
                    value,
                    label: t(`settings.appearance.${value}`),
                  }))}
                  onChange={(value) => change({ theme: value })}
                />
              )}
            </Field>
          </Section>

          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" onClick={restore} disabled={isDefault}>
              <RotateCcw />
              {t('settings.restore')}
            </Button>
            <p className="text-xs text-muted-foreground">{t('settings.restoreHint')}</p>
          </div>
        </>
      )}
    </div>
  )
}

function Section({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children: ReactNode }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="space-y-5 rounded-xl border bg-card p-5">
      <h3 id={id} className="flex items-center gap-2 font-medium">
        <Icon className="size-4 text-primary" />
        {title}
      </h3>
      {children}
    </section>
  )
}

interface FieldProps {
  label: string
  hint?: string
  /** The control, given the id of the label. */
  children: (labelId: string) => ReactNode
}

function Field({ label, hint, children }: FieldProps) {
  const id = useId()
  return (
    <div className="space-y-2">
      <div>
        <p id={id} className="text-sm font-medium">
          {label}
        </p>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
      {children(id)}
    </div>
  )
}

function Note({ children }: { children: ReactNode }) {
  return <p className="border-t pt-3 text-xs text-muted-foreground">{children}</p>
}

function AlwaysQuarantine({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} className="mt-0.5" />
      <div className="space-y-1">
        <label htmlFor={id} className="text-sm font-medium">
          {t('settings.quarantine.always')}
        </label>
        <p className="text-xs text-muted-foreground">{t('settings.quarantine.alwaysHint')}</p>
        {checked && (
          <p className="flex gap-1.5 text-xs text-amber-700 dark:text-amber-400">
            <TriangleAlert className="mt-px size-3.5 shrink-0" />
            {t('settings.quarantine.alwaysWarning')}
          </p>
        )}
      </div>
    </div>
  )
}
