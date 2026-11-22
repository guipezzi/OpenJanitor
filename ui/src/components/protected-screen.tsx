import { Download, File, Folder, ListChecks, Regex, ShieldCheck, TriangleAlert, Upload, X } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatDate } from '@/lib/format'
import {
  exportProtected,
  importProtected,
  protectedEntries,
  protectPattern,
  unprotect,
  type EntryKind,
  type ProtectedEntry,
  type ProtectedUpdate,
} from '@/lib/protected'
import type { ScanOverview } from '@/lib/scan'

const KIND_ICONS: Record<EntryKind, typeof File> = {
  file: File,
  folder: Folder,
  pattern: Regex,
  rule: ListChecks,
}

interface ProtectedScreenProps {
  /** Reload the list whenever the screen is shown. */
  active: boolean
  /** The results changed because more is protected now. */
  onOverviewChange: (overview: ScanOverview) => void
}

/** The Protected list (PLANNING.md section 7.2). */
export function ProtectedScreen({ active, onOverviewChange }: ProtectedScreenProps) {
  const { t, i18n } = useTranslation()
  const [entries, setEntries] = useState<ProtectedEntry[] | null>(null)
  const [pattern, setPattern] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!active) return
    let current = true
    protectedEntries().then(
      (list) => current && setEntries(list),
      (cause) => current && setError(String(cause)),
    )
    return () => {
      current = false
    }
  }, [active])

  const run = async (action: () => Promise<void>) => {
    setMessage(null)
    setError(null)
    try {
      await action()
    } catch (cause) {
      setError(String(cause))
    }
  }

  const applied = (update: ProtectedUpdate) => {
    setEntries(update.entries)
    if (update.overview) onOverviewChange(update.overview)
  }

  const addPattern = (event: FormEvent) => {
    event.preventDefault()
    void run(async () => {
      applied(await protectPattern(pattern))
      setPattern('')
    })
  }

  const remove = (entry: ProtectedEntry) =>
    run(async () => {
      setEntries(await unprotect(entry.kind, entry.value))
      setMessage(t('protected.comesBack'))
    })

  const doImport = () =>
    run(async () => {
      const update = await importProtected()
      if (!update) return
      applied(update)
      setMessage(
        update.added > 0
          ? t('protected.imported', { count: update.added })
          : t('protected.importedNone'),
      )
    })

  const doExport = () =>
    run(async () => {
      if (await exportProtected()) setMessage(t('protected.exported'))
    })

  return (
    <div className="space-y-6 pb-6">
      <header className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-semibold">{t('protected.title')}</h2>
          <p className="text-sm text-muted-foreground">{t('protected.description')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={doImport}>
            <Upload />
            {t('protected.import')}
          </Button>
          <Button variant="outline" onClick={doExport} disabled={!entries?.length}>
            <Download />
            {t('protected.export')}
          </Button>
        </div>
      </header>

      {error && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('protected.error')}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {message && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <ShieldCheck className="size-4 shrink-0 text-primary" />
          {message}
        </p>
      )}

      <form onSubmit={addPattern} className="space-y-2 rounded-xl border bg-card p-5">
        <label htmlFor="protect-pattern" className="text-sm font-medium">
          {t('protected.patternLabel')}
        </label>
        <div className="flex gap-2">
          <input
            id="protect-pattern"
            value={pattern}
            onChange={(event) => setPattern(event.target.value)}
            placeholder={t('protected.patternPlaceholder')}
            spellCheck={false}
            className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 font-mono text-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          />
          <Button type="submit" disabled={!pattern.trim()}>
            {t('protected.add')}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">{t('protected.patternHint')}</p>
      </form>

      <section className="rounded-xl border bg-card" aria-label={t('protected.title')}>
        {entries === null ? null : entries.length === 0 ? (
          <p className="p-5 text-sm text-muted-foreground">{t('protected.empty')}</p>
        ) : (
          <ul className="divide-y">
            {entries.map((entry) => {
              const Icon = KIND_ICONS[entry.kind]
              const name = entry.label ?? entry.value
              return (
                <li key={`${entry.kind}:${entry.value}`} className="flex items-center gap-3 px-4 py-3">
                  <Icon className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p
                      className={
                        entry.label ? 'truncate text-sm' : 'truncate font-mono text-xs'
                      }
                      title={entry.value}
                    >
                      {name}
                    </p>
                    {entry.added_at > 0 && (
                      <p className="text-xs text-muted-foreground">
                        {t('protected.added', { date: formatDate(entry.added_at, i18n.language) })}
                      </p>
                    )}
                  </div>
                  <Badge variant="outline">{t(`protected.kind.${entry.kind}`)}</Badge>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={t('protected.removeLabel', { name })}
                    onClick={() => void remove(entry)}
                  >
                    <X />
                  </Button>
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <p className="text-xs text-muted-foreground">{t('protected.comesBack')}</p>
    </div>
  )
}
