import { LoaderCircle, Search, ShieldCheck, Sparkles, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Logo } from '@/components/logo'
import { ResultsTable } from '@/components/results-table'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { formatBytes } from '@/lib/format'
import { canScan, scan, type ScanSummary } from '@/lib/scan'

export default function App() {
  const { t, i18n } = useTranslation()
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function runScan() {
    setError(null)
    if (!canScan()) {
      setError(t('scan.notInApp'))
      return
    }
    setScanning(true)
    try {
      setSummary(await scan('simple'))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="min-h-screen bg-muted/40">
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-5xl items-center gap-3 px-6 py-4">
          <Logo />
          <div>
            <h1 className="text-lg leading-tight font-semibold">OpenJanitor</h1>
            <p className="text-sm text-muted-foreground">{t('app.tagline')}</p>
          </div>
          <Badge variant="outline" className="ml-auto">
            {t('app.preview')}
          </Badge>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-8">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('scan.title')}</CardTitle>
            <CardDescription>{t('scan.description')}</CardDescription>
            <CardAction>
              <Button size="lg" onClick={runScan} disabled={scanning}>
                {scanning ? <LoaderCircle className="animate-spin" /> : <Search />}
                {scanning ? t('scan.scanning') : summary ? t('scan.again') : t('scan.start')}
              </Button>
            </CardAction>
          </CardHeader>

          <CardContent className="space-y-6">
            {error && (
              <Alert variant="destructive">
                <TriangleAlert />
                <AlertTitle>{t('scan.error')}</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {summary ? (
              <>
                <div className="flex items-center gap-4 rounded-xl bg-primary/5 p-5">
                  <Sparkles className="size-8 shrink-0 text-primary" />
                  <div>
                    <p className="text-3xl font-semibold tabular-nums">
                      {formatBytes(summary.size_on_disk_total, i18n.language)}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {t('scan.summary', { count: summary.findings_total })}
                    </p>
                  </div>
                </div>
                <ResultsTable rules={summary.rules} />
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  <ShieldCheck className="size-4 shrink-0" />
                  {t('scan.nothingDeleted')}
                </p>
              </>
            ) : (
              !error && (
                <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed py-12 text-center text-sm text-muted-foreground">
                  <ShieldCheck className="size-10 text-primary" />
                  {t('scan.idle')}
                </div>
              )
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  )
}
