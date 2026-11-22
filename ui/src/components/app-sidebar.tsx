import { BrushCleaning } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Logo } from '@/components/logo'
import { Badge } from '@/components/ui/badge'

/** The app's screens. Quarantine, History, Protected, and Settings join later in phase 1. */
export function AppSidebar() {
  const { t } = useTranslation()
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r bg-background">
      <div className="flex items-center gap-3 px-4 py-5">
        <Logo className="size-9" />
        <div className="min-w-0">
          <h1 className="leading-tight font-semibold">OpenJanitor</h1>
          <p className="text-xs leading-snug text-muted-foreground">{t('app.tagline')}</p>
        </div>
      </div>
      <nav aria-label={t('nav.label')} className="flex-1 space-y-1 px-2">
        <a
          href="#clean"
          aria-current="page"
          className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-sm font-medium"
        >
          <BrushCleaning className="size-4 text-primary" />
          {t('nav.clean')}
        </a>
      </nav>
      <div className="px-4 py-4">
        <Badge variant="outline">{t('app.preview')}</Badge>
      </div>
    </aside>
  )
}
