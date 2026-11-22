import { BrushCleaning, Shield } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Logo } from '@/components/logo'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export type Screen = 'clean' | 'protected'

const SCREENS: { id: Screen; icon: typeof Shield }[] = [
  { id: 'clean', icon: BrushCleaning },
  { id: 'protected', icon: Shield },
]

interface AppSidebarProps {
  screen: Screen
  onNavigate: (screen: Screen) => void
}

/** The app's screens. Quarantine, History, and Settings join later in phase 1. */
export function AppSidebar({ screen, onNavigate }: AppSidebarProps) {
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
        {SCREENS.map(({ id, icon: Icon }) => (
          <button
            key={id}
            type="button"
            aria-current={screen === id ? 'page' : undefined}
            onClick={() => onNavigate(id)}
            className={cn(
              'flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-medium',
              'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              'aria-[current=page]:bg-muted aria-[current=page]:text-foreground',
            )}
          >
            <Icon className={cn('size-4', screen === id && 'text-primary')} />
            {t(`nav.${id}`)}
          </button>
        ))}
      </nav>
      <div className="px-4 py-4">
        <Badge variant="outline">{t('app.preview')}</Badge>
      </div>
    </aside>
  )
}
