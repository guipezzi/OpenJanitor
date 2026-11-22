import { useTranslation } from 'react-i18next'

import { Badge } from '@/components/ui/badge'
import type { Risk } from '@/lib/scan'

const RISK_STYLES: Record<Risk, string> = {
  low: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
  medium: 'bg-amber-500/10 text-amber-700 dark:text-amber-400',
  review: 'bg-rose-500/10 text-rose-700 dark:text-rose-400',
}

export function RiskBadge({ risk }: { risk: Risk }) {
  const { t } = useTranslation()
  return <Badge className={RISK_STYLES[risk]}>{t(`risk.${risk}`)}</Badge>
}
