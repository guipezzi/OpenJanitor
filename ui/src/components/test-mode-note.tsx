import { FlaskConical } from 'lucide-react'
import type { ReactNode } from 'react'

/** Says that this is a dry run (dev builds): nothing is deleted or moved. */
export function TestModeNote({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-300">
      <FlaskConical className="mt-0.5 size-4 shrink-0" />
      <span>{children}</span>
    </p>
  )
}
