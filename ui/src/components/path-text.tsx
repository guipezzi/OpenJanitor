import { cn } from '@/lib/utils'

interface PathTextProps {
  path: string
  className?: string
}

/**
 * A Windows path that may not fit. Long paths often differ only at the end
 * (`...\Logs\app`, `...\cache\data_1`), so the last part stays in view and
 * the rest is trimmed. The full path shows on hover.
 */
export function PathText({ path, className }: PathTextProps) {
  const cut = path.lastIndexOf('\\')
  if (cut <= 0 || cut === path.length - 1) {
    return (
      <span className={cn('truncate', className)} title={path}>
        {path}
      </span>
    )
  }
  return (
    <span className={cn('flex min-w-0', className)} title={path}>
      <span className="truncate">{path.slice(0, cut + 1)}</span>
      <span className="max-w-[75%] shrink-0 truncate">{path.slice(cut + 1)}</span>
    </span>
  )
}
