import { useId } from 'react'

import { cn } from '@/lib/utils'

/** The app mark: a sparkle on a teal-to-blue tile. Same drawing as src-tauri/icons/icon.svg. */
export function Logo({ className }: { className?: string }) {
  const gradient = useId()
  return (
    <svg viewBox="0 0 1024 1024" aria-hidden="true" className={cn('size-9 shrink-0', className)}>
      <defs>
        <linearGradient id={gradient} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#14b8a6" />
          <stop offset="1" stopColor="#0369a1" />
        </linearGradient>
      </defs>
      <rect width="1024" height="1024" rx="224" fill={`url(#${gradient})`} />
      <path
        fill="#ffffff"
        d="M456 236 C480 452 548 520 764 544 C548 568 480 636 456 852 C432 636 364 568 148 544 C364 520 432 452 456 236 Z"
      />
      <path
        fill="#ffffff"
        fillOpacity="0.85"
        d="M760 168 C770 250 794 274 876 284 C794 294 770 318 760 400 C750 318 726 294 644 284 C726 274 750 250 760 168 Z"
      />
    </svg>
  )
}
