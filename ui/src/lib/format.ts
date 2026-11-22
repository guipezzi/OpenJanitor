const UNITS = ['KB', 'MB', 'GB', 'TB'] as const

/** Sizes the way File Explorer shows them (1 KB = 1024 bytes). */
export function formatBytes(bytes: number, locale: string): string {
  if (bytes < 1024) {
    return `${new Intl.NumberFormat(locale).format(bytes)} B`
  }
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  const number = new Intl.NumberFormat(locale, {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(value)
  return `${number} ${UNITS[unit]}`
}

export function formatCount(count: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(count)
}

/** How long ago `seconds` (since the Unix epoch) was, such as "2 hours ago". */
export function formatAge(seconds: number, now: number, locale: string): string {
  const format = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  const minutes = Math.floor(Math.max(0, now - seconds) / 60)
  if (minutes < 1) return format.format(0, 'second')
  if (minutes < 60) return format.format(-minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (hours < 48) return format.format(-hours, 'hour')
  return format.format(-Math.round(hours / 24), 'day')
}

/** A date from seconds since the Unix epoch. */
export function formatDay(seconds: number, locale: string, timeZone?: string): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone }).format(
    new Date(seconds * 1000),
  )
}

/** A date and time from seconds since the Unix epoch. */
export function formatDate(seconds: number, locale: string, timeZone?: string): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(
    new Date(seconds * 1000),
  )
}
