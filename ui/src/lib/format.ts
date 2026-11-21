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
