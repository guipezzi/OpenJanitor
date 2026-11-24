// Light and dark themes (PLANNING.md section 7.6): the Windows setting by
// default, or the choice made in Settings.
export type ThemeChoice = 'system' | 'light' | 'dark'

const DARK_QUERY = '(prefers-color-scheme: dark)'

let stopFollowing: (() => void) | null = null

export function followSystemTheme(root: HTMLElement = document.documentElement): () => void {
  const media = window.matchMedia(DARK_QUERY)
  const apply = () => root.classList.toggle('dark', media.matches)
  apply()
  media.addEventListener('change', apply)
  return () => media.removeEventListener('change', apply)
}

/** Shows the chosen theme. "system" keeps following Windows as it changes. */
export function applyTheme(choice: ThemeChoice, root: HTMLElement = document.documentElement): void {
  stopFollowing?.()
  stopFollowing = null
  if (choice === 'system') {
    stopFollowing = followSystemTheme(root)
  } else {
    root.classList.toggle('dark', choice === 'dark')
  }
}
