// Light and dark themes follow the Windows setting (PLANNING.md section 7.6).
// A theme choice in Settings comes later.
const DARK_QUERY = '(prefers-color-scheme: dark)'

export function followSystemTheme(root: HTMLElement = document.documentElement): () => void {
  const media = window.matchMedia(DARK_QUERY)
  const apply = () => root.classList.toggle('dark', media.matches)
  apply()
  media.addEventListener('change', apply)
  return () => media.removeEventListener('change', apply)
}
