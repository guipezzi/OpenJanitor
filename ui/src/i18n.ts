// Every UI string goes through a translation key (PLANNING.md section 7.7).
// Only English exists for now; pt-BR comes later as locales/pt-BR.json.
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import en from './locales/en.json'

export const defaultNS = 'translation'
export const resources = { en: { translation: en } } as const

void i18n.use(initReactI18next).init({
  resources,
  lng: 'en',
  fallbackLng: 'en',
  defaultNS,
  // The strings are bundled, so there's nothing to wait for.
  initAsync: false,
  // React already escapes what it renders.
  interpolation: { escapeValue: false },
})

export default i18n
