// Makes t('some.key') a type error when the key isn't in en.json.
import 'i18next'

import type en from './locales/en.json'

declare module 'i18next' {
  interface CustomTypeOptions {
    defaultNS: 'translation'
    resources: { translation: typeof en }
  }
}
