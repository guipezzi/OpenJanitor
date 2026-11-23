import { useTranslation } from 'react-i18next'

import en from '../locales/en.json'
import { formatDate } from './format'
import type { NodeView } from './scan'

type CategoryId = keyof typeof en.categories

function isKnownCategory(id: string): id is CategoryId {
  return Object.hasOwn(en.categories, id)
}

/**
 * A node's display name. Categories have translated names, and quarantine
 * batches are named after their cleanup's date; rule, folder, and file
 * names are shown as they are. (Rule names get translations through
 * rules/locales later.)
 */
export function useNodeLabel() {
  const { t, i18n } = useTranslation()
  return (node: NodeView): string => {
    if (node.kind === 'category' && isKnownCategory(node.name)) {
      return t(`categories.${node.name}`)
    }
    if (node.kind === 'batch' && node.quarantined_at !== undefined) {
      return t('quarantine.batch', { date: formatDate(node.quarantined_at, i18n.language) })
    }
    return node.name
  }
}
