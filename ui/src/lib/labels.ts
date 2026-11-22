import { useTranslation } from 'react-i18next'

import en from '../locales/en.json'
import type { NodeView } from './scan'

type CategoryId = keyof typeof en.categories

function isKnownCategory(id: string): id is CategoryId {
  return Object.hasOwn(en.categories, id)
}

/**
 * A node's display name. Categories have translated names; rule, folder,
 * and file names are shown as they are. (Rule names get translations
 * through rules/locales later.)
 */
export function useNodeLabel() {
  const { t } = useTranslation()
  return (node: NodeView): string =>
    node.kind === 'category' && isKnownCategory(node.name)
      ? t(`categories.${node.name}`)
      : node.name
}
